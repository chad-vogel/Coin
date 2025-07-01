use std::fs::{self, File};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

use bincode;

use crate::Block;

/// Magic bytes identifying the start of a block.
pub const MAGIC_BYTES: [u8; 4] = [0xF9, 0xBE, 0xB4, 0xD9];

fn blockfile_path(dir: &Path, index: u32) -> PathBuf {
    dir.join(format!("blk{:05}.dat", index))
}

/// Determine the next block index by inspecting existing files.
fn next_index(dir: &Path) -> std::io::Result<u32> {
    fs::create_dir_all(dir)?;
    let mut max: Option<u32> = None;
    for entry in fs::read_dir(dir)? {
        let entry = entry?;
        let name = entry.file_name();
        if let Some(name) = name.to_str() {
            if name.starts_with("blk") && name.ends_with(".dat") {
                if let Ok(i) = name[3..name.len() - 4].parse::<u32>() {
                    max = Some(match max {
                        Some(m) => m.max(i),
                        None => i,
                    });
                }
            }
        }
    }
    Ok(max.map_or(0, |m| m + 1))
}

/// Store `block` in a new `blkXXXXX.dat` file inside `dir`.
pub fn append_block(dir: &Path, block: &Block) -> std::io::Result<()> {
    let index = next_index(dir)?;
    let path = blockfile_path(dir, index);
    let mut file = File::create(&path)?;
    let data = bincode::serialize(block).unwrap();
    file.write_all(&MAGIC_BYTES)?;
    file.write_all(&(data.len() as u32).to_le_bytes())?;
    file.write_all(&data)?;
    Ok(())
}

/// Read all blocks from blk.dat files in `dir` in order.
pub fn read_blocks(dir: &Path) -> std::io::Result<Vec<Block>> {
    let mut blocks = Vec::new();
    let mut index = 0;
    loop {
        let path = blockfile_path(dir, index);
        if !path.exists() {
            break;
        }
        let mut file = File::open(&path)?;
        let mut buf = Vec::new();
        file.read_to_end(&mut buf)?;
        if buf.len() < 8 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "block file too small",
            ));
        }
        if buf[..4] != MAGIC_BYTES {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "bad magic bytes",
            ));
        }
        let len = u32::from_le_bytes([buf[4], buf[5], buf[6], buf[7]]) as usize;
        if 8 + len != buf.len() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "block file length mismatch",
            ));
        }
        let block: Block = bincode::deserialize(&buf[8..])
            .map_err(|_| std::io::Error::new(std::io::ErrorKind::InvalidData, "decode error"))?;
        blocks.push(block);
        index += 1;
    }
    Ok(blocks)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Blockchain, coinbase_transaction};
    use tempfile::tempdir;

    #[test]
    fn append_and_read_blocks_roundtrip() {
        let dir = tempdir().unwrap();
        let mut bc = Blockchain::new();
        let tx = coinbase_transaction("1BvgsfsZQVtkLS69NvGF8rw6NZW2ShJQHr", bc.block_subsidy());
        bc.add_block(Block {
            header: crate::BlockHeader {
                previous_hash: String::new(),
                merkle_root: crate::compute_merkle_root(&[tx.clone()]),
                timestamp: 1,
                nonce: 0,
                difficulty: 1,
            },
            transactions: vec![tx.clone()],
        });
        for block in bc.all() {
            append_block(dir.path(), &block).unwrap();
        }
        let blocks = read_blocks(dir.path()).unwrap();
        assert_eq!(blocks, bc.all());
    }

    #[test]
    fn append_creates_separate_files() {
        let dir = tempdir().unwrap();
        let mut bc = Blockchain::new();
        let tx = coinbase_transaction("1BvgsfsZQVtkLS69NvGF8rw6NZW2ShJQHr", bc.block_subsidy());
        bc.add_block(Block {
            header: crate::BlockHeader {
                previous_hash: String::new(),
                merkle_root: crate::compute_merkle_root(&[tx.clone()]),
                timestamp: 1,
                nonce: 0,
                difficulty: 1,
            },
            transactions: vec![tx.clone()],
        });
        let block = bc.all()[0].clone();
        append_block(dir.path(), &block).unwrap();
        append_block(dir.path(), &block).unwrap();
        assert!(dir.path().join("blk00000.dat").exists());
        assert!(dir.path().join("blk00001.dat").exists());
    }

    #[test]
    fn read_blocks_invalid_magic() {
        let dir = tempdir().unwrap();
        let mut file = File::create(dir.path().join("blk00000.dat")).unwrap();
        file.write_all(b"badmagic").unwrap();
        let res = read_blocks(dir.path());
        assert!(res.is_err());
    }

    #[test]
    fn read_blocks_too_small() {
        let dir = tempdir().unwrap();
        let mut file = File::create(dir.path().join("blk00000.dat")).unwrap();
        file.write_all(&MAGIC_BYTES[..2]).unwrap();
        let res = read_blocks(dir.path());
        assert!(res.is_err());
    }

    #[test]
    fn read_blocks_length_mismatch() {
        let dir = tempdir().unwrap();
        let mut file = File::create(dir.path().join("blk00000.dat")).unwrap();
        file.write_all(&MAGIC_BYTES).unwrap();
        file.write_all(&10u32.to_le_bytes()).unwrap();
        file.write_all(&[0u8; 5]).unwrap();
        let res = read_blocks(dir.path());
        assert!(res.is_err());
    }

    #[test]
    fn read_blocks_decode_error() {
        let dir = tempdir().unwrap();
        let mut file = File::create(dir.path().join("blk00000.dat")).unwrap();
        file.write_all(&MAGIC_BYTES).unwrap();
        file.write_all(&2u32.to_le_bytes()).unwrap();
        file.write_all(&[0u8; 2]).unwrap();
        let res = read_blocks(dir.path());
        assert!(res.is_err());
    }
}
