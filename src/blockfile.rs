use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

use bincode;

use crate::Block;

/// Magic bytes identifying the start of a block.
pub const MAGIC_BYTES: [u8; 4] = [0xF9, 0xBE, 0xB4, 0xD9];

/// Maximum size of a blk.dat file in bytes (128 MiB).
pub const MAX_BLOCKFILE_SIZE: u64 = 128 * 1024 * 1024;

fn blockfile_path(dir: &Path, index: u32) -> PathBuf {
    dir.join(format!("blk{:05}.dat", index))
}

fn current_blockfile(dir: &Path) -> std::io::Result<(PathBuf, u32)> {
    fs::create_dir_all(dir)?;
    let mut index = 0;
    loop {
        let path = blockfile_path(dir, index);
        if !path.exists() {
            if index == 0 {
                return Ok((path, index));
            }
            return Ok((blockfile_path(dir, index - 1), index - 1));
        }
        index += 1;
    }
}

/// Append a block to the blk.dat files in `dir`.
pub fn append_block(dir: &Path, block: &Block) -> std::io::Result<()> {
    let (mut path, mut index) = current_blockfile(dir)?;
    let mut file = OpenOptions::new().append(true).create(true).open(&path)?;
    if file.metadata()?.len() >= MAX_BLOCKFILE_SIZE {
        index += 1;
        path = blockfile_path(dir, index);
        file = OpenOptions::new().append(true).create(true).open(&path)?;
    }
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
        let mut i = 0;
        while i + 8 <= buf.len() {
            if buf[i..i + 4] != MAGIC_BYTES {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "bad magic bytes",
                ));
            }
            let len = u32::from_le_bytes([buf[i + 4], buf[i + 5], buf[i + 6], buf[i + 7]]) as usize;
            i += 8;
            if i + len > buf.len() {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::UnexpectedEof,
                    "unexpected eof",
                ));
            }
            let block: Block = bincode::deserialize(&buf[i..i + len]).map_err(|_| {
                std::io::Error::new(std::io::ErrorKind::InvalidData, "decode error")
            })?;
            blocks.push(block);
            i += len;
        }
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
    fn append_creates_new_file_when_full() {
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
        let first = dir.path().join("blk00000.dat");
        OpenOptions::new()
            .append(true)
            .open(&first)
            .unwrap()
            .set_len(MAX_BLOCKFILE_SIZE)
            .unwrap();
        append_block(dir.path(), &block).unwrap();
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
}
