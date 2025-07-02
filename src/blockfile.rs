use std::fs::{self, File};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

use bincode;
use rocksdb::{DB, IteratorMode, Options};

use crate::Block;

const CURRENT_FILE: &str = "CURRENT";

/// Magic bytes identifying the start of a block in legacy files.
const MAGIC_BYTES: [u8; 4] = [0xF9, 0xBE, 0xB4, 0xD9];

fn db_exists(dir: &Path) -> bool {
    dir.join(CURRENT_FILE).exists()
}

fn open_db(path: &Path) -> std::io::Result<DB> {
    let mut opts = Options::default();
    opts.create_if_missing(true);
    DB::open(&opts, path).map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))
}

fn destroy_db(path: &Path) -> std::io::Result<()> {
    if path.exists() {
        DB::destroy(&Options::default(), path)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;
    }
    Ok(())
}

fn serialize_error<E: std::fmt::Display>(e: E) -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::Other, format!("serialize error: {e}"))
}

/// Determine the next block index by examining existing keys.
fn next_index(db: &DB) -> u32 {
    for item in db.iterator(IteratorMode::End) {
        if let Ok((k, _)) = item {
            if k.len() == 4 {
                return u32::from_be_bytes(k.as_ref().try_into().unwrap()) + 1;
            }
        }
    }
    0
}

/// Append `block` to the RocksDB database located at `dir`.
pub fn append_block(dir: &Path, block: &Block) -> std::io::Result<()> {
    migrate_from_files(dir)?;
    let db = open_db(dir)?;
    let index = next_index(&db);
    let data = bincode::serialize(block).map_err(serialize_error)?;
    db.put(index.to_be_bytes(), data)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;
    Ok(())
}

/// Read all blocks from RocksDB at `dir`. If legacy files are present they are
/// migrated automatically.
pub fn read_blocks(dir: &Path) -> std::io::Result<Vec<Block>> {
    migrate_from_files(dir)?;
    let db = open_db(dir)?;
    let mut blocks = Vec::new();
    for item in db.iterator(IteratorMode::Start) {
        let (k, v) = item.map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;
        if k.len() != 4 {
            continue;
        }
        let block: Block = bincode::deserialize(&v)
            .map_err(|_| std::io::Error::new(std::io::ErrorKind::InvalidData, "decode error"))?;
        blocks.push(block);
    }
    Ok(blocks)
}

/// Remove all stored blocks.
pub fn reset(dir: &Path) -> std::io::Result<()> {
    destroy_db(dir)
}

// ----- Legacy file support -----
fn blockfile_path(dir: &Path, index: u32) -> PathBuf {
    dir.join(format!("blk{:05}.dat", index))
}

fn legacy_next_index(dir: &Path) -> std::io::Result<u32> {
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

fn append_block_file(dir: &Path, block: &Block) -> std::io::Result<()> {
    let index = legacy_next_index(dir)?;
    let path = blockfile_path(dir, index);
    let mut file = File::create(&path)?;
    let data = bincode::serialize(block).map_err(serialize_error)?;
    file.write_all(&MAGIC_BYTES)?;
    file.write_all(&(data.len() as u32).to_le_bytes())?;
    file.write_all(&data)?;
    Ok(())
}

fn read_blocks_files(dir: &Path) -> std::io::Result<Vec<Block>> {
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

fn migrate_from_files(dir: &Path) -> std::io::Result<()> {
    if db_exists(dir) {
        return Ok(());
    }
    let mut has_files = false;
    for entry in fs::read_dir(dir).unwrap_or_else(|_| fs::read_dir(".").unwrap()) {
        if let Ok(entry) = entry {
            if let Some(name) = entry.file_name().to_str() {
                if name.starts_with("blk") && name.ends_with(".dat") {
                    has_files = true;
                    break;
                }
            }
        }
    }
    if !has_files {
        // ensure DB directory exists
        let _ = open_db(dir)?;
        return Ok(());
    }
    let blocks = read_blocks_files(dir)?;
    destroy_db(dir)?;
    let db = open_db(dir)?;
    for (i, block) in blocks.iter().enumerate() {
        let data = bincode::serialize(block).map_err(serialize_error)?;
        db.put((i as u32).to_be_bytes(), data)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;
    }
    // remove legacy files
    for entry in fs::read_dir(dir)? {
        let entry = entry?;
        if let Some(name) = entry.file_name().to_str() {
            if name.starts_with("blk") && name.ends_with(".dat") {
                let _ = fs::remove_file(entry.path());
            }
        }
    }
    Ok(())
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
        let tx =
            coinbase_transaction("1BvgsfsZQVtkLS69NvGF8rw6NZW2ShJQHr", bc.block_subsidy()).unwrap();
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
    fn append_creates_multiple_entries() {
        let dir = tempdir().unwrap();
        let mut bc = Blockchain::new();
        let tx =
            coinbase_transaction("1BvgsfsZQVtkLS69NvGF8rw6NZW2ShJQHr", bc.block_subsidy()).unwrap();
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
        let db = open_db(dir.path()).unwrap();
        let count = db.iterator(IteratorMode::Start).count();
        assert_eq!(count, 2);
    }

    #[test]
    fn read_blocks_decode_error() {
        let dir = tempdir().unwrap();
        let db = open_db(dir.path()).unwrap();
        db.put(0u32.to_be_bytes(), [0u8, 1u8])
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))
            .unwrap();
        let res = read_blocks(dir.path());
        assert!(res.is_err());
    }
}
