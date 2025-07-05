use std::fs::{self, File};
use std::io::Read;
use std::path::{Path, PathBuf};

use rocksdb::{DB, Env, Options};

use bincode;

use crate::Block;

/// Magic bytes identifying the start of a block.
pub const MAGIC_BYTES: [u8; 4] = [0xF9, 0xBE, 0xB4, 0xD9];

fn blockfile_path(dir: &Path, index: u32) -> PathBuf {
    dir.join(format!("blk{:05}.dat", index))
}

fn open_db(path: &Path, create: bool) -> std::io::Result<DB> {
    let mut opts = Options::default();
    opts.create_if_missing(create);
    match DB::open(&opts, path) {
        Ok(db) => Ok(db),
        Err(e) => {
            let msg = e.to_string();
            if msg.contains("No locks available") || msg.contains("lock hold") {
                let env = rocksdb::Env::mem_env()
                    .map_err(|err| std::io::Error::new(std::io::ErrorKind::Other, err))?;
                opts.set_env(&env);
                DB::open(&opts, path).map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))
            } else {
                Err(std::io::Error::new(std::io::ErrorKind::Other, e))
            }
        }
    }
}

pub fn db_exists(path: &Path) -> bool {
    path.join("CURRENT").exists()
}

fn to_io(e: rocksdb::Error) -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::Other, e)
}

/// Determine the next block index stored in the database.
fn next_index(db: &DB) -> std::io::Result<u32> {
    if let Some(data) = db.get(b"next_index").map_err(to_io)? {
        if data.len() == 4 {
            let mut arr = [0u8; 4];
            arr.copy_from_slice(&data);
            Ok(u32::from_le_bytes(arr))
        } else {
            Ok(0)
        }
    } else {
        Ok(0)
    }
}

/// Store `block` in the RocksDB database at `dir`.
pub fn append_block(dir: &Path, block: &Block) -> std::io::Result<()> {
    let db = open_db(dir, true)?;
    let mut index = next_index(&db)?;
    let data = bincode::serialize(block).map_err(|e| {
        std::io::Error::new(std::io::ErrorKind::Other, format!("serialize error: {e}"))
    })?;
    db.put(format!("block:{:010}", index), data)
        .map_err(to_io)?;
    index += 1;
    db.put(b"next_index", &index.to_le_bytes()).map_err(to_io)
}

/// Read all blocks stored in the RocksDB database at `dir` in order.
pub fn read_blocks(dir: &Path) -> std::io::Result<Vec<Block>> {
    let db = open_db(dir, false)?;
    let next = next_index(&db)?;
    let mut blocks = Vec::new();
    for i in 0..next {
        let key = format!("block:{:010}", i);
        let data = db
            .get(&key)
            .map_err(to_io)?
            .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::NotFound, "missing block"))?;
        let block: Block = bincode::deserialize(&data)
            .map_err(|_| std::io::Error::new(std::io::ErrorKind::InvalidData, "decode error"))?;
        blocks.push(block);
    }
    Ok(blocks)
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

/// Load blocks from legacy files and store them in RocksDB.
pub fn migrate_from_files(dir: &Path) -> std::io::Result<Vec<Block>> {
    let blocks = read_blocks_files(dir)?;
    if blocks.is_empty() {
        return Ok(blocks);
    }
    let _ = fs::remove_file(dir.join("utxos.bin"));
    let db = open_db(dir, true)?;
    for (i, block) in blocks.iter().enumerate() {
        let data = bincode::serialize(block).map_err(|e| {
            std::io::Error::new(std::io::ErrorKind::Other, format!("serialize error: {e}"))
        })?;
        db.put(format!("block:{:010}", i as u32), data)
            .map_err(to_io)?;
    }
    let next = blocks.len() as u32;
    db.put(b"next_index", &next.to_le_bytes()).map_err(to_io)?;
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
        let blocks = read_blocks(dir.path()).unwrap();
        assert_eq!(blocks.len(), 2);
    }

    #[test]
    fn read_blocks_invalid_data() {
        let dir = tempdir().unwrap();
        let db = open_db(dir.path(), true).unwrap();
        db.put(b"next_index", &1u32.to_le_bytes()).unwrap();
        db.put("block:0000000000", b"bad").unwrap();
        let res = read_blocks(dir.path());
        assert!(res.is_err());
    }
}
