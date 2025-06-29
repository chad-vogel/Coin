use bs58;
pub use coin_proto::proto::Transaction;
use prost::Message;
use sha2::{Digest, Sha256};
use std::fs::File;
use std::io::{Read, Write};
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

/// Number of blocks used for difficulty adjustment
pub const DIFFICULTY_WINDOW: usize = 3;
/// Target time between blocks in seconds
pub const TARGET_BLOCK_TIME: u64 = 1;
/// Reward paid to miners for producing a block
pub const BLOCK_SUBSIDY: u64 = 50;

pub fn new_transaction(
    sender: impl Into<String>,
    recipient: impl Into<String>,
    amount: u64,
) -> Transaction {
    Transaction {
        sender: sender.into(),
        recipient: recipient.into(),
        amount,
    }
}

/// Create a coinbase transaction paying the block subsidy to `miner`
pub fn coinbase_transaction(miner: impl Into<String>) -> Transaction {
    Transaction {
        sender: String::new(),
        recipient: miner.into(),
        amount: BLOCK_SUBSIDY,
    }
}

/// Validate that an address is Base58Check encoded and 34 characters long.
pub fn valid_address(addr: &str) -> bool {
    if addr.len() != 34 {
        return false;
    }
    let bytes = match bs58::decode(addr).into_vec() {
        Ok(b) => b,
        Err(_) => return false,
    };
    if bytes.len() != 25 || bytes[0] != 0x00 {
        return false;
    }
    let (payload, checksum) = bytes.split_at(21);
    let check = Sha256::digest(Sha256::digest(payload));
    checksum == &check[..4]
}

pub trait TransactionExt {
    fn hash(&self) -> String;
}

impl TransactionExt for Transaction {
    fn hash(&self) -> String {
        let mut hasher = Sha256::new();
        hasher.update(self.sender.as_bytes());
        hasher.update(self.recipient.as_bytes());
        hasher.update(self.amount.to_be_bytes());
        let result = hasher.finalize();
        hex::encode(result)
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct BlockHeader {
    pub previous_hash: String,
    pub merkle_root: String,
    pub timestamp: u64,
    pub nonce: u64,
    pub difficulty: u32,
}

#[derive(Clone, Debug, PartialEq)]
pub struct Block {
    pub header: BlockHeader,
    pub transactions: Vec<Transaction>,
}

impl Block {
    /// Hash the block header and transactions for block identification
    pub fn hash(&self) -> String {
        let mut hasher = Sha256::new();
        hasher.update(self.header.previous_hash.as_bytes());
        hasher.update(self.header.merkle_root.as_bytes());
        hasher.update(self.header.timestamp.to_be_bytes());
        hasher.update(self.header.nonce.to_be_bytes());
        hasher.update(self.header.difficulty.to_be_bytes());
        for tx in &self.transactions {
            hasher.update(tx.hash());
        }
        hex::encode(hasher.finalize())
    }

    pub fn to_proto(&self) -> coin_proto::proto::Block {
        coin_proto::proto::Block {
            header: Some(coin_proto::proto::BlockHeader {
                previous_hash: self.header.previous_hash.clone(),
                merkle_root: self.header.merkle_root.clone(),
                timestamp: self.header.timestamp,
                nonce: self.header.nonce,
                difficulty: self.header.difficulty,
            }),
            transactions: self.transactions.clone(),
        }
    }

    pub fn from_proto(pb: coin_proto::proto::Block) -> Option<Self> {
        pb.header.map(|h| Block {
            header: BlockHeader {
                previous_hash: h.previous_hash,
                merkle_root: h.merkle_root,
                timestamp: h.timestamp,
                nonce: h.nonce,
                difficulty: h.difficulty,
            },
            transactions: pb.transactions,
        })
    }
}

pub struct Blockchain {
    chain: Vec<Block>,
    mempool: Vec<Transaction>,
    difficulty: u32,
}

impl Blockchain {
    pub fn new() -> Self {
        Self {
            chain: Vec::new(),
            mempool: Vec::new(),
            difficulty: 1,
        }
    }

    /// Add a transaction to the mempool if addresses are valid.
    /// Returns `true` if the transaction was accepted.
    pub fn add_transaction(&mut self, tx: Transaction) -> bool {
        if (!tx.sender.is_empty() && !valid_address(&tx.sender)) || !valid_address(&tx.recipient) {
            return false;
        }
        self.mempool.push(tx);
        true
    }

    /// Create a block from current mempool transactions without clearing them
    pub fn candidate_block(&self) -> Block {
        let previous_hash = self.last_block_hash().unwrap_or_default();
        let mut hasher = Sha256::new();
        for tx in &self.mempool {
            hasher.update(tx.hash());
        }
        let merkle_root = hex::encode(hasher.finalize());
        Block {
            header: BlockHeader {
                previous_hash,
                merkle_root,
                timestamp: SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap()
                    .as_secs(),
                nonce: 0,
                difficulty: self.difficulty,
            },
            transactions: self.mempool.clone(),
        }
    }

    /// Append a confirmed block to the chain and clear contained transactions
    pub fn add_block(&mut self, block: Block) {
        for tx in &block.transactions {
            if let Some(pos) = self.mempool.iter().position(|m| m == tx) {
                self.mempool.remove(pos);
            }
        }
        self.chain.push(block);

        if self.chain.len() >= DIFFICULTY_WINDOW {
            let window = &self.chain[self.chain.len() - DIFFICULTY_WINDOW..];
            let mut total = 0u64;
            let mut count = 0u64;
            for pair in window.windows(2) {
                total += pair[1].header.timestamp - pair[0].header.timestamp;
                count += 1;
            }
            if count > 0 {
                let avg = total / count;
                if avg < TARGET_BLOCK_TIME {
                    self.difficulty = self.difficulty.saturating_add(1);
                } else if avg > TARGET_BLOCK_TIME {
                    self.difficulty = self.difficulty.saturating_sub(1);
                }
            }
        }
    }

    pub fn last_block_hash(&self) -> Option<String> {
        self.chain.last().map(|b| b.hash())
    }

    pub fn len(&self) -> usize {
        self.chain.len()
    }

    pub fn difficulty(&self) -> u32 {
        self.difficulty
    }

    pub fn replace(&mut self, new_chain: Vec<Block>) {
        if new_chain.len() > self.chain.len() {
            self.chain = new_chain;
        }
    }

    pub fn all(&self) -> Vec<Block> {
        self.chain.clone()
    }

    pub fn save<P: AsRef<Path>>(&self, path: P) -> std::io::Result<()> {
        let chain = coin_proto::proto::Chain {
            blocks: self.chain.iter().map(|b| b.to_proto()).collect(),
        };
        let mut buf = Vec::new();
        chain.encode(&mut buf).unwrap();
        let mut f = File::create(path)?;
        f.write_all(&buf)
    }

    pub fn load<P: AsRef<Path>>(path: P) -> std::io::Result<Self> {
        let mut buf = Vec::new();
        let mut f = File::open(path)?;
        f.read_to_end(&mut buf)?;
        let chain_msg = coin_proto::proto::Chain::decode(&buf[..]).unwrap();
        let mut bc = Blockchain::new();
        for pb in chain_msg.blocks {
            if let Some(block) = Block::from_proto(pb) {
                bc.add_block(block);
            }
        }
        Ok(bc)
    }

    /// Calculate the balance for `addr` by scanning the chain
    pub fn balance(&self, addr: &str) -> i64 {
        let mut bal: i64 = 0;
        for block in &self.chain {
            for tx in &block.transactions {
                if tx.sender == addr && !tx.sender.is_empty() {
                    bal -= tx.amount as i64;
                }
                if tx.recipient == addr {
                    bal += tx.amount as i64;
                }
            }
        }
        bal
    }

    pub fn mempool_len(&self) -> usize {
        self.mempool.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const A1: &str = "1BvgsfsZQVtkLS69NvGF8rw6NZW2ShJQHr";
    const A2: &str = "1B1TKfsCkW5LQ6R1kSXUx7hLt49m1kwz75";

    #[test]
    fn transaction_hash_consistent() {
        let tx = new_transaction(A1, A2, 10);
        let hash1 = tx.hash();
        let hash2 = tx.hash();
        assert_eq!(hash1, hash2);
    }

    #[test]
    fn mempool_and_blocks() {
        let mut bc = Blockchain::new();
        assert_eq!(bc.len(), 0);
        let tx1 = new_transaction(A1, A2, 5);
        let tx2 = new_transaction(A2, A1, 7);
        assert!(bc.add_transaction(tx1.clone()));
        assert!(bc.add_transaction(tx2.clone()));
        // Candidate block should contain both transactions
        let block = bc.candidate_block();
        assert_eq!(block.transactions.len(), 2);
        bc.add_block(block.clone());
        assert_eq!(bc.len(), 1);
        // mempool cleared
        assert!(bc.mempool.is_empty());
        assert_eq!(bc.last_block_hash().unwrap(), block.hash());
    }

    #[test]
    fn difficulty_increases_and_decreases() {
        let mut bc = Blockchain::new();

        // mine blocks too quickly
        for _ in 0..DIFFICULTY_WINDOW {
            let block = Block {
                header: BlockHeader {
                    previous_hash: bc.last_block_hash().unwrap_or_default(),
                    merkle_root: String::new(),
                    timestamp: 0,
                    nonce: 0,
                    difficulty: bc.difficulty(),
                },
                transactions: vec![],
            };
            bc.add_block(block);
        }
        let diff_after_fast = bc.difficulty();
        assert!(diff_after_fast > 1);

        // mine blocks too slowly
        let start = DIFFICULTY_WINDOW as u64 * 2;
        for i in 0..DIFFICULTY_WINDOW {
            let block = Block {
                header: BlockHeader {
                    previous_hash: bc.last_block_hash().unwrap_or_default(),
                    merkle_root: String::new(),
                    timestamp: start + (i as u64 * 2),
                    nonce: 0,
                    difficulty: bc.difficulty(),
                },
                transactions: vec![],
            };
            bc.add_block(block);
        }
        let diff_after_slow = bc.difficulty();
        assert!(diff_after_slow < diff_after_fast);
        assert!(diff_after_slow <= diff_after_fast);
    }

    #[test]
    fn balance_reflects_coinbase() {
        let mut bc = Blockchain::new();
        assert_eq!(bc.balance(A1), 0);
        bc.add_block(Block {
            header: BlockHeader {
                previous_hash: String::new(),
                merkle_root: String::new(),
                timestamp: 0,
                nonce: 0,
                difficulty: 0,
            },
            transactions: vec![coinbase_transaction(A1)],
        });
        assert_eq!(bc.balance(A1), BLOCK_SUBSIDY as i64);
    }

    #[test]
    fn reject_invalid_transaction() {
        let mut bc = Blockchain::new();
        let tx = new_transaction("badaddr", A2, 1);
        assert!(!bc.add_transaction(tx));
        assert_eq!(bc.mempool_len(), 0);
    }

    #[test]
    fn save_and_load_chain() {
        let mut bc = Blockchain::new();
        bc.add_block(Block {
            header: BlockHeader {
                previous_hash: String::new(),
                merkle_root: String::new(),
                timestamp: 0,
                nonce: 0,
                difficulty: 0,
            },
            transactions: vec![coinbase_transaction(A1)],
        });
        let tmp = tempfile::NamedTempFile::new().unwrap();
        bc.save(tmp.path()).unwrap();
        let loaded = Blockchain::load(tmp.path()).unwrap();
        assert_eq!(loaded.len(), bc.len());
        assert_eq!(loaded.last_block_hash(), bc.last_block_hash());
    }
}
