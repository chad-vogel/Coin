pub use coin_proto::proto::Transaction;
use sha2::{Digest, Sha256};
use std::time::{SystemTime, UNIX_EPOCH};

pub fn new_transaction(sender: String, recipient: String, amount: u64) -> Transaction {
    Transaction {
        sender,
        recipient,
        amount,
    }
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
}

pub struct Blockchain {
    chain: Vec<Block>,
    mempool: Vec<Transaction>,
}

impl Blockchain {
    pub fn new() -> Self {
        Self {
            chain: Vec::new(),
            mempool: Vec::new(),
        }
    }

    /// Add a transaction to the mempool
    pub fn add_transaction(&mut self, tx: Transaction) {
        self.mempool.push(tx);
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
                difficulty: 0,
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
    }

    pub fn last_block_hash(&self) -> Option<String> {
        self.chain.last().map(|b| b.hash())
    }

    pub fn len(&self) -> usize {
        self.chain.len()
    }

    pub fn replace(&mut self, new_chain: Vec<Block>) {
        if new_chain.len() > self.chain.len() {
            self.chain = new_chain;
        }
    }

    pub fn all(&self) -> Vec<Block> {
        self.chain.clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn transaction_hash_consistent() {
        let tx = new_transaction("alice".into(), "bob".into(), 10);
        let hash1 = tx.hash();
        let hash2 = tx.hash();
        assert_eq!(hash1, hash2);
    }

    #[test]
    fn mempool_and_blocks() {
        let mut bc = Blockchain::new();
        assert_eq!(bc.len(), 0);
        let tx1 = new_transaction("alice".into(), "bob".into(), 5);
        let tx2 = new_transaction("carol".into(), "dave".into(), 7);
        bc.add_transaction(tx1.clone());
        bc.add_transaction(tx2.clone());
        // Candidate block should contain both transactions
        let block = bc.candidate_block();
        assert_eq!(block.transactions.len(), 2);
        bc.add_block(block.clone());
        assert_eq!(bc.len(), 1);
        // mempool cleared
        assert!(bc.mempool.is_empty());
        assert_eq!(bc.last_block_hash().unwrap(), block.hash());
    }
}
