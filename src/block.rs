use crate::Transaction;
use sha2::{Digest, Sha256};

#[derive(Clone, Debug, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct BlockHeader {
    pub previous_hash: String,
    pub merkle_root: String,
    /// Milliseconds since the Unix epoch
    pub timestamp: u64,
    pub nonce: u64,
    pub difficulty: u32,
}

#[derive(Clone, Debug, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct Block {
    pub header: BlockHeader,
    pub transactions: Vec<Transaction>,
}

impl Block {
    /// Hash the block header for block identification.
    /// The Merkle root in the header commits to all transactions, so the
    /// transactions themselves are not included here.
    pub fn hash(&self) -> String {
        let mut hasher = Sha256::new();
        hasher.update(self.header.previous_hash.as_bytes());
        hasher.update(self.header.merkle_root.as_bytes());
        hasher.update(self.header.timestamp.to_be_bytes());
        hasher.update(self.header.nonce.to_be_bytes());
        hasher.update(self.header.difficulty.to_be_bytes());
        hex::encode(hasher.finalize())
    }

    pub fn to_rpc(&self) -> coin_proto::Block {
        coin_proto::Block {
            header: coin_proto::BlockHeader {
                previous_hash: self.header.previous_hash.clone(),
                merkle_root: self.header.merkle_root.clone(),
                timestamp: self.header.timestamp,
                nonce: self.header.nonce,
                difficulty: self.header.difficulty,
            },
            transactions: self.transactions.clone(),
        }
    }

    pub fn from_rpc(pb: coin_proto::Block) -> Option<Self> {
        Some(Block {
            header: BlockHeader {
                previous_hash: pb.header.previous_hash,
                merkle_root: pb.header.merkle_root,
                timestamp: pb.header.timestamp,
                nonce: pb.header.nonce,
                difficulty: pb.header.difficulty,
            },
            transactions: pb.transactions,
        })
    }

    /// Remove transactions from the block while preserving the header.
    /// This simulates pruning after enough confirmations.
    pub fn prune(&mut self) {
        self.transactions.clear();
    }
}
