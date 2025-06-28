use sha2::{Digest, Sha256};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Transaction {
    pub sender: String,
    pub recipient: String,
    pub amount: u64,
}

impl Transaction {
    pub fn new(sender: String, recipient: String, amount: u64) -> Self {
        Self {
            sender,
            recipient,
            amount,
        }
    }

    pub fn hash(&self) -> String {
        let mut hasher = Sha256::new();
        hasher.update(self.sender.as_bytes());
        hasher.update(self.recipient.as_bytes());
        hasher.update(self.amount.to_be_bytes());
        let result = hasher.finalize();
        hex::encode(result)
    }
}

pub struct Blockchain {
    chain: Vec<Transaction>,
}

impl Blockchain {
    pub fn new() -> Self {
        Self { chain: Vec::new() }
    }

    pub fn add_transaction(&mut self, tx: Transaction) {
        self.chain.push(tx);
    }

    pub fn last_hash(&self) -> Option<String> {
        self.chain.last().map(|tx| tx.hash())
    }

    pub fn len(&self) -> usize {
        self.chain.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn transaction_hash_consistent() {
        let tx = Transaction::new("alice".into(), "bob".into(), 10);
        let hash1 = tx.hash();
        let hash2 = tx.hash();
        assert_eq!(hash1, hash2);
    }

    #[test]
    fn blockchain_adds_transactions() {
        let mut bc = Blockchain::new();
        assert_eq!(bc.len(), 0);
        let tx = Transaction::new("alice".into(), "bob".into(), 5);
        bc.add_transaction(tx.clone());
        assert_eq!(bc.len(), 1);
        assert!(bc.last_hash().is_some());
        assert_eq!(bc.last_hash().unwrap(), tx.hash());
    }
}
