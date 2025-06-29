use bs58;
pub use coin_proto::Transaction;
use ripemd::Ripemd160;
use secp256k1;
use serde_json;
use sha2::{Digest, Sha256};
use std::fs::File;
use std::io::Write;
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

pub mod utils;
pub use utils::meets_difficulty;

/// Number of blocks used for difficulty adjustment
pub const DIFFICULTY_WINDOW: usize = 3;
/// Target time between blocks in seconds
pub const TARGET_BLOCK_TIME: u64 = 1;
/// Smallest unit of the coin (1 coin = 100 million units)
pub const COIN: u64 = 100_000_000;
/// Initial reward paid to miners for producing a block
pub const BLOCK_SUBSIDY: u64 = 50 * COIN;
/// Number of blocks between reward halvings. With an initial subsidy of 50 this
/// caps total issuance at 20 million coins.
pub const HALVING_INTERVAL: u64 = 200_000;
/// Maximum number of units that will ever exist
pub const MAX_SUPPLY: u64 = 20_000_000 * COIN;

pub fn new_transaction_with_fee(
    sender: impl Into<String>,
    recipient: impl Into<String>,
    amount: u64,
    fee: u64,
) -> Transaction {
    Transaction {
        sender: sender.into(),
        recipient: recipient.into(),
        amount,
        fee,
        signature: Vec::new(),
        encrypted_message: Vec::new(),
    }
}

pub fn new_transaction(
    sender: impl Into<String>,
    recipient: impl Into<String>,
    amount: u64,
) -> Transaction {
    new_transaction_with_fee(sender, recipient, amount, 0)
}

/// Create a coinbase transaction paying `amount` to `miner`
pub fn coinbase_transaction(miner: impl Into<String>, amount: u64) -> Transaction {
    Transaction {
        sender: String::new(),
        recipient: miner.into(),
        amount,
        fee: 0,
        signature: Vec::new(),
        encrypted_message: Vec::new(),
    }
}

pub fn encrypt_message(msg: &str, sk: &secp256k1::SecretKey, pk: &secp256k1::PublicKey) -> Vec<u8> {
    let secret = secp256k1::ecdh::SharedSecret::new(pk, sk);
    let key = Sha256::digest(secret.as_ref());
    msg.as_bytes()
        .iter()
        .enumerate()
        .map(|(i, b)| b ^ key[i % key.len()])
        .collect()
}

pub fn decrypt_message(
    data: &[u8],
    sk: &secp256k1::SecretKey,
    pk: &secp256k1::PublicKey,
) -> Option<String> {
    let secret = secp256k1::ecdh::SharedSecret::new(pk, sk);
    let key = Sha256::digest(secret.as_ref());
    let bytes: Vec<u8> = data
        .iter()
        .enumerate()
        .map(|(i, b)| b ^ key[i % key.len()])
        .collect();
    String::from_utf8(bytes).ok()
}

pub fn new_transaction_with_message(
    sender: impl Into<String>,
    recipient: impl Into<String>,
    amount: u64,
    fee: u64,
    message: &str,
    sender_sk: &secp256k1::SecretKey,
    recipient_pk: &secp256k1::PublicKey,
) -> Transaction {
    Transaction {
        sender: sender.into(),
        recipient: recipient.into(),
        amount,
        fee,
        signature: Vec::new(),
        encrypted_message: encrypt_message(message, sender_sk, recipient_pk),
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
    fn sign(&mut self, sk: &secp256k1::SecretKey);
    fn verify(&self) -> bool;
}

impl TransactionExt for Transaction {
    fn hash(&self) -> String {
        let mut hasher = Sha256::new();
        hasher.update(self.sender.as_bytes());
        hasher.update(self.recipient.as_bytes());
        hasher.update(self.amount.to_be_bytes());
        hasher.update(self.fee.to_be_bytes());
        hasher.update(&self.encrypted_message);
        let result = hasher.finalize();
        hex::encode(result)
    }

    fn sign(&mut self, sk: &secp256k1::SecretKey) {
        let secp = secp256k1::Secp256k1::new();
        let msg_hash = Sha256::digest(self.hash().as_bytes());
        let msg = secp256k1::Message::from_slice(&msg_hash).expect("32 bytes");
        let sig = secp.sign_ecdsa_recoverable(&msg, sk);
        let (rec_id, data) = sig.serialize_compact();
        self.signature.clear();
        self.signature.push(rec_id.to_i32() as u8);
        self.signature.extend_from_slice(&data);
    }

    fn verify(&self) -> bool {
        if self.signature.len() != 65 {
            return false;
        }
        let rec_id = match secp256k1::ecdsa::RecoveryId::from_i32(self.signature[0] as i32) {
            Ok(id) => id,
            Err(_) => return false,
        };
        let mut data = [0u8; 64];
        data.copy_from_slice(&self.signature[1..]);
        let sig = match secp256k1::ecdsa::RecoverableSignature::from_compact(&data, rec_id) {
            Ok(s) => s,
            Err(_) => return false,
        };
        let secp = secp256k1::Secp256k1::new();
        let msg_hash = Sha256::digest(self.hash().as_bytes());
        let msg = secp256k1::Message::from_slice(&msg_hash).expect("32 bytes");
        let pk = match secp.recover_ecdsa(&msg, &sig) {
            Ok(p) => p,
            Err(_) => return false,
        };
        // derive address from recovered public key
        let pk_bytes = pk.serialize();
        let sha = Sha256::digest(pk_bytes);
        let rip = Ripemd160::digest(sha);
        let mut payload = Vec::with_capacity(25);
        payload.push(0x00);
        payload.extend_from_slice(&rip);
        let check = Sha256::digest(Sha256::digest(&payload));
        payload.extend_from_slice(&check[..4]);
        let addr = bs58::encode(payload).into_string();
        addr == self.sender
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
        if tx.amount == 0 {
            return false;
        }
        if !tx.sender.is_empty() {
            let mut bal = self.balance(&tx.sender);
            for m in &self.mempool {
                if m.sender == tx.sender && !m.sender.is_empty() {
                    bal -= (m.amount + m.fee) as i64;
                }
                if m.recipient == tx.sender {
                    bal += m.amount as i64;
                }
            }
            if bal < (tx.amount + tx.fee) as i64 {
                return false;
            }
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

    /// Total amount of coins mined so far
    pub fn total_mined(&self) -> u64 {
        self.chain
            .iter()
            .flat_map(|b| &b.transactions)
            .filter(|tx| tx.sender.is_empty())
            .map(|tx| tx.amount)
            .sum()
    }

    /// Calculate the block subsidy for the given height and mined amount
    pub fn subsidy_for_height(height: u64, mined: u64) -> u64 {
        let halvings = height / HALVING_INTERVAL;
        if halvings >= 64 {
            return 0;
        }
        let mut reward = BLOCK_SUBSIDY >> halvings;
        if mined >= MAX_SUPPLY {
            reward = 0;
        } else if mined + reward > MAX_SUPPLY {
            reward = MAX_SUPPLY - mined;
        }
        reward
    }

    /// Subsidy for the next block mined on this chain
    pub fn block_subsidy(&self) -> u64 {
        Self::subsidy_for_height(self.chain.len() as u64, self.total_mined())
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
        let chain = coin_proto::Chain {
            blocks: self.chain.iter().map(|b| b.to_rpc()).collect(),
        };
        let data = serde_json::to_vec(&chain).unwrap();
        let mut f = File::create(path)?;
        f.write_all(&data)
    }

    pub fn load<P: AsRef<Path>>(path: P) -> std::io::Result<Self> {
        let f = File::open(path)?;
        let chain_msg: coin_proto::Chain = serde_json::from_reader(f).unwrap();
        let mut bc = Blockchain::new();
        for pb in chain_msg.blocks {
            if let Some(block) = Block::from_rpc(pb) {
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
                    bal -= (tx.amount + tx.fee) as i64;
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
        // fund both accounts
        bc.add_block(Block {
            header: BlockHeader {
                previous_hash: String::new(),
                merkle_root: String::new(),
                timestamp: 0,
                nonce: 0,
                difficulty: 0,
            },
            transactions: vec![
                coinbase_transaction(A1, bc.block_subsidy()),
                coinbase_transaction(A2, bc.block_subsidy()),
            ],
        });
        let tx1 = new_transaction(A1, A2, 5);
        let tx2 = new_transaction(A2, A1, 7);
        assert!(bc.add_transaction(tx1.clone()));
        assert!(bc.add_transaction(tx2.clone()));
        // Candidate block should contain both transactions
        let block = bc.candidate_block();
        assert_eq!(block.transactions.len(), 2);
        bc.add_block(block.clone());
        assert_eq!(bc.len(), 2);
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
            transactions: vec![coinbase_transaction(A1, bc.block_subsidy())],
        });
        assert_eq!(bc.balance(A1), bc.block_subsidy() as i64);
    }

    #[test]
    fn reject_invalid_transaction() {
        let mut bc = Blockchain::new();
        let tx = new_transaction("badaddr", A2, 1);
        assert!(!bc.add_transaction(tx));
        assert_eq!(bc.mempool_len(), 0);
    }

    #[test]
    fn reject_zero_amount_transaction() {
        let mut bc = Blockchain::new();
        let tx = new_transaction(A1, A2, 0);
        assert!(!bc.add_transaction(tx));
    }

    #[test]
    fn reject_insufficient_balance() {
        let mut bc = Blockchain::new();
        // give A1 some coins
        bc.add_block(Block {
            header: BlockHeader {
                previous_hash: String::new(),
                merkle_root: String::new(),
                timestamp: 0,
                nonce: 0,
                difficulty: 0,
            },
            transactions: vec![coinbase_transaction(A1, bc.block_subsidy())],
        });
        let tx = new_transaction(A1, A2, bc.block_subsidy() + 1);
        assert!(!bc.add_transaction(tx));
    }

    #[test]
    fn fee_deducts_from_balance() {
        let mut bc = Blockchain::new();
        bc.add_block(Block {
            header: BlockHeader {
                previous_hash: String::new(),
                merkle_root: String::new(),
                timestamp: 0,
                nonce: 0,
                difficulty: 0,
            },
            transactions: vec![coinbase_transaction(A1, bc.block_subsidy())],
        });
        let tx = new_transaction_with_fee(A1, A2, 5, 2);
        assert!(bc.add_transaction(tx.clone()));
        let block = bc.candidate_block();
        bc.add_block(block);
        assert_eq!(bc.balance(A1), bc.block_subsidy() as i64 - 7);
        assert_eq!(bc.balance(A2), 5);
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
            transactions: vec![coinbase_transaction(A1, bc.block_subsidy())],
        });
        let tmp = tempfile::NamedTempFile::new().unwrap();
        bc.save(tmp.path()).unwrap();
        let loaded = Blockchain::load(tmp.path()).unwrap();
        assert_eq!(loaded.len(), bc.len());
        assert_eq!(loaded.last_block_hash(), bc.last_block_hash());
    }

    fn address_from_secret(sk: &secp256k1::SecretKey) -> String {
        let secp = secp256k1::Secp256k1::new();
        let pk = secp256k1::PublicKey::from_secret_key(&secp, sk);
        let pk_bytes = pk.serialize();
        let sha = Sha256::digest(pk_bytes);
        let rip = Ripemd160::digest(sha);
        let mut payload = Vec::with_capacity(25);
        payload.push(0x00);
        payload.extend_from_slice(&rip);
        let check = Sha256::digest(Sha256::digest(&payload));
        payload.extend_from_slice(&check[..4]);
        bs58::encode(payload).into_string()
    }

    #[test]
    fn valid_address_checks() {
        assert!(valid_address(A1));
        assert!(valid_address(A2));
        assert!(!valid_address("invalid"));
        let bad_chars = "O".repeat(34);
        assert!(!valid_address(&bad_chars));
        let bad_len = "1".repeat(34);
        assert!(!valid_address(&bad_len));
    }

    #[test]
    fn sign_and_verify_transaction() {
        let sk = secp256k1::SecretKey::from_slice(&[1u8; 32]).unwrap();
        let sender = address_from_secret(&sk);
        let mut tx = new_transaction(&sender, A2, 5);
        tx.sign(&sk);
        assert!(tx.verify());
    }

    #[test]
    fn verify_rejects_bad_signature_len() {
        let mut tx = new_transaction(A1, A2, 5);
        tx.signature = vec![0u8; 10];
        assert!(!tx.verify());
    }

    #[test]
    fn verify_rejects_invalid_recovery_id() {
        let mut tx = new_transaction(A1, A2, 5);
        tx.signature = vec![4u8; 65];
        assert!(!tx.verify());
    }

    #[test]
    fn verify_rejects_malformed_signature() {
        let mut sig = vec![0u8; 65];
        sig[0] = 0; // valid recovery id
        let mut tx = new_transaction(A1, A2, 5);
        tx.signature = sig;
        assert!(!tx.verify());
    }

    #[test]
    fn encrypt_and_decrypt_message() {
        let secp = secp256k1::Secp256k1::new();
        let sk_sender = secp256k1::SecretKey::from_slice(&[1u8; 32]).unwrap();
        let sk_recipient = secp256k1::SecretKey::from_slice(&[2u8; 32]).unwrap();
        let pk_sender = secp256k1::PublicKey::from_secret_key(&secp, &sk_sender);
        let pk_recipient = secp256k1::PublicKey::from_secret_key(&secp, &sk_recipient);
        let msg = "hello";
        let encrypted = encrypt_message(msg, &sk_sender, &pk_recipient);
        let decrypted = decrypt_message(&encrypted, &sk_recipient, &pk_sender).unwrap();
        assert_eq!(decrypted, msg);
    }

    #[test]
    fn new_transaction_with_message_encryption() {
        let secp = secp256k1::Secp256k1::new();
        let sk_sender = secp256k1::SecretKey::from_slice(&[1u8; 32]).unwrap();
        let pk_recipient = secp256k1::PublicKey::from_secret_key(
            &secp,
            &secp256k1::SecretKey::from_slice(&[2u8; 32]).unwrap(),
        );
        let tx = new_transaction_with_message(A1, A2, 5, 0, "secret", &sk_sender, &pk_recipient);
        assert!(!tx.encrypted_message.is_empty());
    }
}
