use bs58;
pub use coin_proto::{Transaction, TransactionInput, TransactionOutput};
use contract_runtime;
use ripemd::Ripemd160;
use secp256k1;
use serde_json;
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::fs::File;
use std::io::Write;
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

pub mod blockfile;
pub mod utils;
pub mod utxofile;
pub use utils::meets_difficulty;

/// Compute the Merkle root of a set of hex-encoded transaction hashes.
pub fn merkle_root_from_hashes(hashes: &[String]) -> String {
    if hashes.is_empty() {
        return hex::encode(Sha256::digest(&[]));
    }
    let mut layer: Vec<Vec<u8>> = hashes
        .iter()
        .map(|h| hex::decode(h).unwrap_or_default())
        .collect();
    while layer.len() > 1 {
        let mut next = Vec::new();
        for chunk in layer.chunks(2) {
            let left = &chunk[0];
            let right = if chunk.len() > 1 { &chunk[1] } else { left };
            let mut hasher = Sha256::new();
            hasher.update(left);
            hasher.update(right);
            next.push(hasher.finalize().to_vec());
        }
        layer = next;
    }
    hex::encode(&layer[0])
}

/// Compute the Merkle root for a slice of transactions.
pub fn compute_merkle_root(txs: &[Transaction]) -> String {
    let hashes: Vec<String> = txs.iter().map(|t| t.hash()).collect();
    merkle_root_from_hashes(&hashes)
}

/// Number of blocks used for difficulty adjustment
pub const DIFFICULTY_WINDOW: usize = 3;
/// Target time between blocks in milliseconds
pub const TARGET_BLOCK_MS: u64 = 400;
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
    let sender = sender.into();
    let recipient = recipient.into();
    assert!(valid_address(&sender));
    assert!(valid_address(&recipient));
    Transaction {
        sender,
        recipient,
        amount,
        fee,
        signature: Vec::new(),
        encrypted_message: Vec::new(),
        inputs: Vec::new(),
        outputs: Vec::new(),
        contract_state: HashMap::new(),
    }
}

pub fn new_transaction(
    sender: impl Into<String>,
    recipient: impl Into<String>,
    amount: u64,
) -> Transaction {
    new_transaction_with_fee(sender, recipient, amount, 0)
}

pub fn new_multi_transaction_with_fee(
    sender: impl Into<String>,
    outputs: Vec<(String, u64)>,
    fee: u64,
) -> Transaction {
    let sender = sender.into();
    assert!(valid_address(&sender));
    let recipient = outputs.first().map(|o| o.0.clone()).unwrap_or_default();
    let amount = outputs.first().map(|o| o.1).unwrap_or(0);
    let extra: Vec<_> = outputs
        .into_iter()
        .skip(1)
        .map(|(addr, amt)| TransactionOutput {
            address: addr,
            amount: amt,
        })
        .collect();
    assert!(valid_address(&recipient));
    for out in &extra {
        assert!(valid_address(&out.address));
    }
    Transaction {
        sender,
        recipient,
        amount,
        fee,
        signature: Vec::new(),
        encrypted_message: Vec::new(),
        inputs: Vec::new(),
        outputs: extra,
        contract_state: HashMap::new(),
    }
}

/// Create a coinbase transaction paying `amount` to `miner`
pub fn coinbase_transaction(miner: impl Into<String>, amount: u64) -> Transaction {
    let miner = miner.into();
    assert!(valid_address(&miner));
    Transaction {
        sender: String::new(),
        recipient: miner,
        amount,
        fee: 0,
        signature: Vec::new(),
        encrypted_message: Vec::new(),
        inputs: Vec::new(),
        outputs: Vec::new(),
        contract_state: HashMap::new(),
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
    let sender = sender.into();
    let recipient = recipient.into();
    assert!(valid_address(&sender));
    assert!(valid_address(&recipient));
    Transaction {
        sender,
        recipient,
        amount,
        fee,
        signature: Vec::new(),
        encrypted_message: encrypt_message(message, sender_sk, recipient_pk),
        inputs: Vec::new(),
        outputs: Vec::new(),
        contract_state: HashMap::new(),
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

/// Derive an address from a secret key.
pub fn address_from_secret(sk: &secp256k1::SecretKey) -> String {
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
        for inp in &self.inputs {
            hasher.update(inp.address.as_bytes());
            hasher.update(inp.amount.to_be_bytes());
        }
        for out in &self.outputs {
            hasher.update(out.address.as_bytes());
            hasher.update(out.amount.to_be_bytes());
        }
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
    /// Hash the block header for block identification. The Merkle root in the
    /// header commits to all transactions, so the transactions themselves are
    /// not included here. This allows pruning without changing the block hash.
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

    /// Remove transactions from the block while preserving the header. This
    /// simulates pruning after enough confirmations.
    pub fn prune(&mut self) {
        self.transactions.clear();
    }
}

pub struct Blockchain {
    chain: Vec<Block>,
    mempool: Vec<Transaction>,
    difficulty: u32,
    runtime: contract_runtime::Runtime,
    utxos: HashMap<String, u64>,
    locked: HashMap<String, u64>,
}

impl Blockchain {
    pub fn new() -> Self {
        Self {
            chain: Vec::new(),
            mempool: Vec::new(),
            runtime: contract_runtime::Runtime::default(),
            difficulty: 1,
            utxos: HashMap::new(),
            locked: HashMap::new(),
        }
    }

    /// Add a transaction to the mempool if addresses are valid.
    /// Returns `true` if the transaction was accepted.
    pub fn add_transaction(&mut self, tx: Transaction) -> bool {
        if (!tx.sender.is_empty() && !valid_address(&tx.sender)) || !valid_address(&tx.recipient) {
            return false;
        }
        for out in &tx.outputs {
            if !valid_address(&out.address) {
                return false;
            }
        }
        if tx.amount == 0 && tx.outputs.iter().all(|o| o.amount == 0) {
            return false;
        }
        if !tx.sender.is_empty() {
            if !tx.verify() {
                return false;
            }
            if tx.inputs.is_empty() {
                let bal = self.available_utxo(&tx.sender);
                let total_out: u64 = tx.amount + tx.outputs.iter().map(|o| o.amount).sum::<u64>();
                if bal < (total_out + tx.fee) as i64 {
                    return false;
                }
            } else {
                let mut sum_inputs = 0u64;
                for inp in &tx.inputs {
                    if !valid_address(&inp.address) {
                        return false;
                    }
                    let bal = self.available_utxo(&inp.address);
                    if bal < inp.amount as i64 {
                        return false;
                    }
                    sum_inputs += inp.amount;
                }
                let total_out: u64 =
                    tx.amount + tx.outputs.iter().map(|o| o.amount).sum::<u64>() + tx.fee;
                if sum_inputs < total_out {
                    return false;
                }
            }
        }
        self.mempool.push(tx);
        true
    }

    /// Create a block from current mempool transactions without clearing them
    pub fn candidate_block(&self) -> Block {
        let previous_hash = self.last_block_hash().unwrap_or_default();
        let merkle_root = compute_merkle_root(&self.mempool);
        Block {
            header: BlockHeader {
                previous_hash,
                merkle_root,
                timestamp: SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap()
                    .as_millis() as u64,
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
    pub fn add_block(&mut self, mut block: Block) -> Block {
        for tx in &mut block.transactions {
            if let Some(pos) = self.mempool.iter().position(|m| m == tx) {
                self.mempool.remove(pos);
            }

            if tx.inputs.is_empty() {
                if !tx.sender.is_empty() {
                    let spend =
                        tx.amount + tx.outputs.iter().map(|o| o.amount).sum::<u64>() + tx.fee;
                    let entry = self.utxos.entry(tx.sender.clone()).or_insert(0);
                    *entry = entry.saturating_sub(spend);
                }
            } else {
                for inp in &tx.inputs {
                    let entry = self.utxos.entry(inp.address.clone()).or_insert(0);
                    *entry = entry.saturating_sub(inp.amount);
                }
            }

            let entry = self.utxos.entry(tx.recipient.clone()).or_insert(0);
            *entry += tx.amount;
            for out in &tx.outputs {
                let e = self.utxos.entry(out.address.clone()).or_insert(0);
                *e += out.amount;
            }

            if tx.recipient.is_empty() && !tx.encrypted_message.is_empty() {
                if let Ok(dep) =
                    serde_json::from_slice::<contract_runtime::DeployPayload>(&tx.encrypted_message)
                {
                    if tx.contract_state.is_empty() {
                        let state = self
                            .runtime
                            .deploy(&tx.sender, &dep.wasm)
                            .unwrap_or_default();
                        tx.contract_state = state;
                    } else {
                        self.runtime
                            .set_state(&tx.sender, tx.contract_state.clone());
                    }
                } else if let Ok(inv) =
                    serde_json::from_slice::<contract_runtime::InvokePayload>(&tx.encrypted_message)
                {
                    if tx.contract_state.is_empty() {
                        let mut gas = 1_000_000;
                        let (_res, state) = self
                            .runtime
                            .execute(&inv.contract, &mut gas)
                            .unwrap_or((0, HashMap::new()));
                        tx.contract_state = state;
                    } else {
                        self.runtime
                            .set_state(&inv.contract, tx.contract_state.clone());
                    }
                }
            }
        }
        block.header.merkle_root = compute_merkle_root(&block.transactions);
        self.chain.push(block.clone());

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
                if avg < TARGET_BLOCK_MS {
                    self.difficulty = self.difficulty.saturating_add(1);
                } else if avg > TARGET_BLOCK_MS {
                    self.difficulty = self.difficulty.saturating_sub(1);
                }
            }
        }
        block
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

    pub fn validate_chain(blocks: &[Block]) -> bool {
        let mut mined = 0u64;
        for (i, block) in blocks.iter().enumerate() {
            if i > 0 && block.header.previous_hash != blocks[i - 1].hash() {
                return false;
            }

            if !block.transactions.is_empty() {
                let mut fees = 0u64;
                let mut coinbase: Option<&Transaction> = None;
                for tx in &block.transactions {
                    if tx.sender.is_empty() {
                        if coinbase.is_some() {
                            return false;
                        }
                        if tx.fee != 0 || !tx.inputs.is_empty() {
                            return false;
                        }
                        coinbase = Some(tx);
                    } else {
                        if !tx.verify() {
                            return false;
                        }
                        fees += tx.fee;
                    }
                }
                let reward = Blockchain::subsidy_for_height(i as u64, mined);
                let expected = reward + fees;
                let cb = match coinbase {
                    Some(c) => c,
                    None => return false,
                };
                if cb.amount != expected {
                    return false;
                }
                mined = mined.saturating_add(reward);

                let merkle = compute_merkle_root(&block.transactions);
                if merkle != block.header.merkle_root {
                    return false;
                }
            }

            if let Ok(hash) = hex::decode(block.hash()) {
                if !meets_difficulty(&hash, block.header.difficulty) {
                    return false;
                }
            } else {
                return false;
            }
        }
        true
    }

    /// Calculate the cumulative difficulty for a slice of blocks.
    pub fn total_difficulty_of(blocks: &[Block]) -> u64 {
        blocks.iter().map(|b| b.header.difficulty as u64).sum()
    }

    /// Total difficulty of the current chain.
    pub fn total_difficulty(&self) -> u64 {
        Self::total_difficulty_of(&self.chain)
    }

    pub fn replace(&mut self, new_chain: Vec<Block>) {
        let new_diff = Self::total_difficulty_of(&new_chain);
        let cur_diff = self.total_difficulty();
        if new_diff > cur_diff || (new_diff == cur_diff && new_chain.len() > self.chain.len()) {
            self.chain = new_chain;
        }
    }

    pub fn all(&self) -> Vec<Block> {
        self.chain.clone()
    }

    pub fn save<P: AsRef<Path>>(&self, dir: P) -> std::io::Result<()> {
        use std::fs;

        let dir = dir.as_ref();
        fs::create_dir_all(dir)?;
        // remove existing block files to avoid duplication
        if dir.exists() {
            for entry in fs::read_dir(dir)? {
                let entry = entry?;
                if let Some(name) = entry.file_name().to_str() {
                    if name.starts_with("blk") && name.ends_with(".dat") {
                        let _ = fs::remove_file(entry.path());
                    }
                }
            }
        }
        for block in &self.chain {
            blockfile::append_block(dir, block)?;
        }
        utxofile::save_utxos(dir.join("utxos.bin"), &self.utxos)?;
        Ok(())
    }

    pub fn save_mempool<P: AsRef<Path>>(&self, path: P) -> std::io::Result<()> {
        let data = serde_json::to_vec(&self.mempool).unwrap();
        let mut f = File::create(path)?;
        f.write_all(&data)
    }

    pub fn load<P: AsRef<Path>>(dir: P) -> std::io::Result<Self> {
        let dir = dir.as_ref();
        let blocks = blockfile::read_blocks(dir)?;
        if !Self::validate_chain(&blocks) {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "invalid chain",
            ));
        }
        let saved_utxos = utxofile::load_utxos(dir.join("utxos.bin")).ok();
        let mut bc = Blockchain::new();
        for block in &blocks {
            let _ = bc.add_block(block.clone());
        }
        if let Some(map) = saved_utxos {
            bc.utxos = map;
        }
        Ok(bc)
    }

    pub fn load_mempool<P: AsRef<Path>>(&mut self, path: P) -> std::io::Result<()> {
        let f = File::open(path)?;
        let mempool: Vec<Transaction> = serde_json::from_reader(f)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
        self.mempool = mempool;
        Ok(())
    }

    /// Calculate the balance for `addr` by scanning the chain
    pub fn balance(&self, addr: &str) -> i64 {
        let total = *self.utxos.get(addr).unwrap_or(&0) as i64;
        let locked = *self.locked.get(addr).unwrap_or(&0) as i64;
        total - locked
    }

    fn available_utxo(&self, addr: &str) -> i64 {
        let mut bal = self.balance(addr);
        for m in &self.mempool {
            if m.inputs.is_empty() {
                if m.sender == addr && !m.sender.is_empty() {
                    let extra: u64 = m.outputs.iter().map(|o| o.amount).sum();
                    bal -= (m.amount + extra + m.fee) as i64;
                }
            } else {
                for inp in &m.inputs {
                    if inp.address == addr {
                        bal -= inp.amount as i64;
                    }
                }
            }
        }
        bal
    }

    pub fn lock_stake(&mut self, addr: &str, amount: u64) -> bool {
        let bal = self.balance(addr);
        if bal < amount as i64 {
            return false;
        }
        let entry = self.locked.entry(addr.to_string()).or_default();
        *entry += amount;
        true
    }

    pub fn unlock_stake(&mut self, addr: &str, amount: u64) -> bool {
        if let Some(entry) = self.locked.get_mut(addr) {
            if *entry >= amount {
                *entry -= amount;
                if *entry == 0 {
                    self.locked.remove(addr);
                }
                return true;
            }
        }
        false
    }

    pub fn mempool_len(&self) -> usize {
        self.mempool.len()
    }

    pub fn locked_balance(&self, addr: &str) -> u64 {
        *self.locked.get(addr).unwrap_or(&0)
    }

    /// Prune transactions from blocks older than `depth` from the tip.
    pub fn prune(&mut self, depth: usize) {
        let len = self.chain.len();
        if len <= depth {
            return;
        }
        for block in &mut self.chain[..len - depth] {
            block.prune();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;
    use std::collections::HashMap;

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
        let sk1 = secp256k1::SecretKey::from_slice(&[1u8; 32]).unwrap();
        let sk2 = secp256k1::SecretKey::from_slice(&[2u8; 32]).unwrap();
        let addr1 = address_from_secret(&sk1);
        let addr2 = address_from_secret(&sk2);
        // fund both accounts
        let _ = bc.add_block(Block {
            header: BlockHeader {
                previous_hash: String::new(),
                merkle_root: String::new(),
                timestamp: 0,
                nonce: 0,
                difficulty: 0,
            },
            transactions: vec![
                coinbase_transaction(&addr1, bc.block_subsidy()),
                coinbase_transaction(&addr2, bc.block_subsidy()),
            ],
        });
        let mut tx1 = new_transaction(&addr1, &addr2, 5);
        tx1.sign(&sk1);
        let mut tx2 = new_transaction(&addr2, &addr1, 7);
        tx2.sign(&sk2);
        assert!(bc.add_transaction(tx1.clone()));
        assert!(bc.add_transaction(tx2.clone()));
        // Candidate block should contain both transactions
        let block = bc.candidate_block();
        assert_eq!(block.transactions.len(), 2);
        let _ = bc.add_block(block.clone());
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
            let _ = bc.add_block(block);
        }
        let diff_after_fast = bc.difficulty();
        assert!(diff_after_fast > 1);

        // mine blocks too slowly
        let start = DIFFICULTY_WINDOW as u64 * TARGET_BLOCK_MS * 2;
        for i in 0..DIFFICULTY_WINDOW {
            let block = Block {
                header: BlockHeader {
                    previous_hash: bc.last_block_hash().unwrap_or_default(),
                    merkle_root: String::new(),
                    timestamp: start + (i as u64 * TARGET_BLOCK_MS * 2),
                    nonce: 0,
                    difficulty: bc.difficulty(),
                },
                transactions: vec![],
            };
            let _ = bc.add_block(block);
        }
        let diff_after_slow = bc.difficulty();
        assert!(diff_after_slow < diff_after_fast);
        assert!(diff_after_slow <= diff_after_fast);
    }

    #[test]
    fn balance_reflects_coinbase() {
        let mut bc = Blockchain::new();
        assert_eq!(bc.balance(A1), 0);
        let tx = coinbase_transaction(A1, bc.block_subsidy());
        let block = Block {
            header: BlockHeader {
                previous_hash: String::new(),
                merkle_root: compute_merkle_root(&[tx.clone()]),
                timestamp: 0,
                nonce: 0,
                difficulty: 0,
            },
            transactions: vec![tx],
        };
        let _ = bc.add_block(block);
        assert_eq!(bc.balance(A1), bc.block_subsidy() as i64);
    }

    #[test]
    fn reject_invalid_transaction() {
        let mut bc = Blockchain::new();
        let tx = Transaction {
            sender: "badaddr".into(),
            recipient: A2.into(),
            amount: 1,
            fee: 0,
            signature: Vec::new(),
            encrypted_message: Vec::new(),
            inputs: Vec::new(),
            outputs: Vec::new(),
            contract_state: HashMap::new(),
        };
        assert!(!bc.add_transaction(tx));
        assert_eq!(bc.mempool_len(), 0);
    }

    #[test]
    #[should_panic]
    fn new_transaction_invalid_sender_panics() {
        let _ = new_transaction("badaddr", A2, 1);
    }

    #[test]
    fn reject_zero_amount_transaction() {
        let mut bc = Blockchain::new();
        let sk = secp256k1::SecretKey::from_slice(&[1u8; 32]).unwrap();
        let addr = address_from_secret(&sk);
        let mut tx = new_transaction(&addr, A2, 0);
        tx.sign(&sk);
        assert!(!bc.add_transaction(tx));
    }

    #[test]
    fn reject_insufficient_balance() {
        let mut bc = Blockchain::new();
        let sk = secp256k1::SecretKey::from_slice(&[1u8; 32]).unwrap();
        let addr = address_from_secret(&sk);
        // give sender some coins
        let _ = bc.add_block(Block {
            header: BlockHeader {
                previous_hash: String::new(),
                merkle_root: String::new(),
                timestamp: 0,
                nonce: 0,
                difficulty: 0,
            },
            transactions: vec![coinbase_transaction(&addr, bc.block_subsidy())],
        });
        let mut tx = new_transaction(&addr, A2, bc.block_subsidy() + 1);
        tx.sign(&sk);
        assert!(!bc.add_transaction(tx));
    }

    #[test]
    fn fee_deducts_from_balance() {
        let mut bc = Blockchain::new();
        let sk1 = secp256k1::SecretKey::from_slice(&[1u8; 32]).unwrap();
        let addr1 = address_from_secret(&sk1);
        let sk2 = secp256k1::SecretKey::from_slice(&[2u8; 32]).unwrap();
        let addr2 = address_from_secret(&sk2);
        let _ = bc.add_block(Block {
            header: BlockHeader {
                previous_hash: String::new(),
                merkle_root: compute_merkle_root(&[coinbase_transaction(
                    &addr1,
                    bc.block_subsidy(),
                )]),
                timestamp: 0,
                nonce: 0,
                difficulty: 0,
            },
            transactions: vec![coinbase_transaction(&addr1, bc.block_subsidy())],
        });
        let mut tx = new_transaction_with_fee(&addr1, &addr2, 5, 2);
        tx.sign(&sk1);
        assert!(bc.add_transaction(tx.clone()));
        let block = bc.candidate_block();
        let _ = bc.add_block(block);
        assert_eq!(bc.balance(&addr1), bc.block_subsidy() as i64 - 7);
        assert_eq!(bc.balance(&addr2), 5);
    }

    #[test]
    fn save_and_load_chain() {
        let mut bc = Blockchain::new();
        let tx = coinbase_transaction(A1, bc.block_subsidy());
        let block = Block {
            header: BlockHeader {
                previous_hash: String::new(),
                merkle_root: compute_merkle_root(&[tx.clone()]),
                timestamp: 0,
                nonce: 0,
                difficulty: 0,
            },
            transactions: vec![tx],
        };
        let _ = bc.add_block(block);
        let dir = tempfile::tempdir().unwrap();
        bc.save(dir.path()).unwrap();
        let loaded = Blockchain::load(dir.path()).unwrap();
        assert_eq!(loaded.len(), bc.len());
        assert_eq!(loaded.last_block_hash(), bc.last_block_hash());
    }

    #[test]
    fn save_creates_block_files() {
        let mut bc = Blockchain::new();
        for i in 0..2 {
            let tx = coinbase_transaction(A1, bc.block_subsidy());
            let _ = bc.add_block(Block {
                header: BlockHeader {
                    previous_hash: bc.last_block_hash().unwrap_or_default(),
                    merkle_root: compute_merkle_root(&[tx.clone()]),
                    timestamp: i,
                    nonce: 0,
                    difficulty: 0,
                },
                transactions: vec![tx],
            });
        }
        let dir = tempfile::tempdir().unwrap();
        bc.save(dir.path()).unwrap();
        assert!(dir.path().join("blk00000.dat").exists());
        assert!(dir.path().join("blk00001.dat").exists());
        let loaded = Blockchain::load(dir.path()).unwrap();
        assert_eq!(loaded.all(), bc.all());
    }

    #[test]
    fn save_removes_existing_block_files() {
        let mut bc = Blockchain::new();
        for _ in 0..2 {
            let tx = coinbase_transaction(A1, bc.block_subsidy());
            bc.add_block(Block {
                header: BlockHeader {
                    previous_hash: bc.last_block_hash().unwrap_or_default(),
                    merkle_root: compute_merkle_root(&[tx.clone()]),
                    timestamp: 0,
                    nonce: 0,
                    difficulty: 0,
                },
                transactions: vec![tx],
            });
        }
        let dir = tempfile::tempdir().unwrap();
        bc.save(dir.path()).unwrap();
        std::fs::write(dir.path().join("blk99999.dat"), b"junk").unwrap();
        bc.save(dir.path()).unwrap();
        let count = std::fs::read_dir(dir.path())
            .unwrap()
            .filter(|e| {
                e.as_ref()
                    .unwrap()
                    .file_name()
                    .to_str()
                    .unwrap()
                    .starts_with("blk")
            })
            .count();
        assert_eq!(count, 2);
    }

    #[test]
    fn load_rejects_invalid_chain() {
        let dir = tempfile::tempdir().unwrap();
        let block = Block {
            header: BlockHeader {
                previous_hash: String::new(),
                merkle_root: String::new(),
                timestamp: 0,
                nonce: 0,
                difficulty: 0,
            },
            transactions: vec![Transaction {
                sender: A1.into(),
                recipient: A2.into(),
                amount: 1,
                fee: 0,
                signature: Vec::new(),
                encrypted_message: Vec::new(),
                inputs: vec![],
                outputs: vec![],
                contract_state: HashMap::new(),
            }],
        };
        blockfile::append_block(dir.path(), &block).unwrap();
        let res = Blockchain::load(dir.path());
        assert!(res.is_err());
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
    fn address_from_secret_known_value() {
        let sk = secp256k1::SecretKey::from_slice(&[1u8; 32]).unwrap();
        let addr = address_from_secret(&sk);
        assert_eq!(addr, "1C6Rc3w25VHud3dLDamutaqfKWqhrLRTaD");
        assert!(valid_address(&addr));
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
    fn add_transaction_rejects_unsigned() {
        let mut bc = Blockchain::new();
        let sk = secp256k1::SecretKey::from_slice(&[1u8; 32]).unwrap();
        let addr = address_from_secret(&sk);
        bc.add_block(Block {
            header: BlockHeader {
                previous_hash: String::new(),
                merkle_root: String::new(),
                timestamp: 0,
                nonce: 0,
                difficulty: 0,
            },
            transactions: vec![coinbase_transaction(&addr, bc.block_subsidy())],
        });
        let tx = new_transaction(&addr, A2, 1);
        assert!(!bc.add_transaction(tx));
    }

    #[test]
    fn add_transaction_rejects_malformed_signature() {
        let mut bc = Blockchain::new();
        let sk = secp256k1::SecretKey::from_slice(&[1u8; 32]).unwrap();
        let addr = address_from_secret(&sk);
        bc.add_block(Block {
            header: BlockHeader {
                previous_hash: String::new(),
                merkle_root: String::new(),
                timestamp: 0,
                nonce: 0,
                difficulty: 0,
            },
            transactions: vec![coinbase_transaction(&addr, bc.block_subsidy())],
        });
        let mut tx = new_transaction(&addr, A2, 1);
        tx.signature = vec![0u8; 10];
        assert!(!bc.add_transaction(tx));
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

    #[test]
    #[should_panic]
    fn new_transaction_with_message_invalid_recipient() {
        let secp = secp256k1::Secp256k1::new();
        let sk_sender = secp256k1::SecretKey::from_slice(&[1u8; 32]).unwrap();
        let pk_recipient = secp256k1::PublicKey::from_secret_key(
            &secp,
            &secp256k1::SecretKey::from_slice(&[2u8; 32]).unwrap(),
        );
        let _ =
            new_transaction_with_message(A1, "badaddr", 5, 0, "secret", &sk_sender, &pk_recipient);
    }

    #[test]
    fn mempool_save_load_roundtrip() {
        let mut bc = Blockchain::new();
        bc.add_transaction(coinbase_transaction(A1, 5));
        bc.add_transaction(coinbase_transaction(A2, 7));
        let tmp = tempfile::NamedTempFile::new().unwrap();
        bc.save_mempool(tmp.path()).unwrap();

        let mut bc2 = Blockchain::new();
        bc2.load_mempool(tmp.path()).unwrap();
        assert_eq!(bc.mempool, bc2.mempool);
    }

    #[test]
    fn merkle_root_tree() {
        let tx1 = coinbase_transaction(A1, 1);
        let tx2 = coinbase_transaction(A2, 1);
        let manual = {
            let mut hasher = Sha256::new();
            hasher.update(hex::decode(tx1.hash()).unwrap());
            hasher.update(hex::decode(tx2.hash()).unwrap());
            hex::encode(hasher.finalize())
        };
        let calc = compute_merkle_root(&[tx1, tx2]);
        assert_eq!(manual, calc);
    }

    #[test]
    fn merkle_root_empty_slice() {
        let root = merkle_root_from_hashes(&[]);
        assert_eq!(root, hex::encode(Sha256::digest(&[])));
    }

    #[test]
    fn compute_merkle_single_tx() {
        let tx = coinbase_transaction(A1, 1);
        let root = compute_merkle_root(&[tx.clone()]);
        assert_eq!(root, tx.hash());
    }

    #[test]
    fn prune_preserves_hash() {
        let bc = Blockchain::new();
        let tx = coinbase_transaction(A1, bc.block_subsidy());
        let merkle = compute_merkle_root(&[tx.clone()]);
        let block = Block {
            header: BlockHeader {
                previous_hash: String::new(),
                merkle_root: merkle,
                timestamp: 0,
                nonce: 0,
                difficulty: 0,
            },
            transactions: vec![tx],
        };
        let hash_before = block.hash();
        let mut block_pruned = block.clone();
        block_pruned.prune();
        assert_eq!(hash_before, block_pruned.hash());
        assert!(Blockchain::validate_chain(&[block.clone()]));
        assert!(Blockchain::validate_chain(&[block_pruned.clone()]));
    }

    #[test]
    fn total_difficulty_and_replace() {
        let mut bc = Blockchain::new();
        bc.add_block(Block {
            header: BlockHeader {
                previous_hash: String::new(),
                merkle_root: String::new(),
                timestamp: 0,
                nonce: 0,
                difficulty: 1,
            },
            transactions: vec![],
        });

        assert_eq!(bc.total_difficulty(), 1);

        let weaker = vec![Block {
            header: BlockHeader {
                previous_hash: String::new(),
                merkle_root: String::new(),
                timestamp: 0,
                nonce: 0,
                difficulty: 0,
            },
            transactions: vec![],
        }];
        bc.replace(weaker.clone());
        assert_eq!(bc.len(), 1);
        assert_eq!(bc.total_difficulty(), 1);

        let stronger = vec![Block {
            header: BlockHeader {
                previous_hash: String::new(),
                merkle_root: String::new(),
                timestamp: 0,
                nonce: 0,
                difficulty: 2,
            },
            transactions: vec![],
        }];
        bc.replace(stronger.clone());
        assert_eq!(bc.total_difficulty(), 2);

        let tie_longer = vec![
            Block {
                header: BlockHeader {
                    previous_hash: String::new(),
                    merkle_root: String::new(),
                    timestamp: 0,
                    nonce: 0,
                    difficulty: 2,
                },
                transactions: vec![],
            },
            Block {
                header: BlockHeader {
                    previous_hash: String::new(),
                    merkle_root: String::new(),
                    timestamp: 1,
                    nonce: 0,
                    difficulty: 0,
                },
                transactions: vec![],
            },
        ];
        bc.replace(tie_longer);
        assert_eq!(bc.len(), 2);
    }

    #[test]
    fn available_utxo_considers_mempool() {
        let mut bc = Blockchain::new();
        let sk1 = secp256k1::SecretKey::from_slice(&[1u8; 32]).unwrap();
        let sk2 = secp256k1::SecretKey::from_slice(&[2u8; 32]).unwrap();
        let addr1 = address_from_secret(&sk1);
        let addr2 = address_from_secret(&sk2);
        let coinbase = coinbase_transaction(&addr1, bc.block_subsidy());
        bc.add_block(Block {
            header: BlockHeader {
                previous_hash: String::new(),
                merkle_root: compute_merkle_root(&[coinbase.clone()]),
                timestamp: 0,
                nonce: 0,
                difficulty: 0,
            },
            transactions: vec![coinbase.clone()],
        });
        assert_eq!(bc.balance(&addr1), bc.block_subsidy() as i64);
        let mut tx = new_transaction_with_fee(&addr1, &addr2, 5, 1);
        tx.sign(&sk1);
        assert!(bc.add_transaction(tx));
        assert_eq!(bc.available_utxo(&addr1), bc.block_subsidy() as i64 - 6);
        assert_eq!(bc.balance(&addr1), bc.block_subsidy() as i64);
        let block = bc.candidate_block();
        let _ = bc.add_block(block);
        assert_eq!(bc.balance(&addr1), bc.block_subsidy() as i64 - 6);
    }

    #[test]
    fn load_rebuilds_utxos() {
        let mut bc = Blockchain::new();
        let sk1 = secp256k1::SecretKey::from_slice(&[1u8; 32]).unwrap();
        let sk2 = secp256k1::SecretKey::from_slice(&[2u8; 32]).unwrap();
        let addr1 = address_from_secret(&sk1);
        let addr2 = address_from_secret(&sk2);
        let cb = coinbase_transaction(&addr1, bc.block_subsidy());
        bc.add_block(Block {
            header: BlockHeader {
                previous_hash: String::new(),
                merkle_root: compute_merkle_root(&[cb.clone()]),
                timestamp: 0,
                nonce: 0,
                difficulty: 0,
            },
            transactions: vec![cb.clone()],
        });
        let mut tx = new_transaction(&addr1, &addr2, 10);
        tx.sign(&sk1);
        let cb2 = coinbase_transaction(&addr2, bc.block_subsidy());
        bc.add_block(Block {
            header: BlockHeader {
                previous_hash: bc.last_block_hash().unwrap(),
                merkle_root: compute_merkle_root(&[cb2.clone(), tx.clone()]),
                timestamp: 1,
                nonce: 0,
                difficulty: 0,
            },
            transactions: vec![cb2, tx],
        });
        let dir = tempfile::tempdir().unwrap();
        bc.save(dir.path()).unwrap();
        std::fs::remove_file(dir.path().join("utxos.bin")).unwrap();
        let loaded = Blockchain::load(dir.path()).unwrap();
        assert_eq!(loaded.balance(&addr1), bc.balance(&addr1));
        assert_eq!(loaded.balance(&addr2), bc.balance(&addr2));
    }

    #[test]
    fn save_writes_utxo_file() {
        let mut bc = Blockchain::new();
        let tx = coinbase_transaction(A1, bc.block_subsidy());
        bc.add_block(Block {
            header: BlockHeader {
                previous_hash: String::new(),
                merkle_root: compute_merkle_root(&[tx.clone()]),
                timestamp: 0,
                nonce: 0,
                difficulty: 0,
            },
            transactions: vec![tx.clone()],
        });
        let dir = tempfile::tempdir().unwrap();
        bc.save(dir.path()).unwrap();
        let path = dir.path().join("utxos.bin");
        assert!(path.exists());
        let stored = utxofile::load_utxos(&path).unwrap();
        assert_eq!(stored, bc.utxos);
    }

    #[test]
    fn load_uses_saved_utxos() {
        let mut bc = Blockchain::new();
        let tx = coinbase_transaction(A1, bc.block_subsidy());
        bc.add_block(Block {
            header: BlockHeader {
                previous_hash: String::new(),
                merkle_root: compute_merkle_root(&[tx.clone()]),
                timestamp: 0,
                nonce: 0,
                difficulty: 0,
            },
            transactions: vec![tx.clone()],
        });
        let dir = tempfile::tempdir().unwrap();
        bc.save(dir.path()).unwrap();
        let mut map = HashMap::new();
        map.insert(A1.to_string(), 123);
        utxofile::save_utxos(dir.path().join("utxos.bin"), &map).unwrap();
        let loaded = Blockchain::load(dir.path()).unwrap();
        assert_eq!(loaded.balance(A1), 123);
    }

    #[test]
    fn multi_output_transaction_construction() {
        let sk = secp256k1::SecretKey::from_slice(&[1u8; 32]).unwrap();
        let sender = address_from_secret(&sk);
        let tx = new_multi_transaction_with_fee(
            &sender,
            vec![(A1.to_string(), 2), (A2.to_string(), 3)],
            1,
        );
        assert_eq!(tx.recipient, A1);
        assert_eq!(tx.amount, 2);
        assert_eq!(tx.outputs.len(), 1);
        assert_eq!(tx.outputs[0].address, A2);
        assert_eq!(tx.outputs[0].amount, 3);
        assert_eq!(tx.fee, 1);
    }

    #[test]
    fn prune_removes_old_transactions() {
        let mut bc = Blockchain::new();
        for i in 0..3 {
            let tx = coinbase_transaction(A1, bc.block_subsidy());
            bc.add_block(Block {
                header: BlockHeader {
                    previous_hash: bc.last_block_hash().unwrap_or_default(),
                    merkle_root: compute_merkle_root(&[tx.clone()]),
                    timestamp: i as u64,
                    nonce: 0,
                    difficulty: 0,
                },
                transactions: vec![tx],
            });
        }
        bc.prune(1);
        assert!(bc.chain[0].transactions.is_empty());
        assert!(bc.chain[1].transactions.is_empty());
        assert!(!bc.chain[2].transactions.is_empty());
    }

    #[test]
    fn prune_reduces_disk_usage() {
        let mut bc = Blockchain::new();
        for i in 0..3 {
            let tx = coinbase_transaction(A1, bc.block_subsidy());
            bc.add_block(Block {
                header: BlockHeader {
                    previous_hash: bc.last_block_hash().unwrap_or_default(),
                    merkle_root: compute_merkle_root(&[tx.clone()]),
                    timestamp: i as u64,
                    nonce: 0,
                    difficulty: 0,
                },
                transactions: vec![tx],
            });
        }
        let dir_before = tempfile::tempdir().unwrap();
        bc.save(dir_before.path()).unwrap();
        let size_before: u64 = std::fs::read_dir(dir_before.path())
            .unwrap()
            .filter_map(|e| e.ok())
            .map(|e| std::fs::metadata(e.path()).unwrap().len())
            .sum();
        bc.prune(1);
        let dir_after = tempfile::tempdir().unwrap();
        bc.save(dir_after.path()).unwrap();
        let size_after: u64 = std::fs::read_dir(dir_after.path())
            .unwrap()
            .filter_map(|e| e.ok())
            .map(|e| std::fs::metadata(e.path()).unwrap().len())
            .sum();
        assert!(size_after < size_before);
    }

    #[test]
    fn validate_chain_accepts_correct_rewards() {
        let sk1 = secp256k1::SecretKey::from_slice(&[1u8; 32]).unwrap();
        let sk2 = secp256k1::SecretKey::from_slice(&[2u8; 32]).unwrap();
        let addr1 = address_from_secret(&sk1);
        let addr2 = address_from_secret(&sk2);
        let mut tx = new_transaction_with_fee(&addr1, &addr2, 5, 1);
        tx.sign(&sk1);
        let reward = Blockchain::subsidy_for_height(0, 0);
        let cb = coinbase_transaction(&addr1, reward + tx.fee);
        let merkle = compute_merkle_root(&[cb.clone(), tx.clone()]);
        let block = Block {
            header: BlockHeader {
                previous_hash: String::new(),
                merkle_root: merkle,
                timestamp: 0,
                nonce: 0,
                difficulty: 0,
            },
            transactions: vec![cb, tx],
        };
        assert!(Blockchain::validate_chain(&[block]));
    }

    #[test]
    fn validate_chain_rejects_bad_reward() {
        let sk1 = secp256k1::SecretKey::from_slice(&[1u8; 32]).unwrap();
        let sk2 = secp256k1::SecretKey::from_slice(&[2u8; 32]).unwrap();
        let addr1 = address_from_secret(&sk1);
        let addr2 = address_from_secret(&sk2);
        let mut tx = new_transaction_with_fee(&addr1, &addr2, 5, 1);
        tx.sign(&sk1);
        let reward = Blockchain::subsidy_for_height(0, 0);
        let cb = coinbase_transaction(&addr1, reward + tx.fee + 1);
        let merkle = compute_merkle_root(&[cb.clone(), tx.clone()]);
        let block = Block {
            header: BlockHeader {
                previous_hash: String::new(),
                merkle_root: merkle,
                timestamp: 0,
                nonce: 0,
                difficulty: 0,
            },
            transactions: vec![cb, tx],
        };
        assert!(!Blockchain::validate_chain(&[block]));
    }

    #[test]
    fn add_block_consumes_inputs() {
        let mut bc = Blockchain::new();
        let sk1 = secp256k1::SecretKey::from_slice(&[1u8; 32]).unwrap();
        let sk2 = secp256k1::SecretKey::from_slice(&[2u8; 32]).unwrap();
        let addr1 = address_from_secret(&sk1);
        let addr2 = address_from_secret(&sk2);
        let cb = coinbase_transaction(&addr1, bc.block_subsidy());
        bc.add_block(Block {
            header: BlockHeader {
                previous_hash: String::new(),
                merkle_root: compute_merkle_root(&[cb.clone()]),
                timestamp: 0,
                nonce: 0,
                difficulty: 0,
            },
            transactions: vec![cb.clone()],
        });
        let mut tx = new_transaction(&addr1, &addr2, 10);
        tx.inputs.push(TransactionInput {
            address: addr1.clone(),
            amount: 10,
        });
        tx.sign(&sk1);
        assert!(bc.add_transaction(tx.clone()));
        let block = bc.candidate_block();
        let _ = bc.add_block(block);
        assert_eq!(bc.balance(&addr1), bc.block_subsidy() as i64 - 10);
        assert_eq!(bc.balance(&addr2), 10);
    }

    // Strategy to generate random valid addresses using secret keys
    fn arb_address() -> impl Strategy<Value = String> {
        any::<[u8; 32]>()
            .prop_filter_map("valid key", |b| secp256k1::SecretKey::from_slice(&b).ok())
            .prop_map(|sk| address_from_secret(&sk))
            .prop_filter("length", |addr| addr.len() == 34)
    }

    proptest::proptest! {
        #[test]
        fn prop_valid_chains(addrs in proptest::collection::vec(arb_address(), 1..5)) {
            let mut prev_hash = String::new();
            let mut timestamp = 0u64;
            let mut chain = Vec::new();
            let mut mined = 0u64;
            for (i, addr) in addrs.into_iter().enumerate() {
                timestamp += 1;
                let reward = Blockchain::subsidy_for_height(i as u64, mined);
                mined += reward;
                let tx = coinbase_transaction(&addr, reward);
                let merkle = compute_merkle_root(&[tx.clone()]);
                let block = Block {
                    header: BlockHeader {
                        previous_hash: prev_hash.clone(),
                        merkle_root: merkle,
                        timestamp,
                        nonce: 0,
                        difficulty: 0,
                    },
                    transactions: vec![tx],
                };
                prev_hash = block.hash();
                chain.push(block);
            }
            proptest::prop_assert!(Blockchain::validate_chain(&chain));
        }

        #[test]
        fn prop_invalid_chains(addrs in proptest::collection::vec(arb_address(), 2..5)) {
            let mut prev_hash = String::new();
            let mut timestamp = 0u64;
            let mut chain = Vec::new();
            let mut mined = 0u64;
            for (i, addr) in addrs.into_iter().enumerate() {
                timestamp += 1;
                let reward = Blockchain::subsidy_for_height(i as u64, mined);
                mined += reward;
                let tx = coinbase_transaction(&addr, reward);
                let merkle = compute_merkle_root(&[tx.clone()]);
                let block = Block {
                    header: BlockHeader {
                        previous_hash: prev_hash.clone(),
                        merkle_root: merkle,
                        timestamp,
                        nonce: 0,
                        difficulty: 0,
                    },
                    transactions: vec![tx],
                };
                prev_hash = block.hash();
                chain.push(block);
            }
            // Corrupt the last block
            if let Some(last) = chain.last_mut() {
                last.header.merkle_root.push('0');
            }
            proptest::prop_assert!(!Blockchain::validate_chain(&chain));
        }
    }
}
