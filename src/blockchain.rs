use crate::compute_merkle_root;
use crate::transaction::{TransactionExt, valid_address};
use crate::{Block, BlockHeader, Transaction, blockfile, utxofile};
use contract_runtime;
use serde_json;
use std::collections::HashMap;
use std::fs::File;
use std::io::Write;
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};
pub const DIFFICULTY_WINDOW: usize = 3;
pub const TARGET_BLOCK_MS: u64 = 400;
pub const COIN: u64 = 100_000_000;
pub const BLOCK_SUBSIDY: u64 = 50 * COIN;
pub const HALVING_INTERVAL: u64 = 200_000;
pub const MAX_SUPPLY: u64 = 20_000_000 * COIN;

pub struct Blockchain {
    pub(crate) chain: Vec<Block>,
    pub(crate) mempool: Vec<Transaction>,
    difficulty: u32,
    runtime: contract_runtime::Runtime,
    pub(crate) utxos: HashMap<String, u64>,
    pub(crate) locked: HashMap<String, u64>,
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

    pub fn candidate_block(&self) -> Block {
        let previous_hash = self.last_block_hash().unwrap_or_default();
        let merkle_root = compute_merkle_root(&self.mempool);
        Block {
            header: BlockHeader {
                previous_hash,
                merkle_root,
                timestamp: SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap_or_else(|_| std::time::Duration::new(0, 0))
                    .as_millis() as u64,
                nonce: 0,
                difficulty: self.difficulty,
            },
            transactions: self.mempool.clone(),
        }
    }

    pub fn total_mined(&self) -> u64 {
        self.chain
            .iter()
            .flat_map(|b| &b.transactions)
            .filter(|tx| tx.sender.is_empty())
            .map(|tx| tx.amount)
            .sum()
    }

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

    pub fn block_subsidy(&self) -> u64 {
        Self::subsidy_for_height(self.chain.len() as u64, self.total_mined())
    }

    pub fn add_block(&mut self, block: Block) {
        for tx in &block.transactions {
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
                    let _ = self.runtime.deploy(&tx.sender, &dep.wasm);
                } else if let Ok(inv) =
                    serde_json::from_slice::<contract_runtime::InvokePayload>(&tx.encrypted_message)
                {
                    let mut gas = 1_000_000;
                    let _ = self.runtime.execute(&inv.contract, &mut gas);
                }
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
                if avg < TARGET_BLOCK_MS {
                    self.difficulty = self.difficulty.saturating_add(1);
                } else if avg > TARGET_BLOCK_MS {
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
                if !crate::utils::meets_difficulty(&hash, block.header.difficulty) {
                    return false;
                }
            } else {
                return false;
            }
        }
        true
    }

    pub fn total_difficulty_of(blocks: &[Block]) -> u64 {
        blocks.iter().map(|b| b.header.difficulty as u64).sum()
    }

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
        use rocksdb::Options;
        use std::fs;

        let dir = dir.as_ref();
        fs::create_dir_all(dir)?;
        if blockfile::db_exists(dir) {
            let _ = rocksdb::DB::destroy(&Options::default(), dir);
        }
        for entry in fs::read_dir(dir)? {
            let entry = entry?;
            if let Some(name) = entry.file_name().to_str() {
                if name.starts_with("blk") && name.ends_with(".dat") {
                    let _ = fs::remove_file(entry.path());
                } else if name != "." && name != ".." {
                    let _ = fs::remove_file(entry.path());
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
        let data = serde_json::to_vec(&self.mempool)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;
        let mut f = File::create(path)?;
        f.write_all(&data)
    }

    pub fn load<P: AsRef<Path>>(dir: P) -> std::io::Result<Self> {
        let dir = dir.as_ref();
        let blocks = if blockfile::db_exists(dir) {
            blockfile::read_blocks(dir)?
        } else {
            blockfile::migrate_from_files(dir)?
        };
        if !Self::validate_chain(&blocks) {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "invalid chain",
            ));
        }
        let saved_utxos = if blockfile::db_exists(dir) {
            utxofile::load_utxos(dir.join("utxos.bin")).ok()
        } else {
            let map = utxofile::load_utxos(dir.join("utxos.bin")).ok();
            if let Some(ref m) = map {
                let _ = utxofile::save_utxos(dir.join("utxos.bin"), m);
            }
            map
        };
        let mut bc = Blockchain::new();
        for block in &blocks {
            bc.add_block(block.clone());
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

    pub fn balance(&self, addr: &str) -> i64 {
        let total = *self.utxos.get(addr).unwrap_or(&0) as i64;
        let locked = *self.locked.get(addr).unwrap_or(&0) as i64;
        total - locked
    }

    pub(crate) fn available_utxo(&self, addr: &str) -> i64 {
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
