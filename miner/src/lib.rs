use coin::meets_difficulty;
use coin::new_transaction_with_fee;
use coin::{
    Block, BlockHeader, Blockchain, TransactionExt, coinbase_transaction, compute_merkle_root,
};
use sha2::{Digest, Sha256};
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};
use std::thread;

fn hash_bytes(block: &Block) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(block.header.previous_hash.as_bytes());
    hasher.update(block.header.merkle_root.as_bytes());
    hasher.update(block.header.timestamp.to_be_bytes());
    hasher.update(block.header.nonce.to_be_bytes());
    hasher.update(block.header.difficulty.to_be_bytes());
    let result = hasher.finalize();
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&result);
    arr
}

pub fn mine_block(chain: &mut Blockchain, miner: &str) -> Block {
    let difficulty = chain.difficulty();
    let mut block = chain.candidate_block();
    let fee_total: u64 = block.transactions.iter().map(|t| t.fee).sum();
    let reward = chain.block_subsidy() + fee_total;
    block
        .transactions
        .insert(0, coinbase_transaction(miner.to_string(), reward));
    block.header.merkle_root = compute_merkle_root(&block.transactions);
    block.header.difficulty = difficulty;
    loop {
        let hash = {
            let mut hasher = Sha256::new();
            hasher.update(block.header.previous_hash.as_bytes());
            hasher.update(block.header.merkle_root.as_bytes());
            hasher.update(block.header.timestamp.to_be_bytes());
            hasher.update(block.header.nonce.to_be_bytes());
            hasher.update(block.header.difficulty.to_be_bytes());
            for tx in &block.transactions {
                hasher.update(tx.hash());
            }
            hasher.finalize()
        };
        if meets_difficulty(&hash, difficulty) {
            break;
        }
        block.header.nonce += 1;
    }
    chain.add_block(block.clone());
    block
}

pub fn mine_block_threads(chain: &mut Blockchain, miner: &str, threads: usize) -> Block {
    if threads <= 1 {
        return mine_block(chain, miner);
    }

    let difficulty = chain.difficulty();
    let mut base = chain.candidate_block();
    let fee_total: u64 = base.transactions.iter().map(|t| t.fee).sum();
    let reward = chain.block_subsidy() + fee_total;
    base.transactions
        .insert(0, coinbase_transaction(miner.to_string(), reward));
    base.header.merkle_root = compute_merkle_root(&base.transactions);
    base.header.difficulty = difficulty;

    let found = Arc::new(AtomicBool::new(false));
    let result = Arc::new(std::sync::Mutex::new(None));

    let mut handles = Vec::new();
    for i in 0..threads {
        let mut block = base.clone();
        block.header.nonce = i as u64;
        let found_cl = found.clone();
        let res_cl = result.clone();
        handles.push(thread::spawn(move || {
            while !found_cl.load(Ordering::Relaxed) {
                let hash = hash_bytes(&block);
                if meets_difficulty(&hash, difficulty) {
                    let mut out = res_cl.lock().unwrap();
                    if !found_cl.swap(true, Ordering::Relaxed) {
                        *out = Some(block.clone());
                    }
                    break;
                }
                block.header.nonce += threads as u64;
            }
        }));
    }

    for handle in handles {
        let _ = handle.join();
    }

    let block = result.lock().unwrap().take().unwrap();
    chain.add_block(block.clone());
    block
}

#[cfg(test)]
mod tests {
    use super::*;
    use coin::new_transaction;
    use coin_wallet::Wallet;
    use hex_literal::hex;

    const A1: &str = "1BvgsfsZQVtkLS69NvGF8rw6NZW2ShJQHr";
    const A2: &str = "1B1TKfsCkW5LQ6R1kSXUx7hLt49m1kwz75";
    const SEED: [u8; 16] = hex!("000102030405060708090a0b0c0d0e0f");

    fn sign_a1(tx: &mut coin::Transaction) {
        let wallet = Wallet::from_seed(&SEED).unwrap();
        let sk = wallet.derive_priv("m/0'/0/0").unwrap().secret_key().clone();
        tx.sign(&sk);
    }

    #[test]
    fn difficulty_check() {
        assert!(meets_difficulty(&[0x00, 0x7F], 9));
        assert!(!meets_difficulty(&[0x00, 0x7F], 10));
    }

    #[test]
    fn mining_adds_block() {
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
        let mut tx = new_transaction(A1, A2, 1);
        sign_a1(&mut tx);
        assert!(bc.add_transaction(tx));
        let len_before = bc.len();
        let difficulty = bc.difficulty();
        let block = mine_block(&mut bc, A1);
        assert!(bc.len() > len_before);
        let hash = hex::decode(block.hash()).unwrap();
        assert!(meets_difficulty(&hash, difficulty));
    }

    #[test]
    fn mining_rewards_miner() {
        let mut bc = Blockchain::new();
        assert_eq!(bc.balance(A1), 0);
        mine_block(&mut bc, A1);
        assert_eq!(bc.balance(A1), bc.block_subsidy() as i64);
        mine_block(&mut bc, A1);
        assert_eq!(bc.balance(A1), (bc.block_subsidy() * 2) as i64);
    }

    #[test]
    fn miner_collects_fees() {
        let mut bc = Blockchain::new();
        let reward1 = bc.block_subsidy();
        bc.add_block(Block {
            header: BlockHeader {
                previous_hash: String::new(),
                merkle_root: String::new(),
                timestamp: 0,
                nonce: 0,
                difficulty: 0,
            },
            transactions: vec![coinbase_transaction(A1, reward1)],
        });
        let mut tx = new_transaction_with_fee(A1, A2, 1, 2);
        sign_a1(&mut tx);
        assert!(bc.add_transaction(tx));
        let reward2 = bc.block_subsidy();
        mine_block(&mut bc, A1);
        assert_eq!(bc.balance(A1), (reward1 + reward2 - 1) as i64);
        assert_eq!(bc.balance(A2), 1);
    }

    #[test]
    fn multithreaded_mining() {
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
        let len_before = bc.len();
        let block = mine_block_threads(&mut bc, A1, 2);
        assert!(bc.len() > len_before);
        let hash = hex::decode(block.hash()).unwrap();
        assert!(meets_difficulty(&hash, block.header.difficulty));
    }
}
