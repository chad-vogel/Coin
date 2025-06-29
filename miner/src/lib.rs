use coin::{Block, BlockHeader, Blockchain, TransactionExt, coinbase_transaction};
use sha2::{Digest, Sha256};

fn meets_difficulty(hash: &[u8], difficulty: u32) -> bool {
    for i in 0..difficulty {
        if hash.get(i as usize).copied().unwrap_or(0) != 0 {
            return false;
        }
    }
    true
}

pub fn mine_block(chain: &mut Blockchain, miner: &str) -> Block {
    let difficulty = chain.difficulty();
    let mut block = chain.candidate_block();
    let reward = chain.block_subsidy();
    block
        .transactions
        .insert(0, coinbase_transaction(miner.to_string(), reward));
    let mut h = Sha256::new();
    for tx in &block.transactions {
        h.update(tx.hash());
    }
    block.header.merkle_root = hex::encode(h.finalize());
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
        assert!(meets_difficulty(&[0, 0, 1], 2));
        assert!(!meets_difficulty(&[0, 1], 2));
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
}
