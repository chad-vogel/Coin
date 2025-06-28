use coin::{Block, Blockchain, TransactionExt};
use sha2::{Digest, Sha256};

fn meets_difficulty(hash: &[u8], difficulty: u32) -> bool {
    for i in 0..difficulty {
        if hash.get(i as usize).copied().unwrap_or(0) != 0 {
            return false;
        }
    }
    true
}

pub fn mine_block(chain: &mut Blockchain, difficulty: u32) -> Block {
    let mut block = chain.candidate_block();
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

    #[test]
    fn difficulty_check() {
        assert!(meets_difficulty(&[0, 0, 1], 2));
        assert!(!meets_difficulty(&[0, 1], 2));
    }

    #[test]
    fn mining_adds_block() {
        let mut bc = Blockchain::new();
        bc.add_transaction(new_transaction("a".into(), "b".into(), 1));
        let len_before = bc.len();
        let block = mine_block(&mut bc, 1);
        assert!(bc.len() > len_before);
        let hash = hex::decode(block.hash()).unwrap();
        assert!(meets_difficulty(&hash, 1));
    }
}
