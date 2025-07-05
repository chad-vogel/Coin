pub use coin_proto::{Transaction, TransactionInput, TransactionOutput};
use sha2::{Digest, Sha256};

pub mod block;
pub mod blockchain;
pub mod blockfile;
pub mod transaction;
pub mod utils;

pub use block::{Block, BlockHeader};
pub use blockchain::{
    BLOCK_SUBSIDY, Blockchain, COIN, DIFFICULTY_WINDOW, HALVING_INTERVAL, MAX_SUPPLY,
    TARGET_BLOCK_MS,
};
pub use transaction::{
    Error, Result, TransactionExt, address_from_secret, coinbase_transaction, decrypt_message,
    encrypt_message, new_multi_transaction_with_fee, new_transaction, new_transaction_with_fee,
    new_transaction_with_message, valid_address,
};
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

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;
    use std::collections::HashMap;

    const A1: &str = "1BvgsfsZQVtkLS69NvGF8rw6NZW2ShJQHr";
    const A2: &str = "1B1TKfsCkW5LQ6R1kSXUx7hLt49m1kwz75";

    #[test]
    fn transaction_hash_consistent() {
        let tx = new_transaction(A1, A2, 10).unwrap();
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
        bc.add_block(Block {
            header: BlockHeader {
                previous_hash: String::new(),
                merkle_root: String::new(),
                timestamp: 0,
                nonce: 0,
                difficulty: 0,
            },
            transactions: vec![
                coinbase_transaction(&addr1, bc.block_subsidy()).unwrap(),
                coinbase_transaction(&addr2, bc.block_subsidy()).unwrap(),
            ],
        });
        let mut tx1 = new_transaction(&addr1, &addr2, 5).unwrap();
        tx1.sign(&sk1);
        let mut tx2 = new_transaction(&addr2, &addr1, 7).unwrap();
        tx2.sign(&sk2);
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
        let tx = coinbase_transaction(A1, bc.block_subsidy()).unwrap();
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
        bc.add_block(block);
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
        };
        assert!(!bc.add_transaction(tx));
        assert_eq!(bc.mempool_len(), 0);
    }

    #[test]
    fn new_transaction_invalid_sender_panics() {
        assert!(new_transaction("badaddr", A2, 1).is_err());
    }

    #[test]
    fn reject_zero_amount_transaction() {
        let mut bc = Blockchain::new();
        let sk = secp256k1::SecretKey::from_slice(&[1u8; 32]).unwrap();
        let addr = address_from_secret(&sk);
        let mut tx = new_transaction(&addr, A2, 0).unwrap();
        tx.sign(&sk);
        assert!(!bc.add_transaction(tx));
    }

    #[test]
    fn reject_insufficient_balance() {
        let mut bc = Blockchain::new();
        let sk = secp256k1::SecretKey::from_slice(&[1u8; 32]).unwrap();
        let addr = address_from_secret(&sk);
        // give sender some coins
        bc.add_block(Block {
            header: BlockHeader {
                previous_hash: String::new(),
                merkle_root: String::new(),
                timestamp: 0,
                nonce: 0,
                difficulty: 0,
            },
            transactions: vec![coinbase_transaction(&addr, bc.block_subsidy()).unwrap()],
        });
        let mut tx = new_transaction(&addr, A2, bc.block_subsidy() + 1).unwrap();
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
        bc.add_block(Block {
            header: BlockHeader {
                previous_hash: String::new(),
                merkle_root: compute_merkle_root(&[coinbase_transaction(
                    &addr1,
                    bc.block_subsidy(),
                )
                .unwrap()]),
                timestamp: 0,
                nonce: 0,
                difficulty: 0,
            },
            transactions: vec![coinbase_transaction(&addr1, bc.block_subsidy()).unwrap()],
        });
        let mut tx = new_transaction_with_fee(&addr1, &addr2, 5, 2).unwrap();
        tx.sign(&sk1);
        assert!(bc.add_transaction(tx.clone()));
        let block = bc.candidate_block();
        bc.add_block(block);
        assert_eq!(bc.balance(&addr1), bc.block_subsidy() as i64 - 7);
        assert_eq!(bc.balance(&addr2), 5);
    }

    #[test]
    fn save_and_load_chain() {
        let mut bc = Blockchain::new();
        let tx = coinbase_transaction(A1, bc.block_subsidy()).unwrap();
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
        bc.add_block(block);
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
            let tx = coinbase_transaction(A1, bc.block_subsidy()).unwrap();
            bc.add_block(Block {
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
        assert!(dir.path().join("CURRENT").exists());
        let loaded = Blockchain::load(dir.path()).unwrap();
        assert_eq!(loaded.all(), bc.all());
    }

    #[test]
    fn save_removes_existing_block_files() {
        let mut bc = Blockchain::new();
        for _ in 0..2 {
            let tx = coinbase_transaction(A1, bc.block_subsidy()).unwrap();
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
        std::fs::write(dir.path().join("junk"), b"bad").unwrap();
        bc.save(dir.path()).unwrap();
        assert!(!dir.path().join("junk").exists());
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
        let mut tx = new_transaction(&sender, A2, 5).unwrap();
        tx.sign(&sk);
        assert!(tx.verify());
    }

    #[test]
    fn verify_rejects_bad_signature_len() {
        let mut tx = new_transaction(A1, A2, 5).unwrap();
        tx.signature = vec![0u8; 10];
        assert!(!tx.verify());
    }

    #[test]
    fn verify_rejects_invalid_recovery_id() {
        let mut tx = new_transaction(A1, A2, 5).unwrap();
        tx.signature = vec![4u8; 65];
        assert!(!tx.verify());
    }

    #[test]
    fn verify_rejects_malformed_signature() {
        let mut sig = vec![0u8; 65];
        sig[0] = 0; // valid recovery id
        let mut tx = new_transaction(A1, A2, 5).unwrap();
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
            transactions: vec![coinbase_transaction(&addr, bc.block_subsidy()).unwrap()],
        });
        let tx = new_transaction(&addr, A2, 1).unwrap();
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
            transactions: vec![coinbase_transaction(&addr, bc.block_subsidy()).unwrap()],
        });
        let mut tx = new_transaction(&addr, A2, 1).unwrap();
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
        let tx = new_transaction_with_message(A1, A2, 5, 0, "secret", &sk_sender, &pk_recipient)
            .unwrap();
        assert!(!tx.encrypted_message.is_empty());
    }

    #[test]
    fn new_transaction_with_message_invalid_recipient() {
        let secp = secp256k1::Secp256k1::new();
        let sk_sender = secp256k1::SecretKey::from_slice(&[1u8; 32]).unwrap();
        let pk_recipient = secp256k1::PublicKey::from_secret_key(
            &secp,
            &secp256k1::SecretKey::from_slice(&[2u8; 32]).unwrap(),
        );
        let res =
            new_transaction_with_message(A1, "badaddr", 5, 0, "secret", &sk_sender, &pk_recipient);
        assert!(res.is_err());
    }

    #[test]
    fn mempool_save_load_roundtrip() {
        let mut bc = Blockchain::new();
        bc.add_transaction(coinbase_transaction(A1, 5).unwrap());
        bc.add_transaction(coinbase_transaction(A2, 7).unwrap());
        let tmp = tempfile::NamedTempFile::new().unwrap();
        bc.save_mempool(tmp.path()).unwrap();

        let mut bc2 = Blockchain::new();
        bc2.load_mempool(tmp.path()).unwrap();
        assert_eq!(bc.mempool, bc2.mempool);
    }

    #[test]
    fn load_mempool_invalid_data() {
        let mut bc = Blockchain::new();
        let tmp = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(tmp.path(), b"not json").unwrap();
        let res = bc.load_mempool(tmp.path());
        assert!(res.is_err());
    }

    #[test]
    fn merkle_root_tree() {
        let tx1 = coinbase_transaction(A1, 1).unwrap();
        let tx2 = coinbase_transaction(A2, 1).unwrap();
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
        let tx = coinbase_transaction(A1, 1).unwrap();
        let root = compute_merkle_root(&[tx.clone()]);
        assert_eq!(root, tx.hash());
    }

    #[test]
    fn prune_preserves_hash() {
        let bc = Blockchain::new();
        let tx = coinbase_transaction(A1, bc.block_subsidy()).unwrap();
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
        let coinbase = coinbase_transaction(&addr1, bc.block_subsidy()).unwrap();
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
        let mut tx = new_transaction_with_fee(&addr1, &addr2, 5, 1).unwrap();
        tx.sign(&sk1);
        assert!(bc.add_transaction(tx));
        assert_eq!(bc.available_utxo(&addr1), bc.block_subsidy() as i64 - 6);
        assert_eq!(bc.balance(&addr1), bc.block_subsidy() as i64);
        let block = bc.candidate_block();
        bc.add_block(block);
        assert_eq!(bc.balance(&addr1), bc.block_subsidy() as i64 - 6);
    }

    #[test]
    fn load_rebuilds_utxos() {
        let mut bc = Blockchain::new();
        let sk1 = secp256k1::SecretKey::from_slice(&[1u8; 32]).unwrap();
        let sk2 = secp256k1::SecretKey::from_slice(&[2u8; 32]).unwrap();
        let addr1 = address_from_secret(&sk1);
        let addr2 = address_from_secret(&sk2);
        let cb = coinbase_transaction(&addr1, bc.block_subsidy()).unwrap();
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
        let mut tx = new_transaction(&addr1, &addr2, 10).unwrap();
        tx.sign(&sk1);
        let cb2 = coinbase_transaction(&addr2, bc.block_subsidy()).unwrap();
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
        let tx = coinbase_transaction(A1, bc.block_subsidy()).unwrap();
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
        let tx = coinbase_transaction(A1, bc.block_subsidy()).unwrap();
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
        )
        .unwrap();
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
            let tx = coinbase_transaction(A1, bc.block_subsidy()).unwrap();
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
            let tx = coinbase_transaction(A1, bc.block_subsidy()).unwrap();
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
        let mut tx = new_transaction_with_fee(&addr1, &addr2, 5, 1).unwrap();
        tx.sign(&sk1);
        let reward = Blockchain::subsidy_for_height(0, 0);
        let cb = coinbase_transaction(&addr1, reward + tx.fee).unwrap();
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
        let mut tx = new_transaction_with_fee(&addr1, &addr2, 5, 1).unwrap();
        tx.sign(&sk1);
        let reward = Blockchain::subsidy_for_height(0, 0);
        let cb = coinbase_transaction(&addr1, reward + tx.fee + 1).unwrap();
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
        let cb = coinbase_transaction(&addr1, bc.block_subsidy()).unwrap();
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
        let mut tx = new_transaction(&addr1, &addr2, 10).unwrap();
        tx.inputs.push(TransactionInput {
            address: addr1.clone(),
            amount: 10,
        });
        tx.sign(&sk1);
        assert!(bc.add_transaction(tx.clone()));
        let block = bc.candidate_block();
        bc.add_block(block);
        assert_eq!(bc.balance(&addr1), bc.block_subsidy() as i64 - 10);
        assert_eq!(bc.balance(&addr2), 10);
    }

    #[test]
    fn lock_and_unlock_stake() {
        let mut bc = Blockchain::new();
        let tx = coinbase_transaction(A1, bc.block_subsidy()).unwrap();
        bc.add_block(Block {
            header: BlockHeader {
                previous_hash: String::new(),
                merkle_root: compute_merkle_root(&[tx.clone()]),
                timestamp: 0,
                nonce: 0,
                difficulty: 0,
            },
            transactions: vec![tx],
        });
        let subsidy = bc.block_subsidy();
        assert!(bc.lock_stake(A1, subsidy / 2));
        assert_eq!(bc.locked_balance(A1), subsidy / 2);
        assert_eq!(bc.balance(A1), subsidy as i64 / 2);
        assert!(bc.unlock_stake(A1, subsidy / 2));
        assert_eq!(bc.locked_balance(A1), 0);
        assert_eq!(bc.balance(A1), subsidy as i64);
        assert!(!bc.unlock_stake(A1, 1));
    }

    #[test]
    fn lock_stake_rejects_insufficient_balance() {
        let mut bc = Blockchain::new();
        assert!(!bc.lock_stake(A1, 10));
    }

    #[test]
    fn subsidy_for_height_respects_halving_and_max() {
        // initial subsidy
        assert_eq!(Blockchain::subsidy_for_height(0, 0), BLOCK_SUBSIDY);
        // halving after HALVING_INTERVAL blocks
        assert_eq!(
            Blockchain::subsidy_for_height(HALVING_INTERVAL, 0),
            BLOCK_SUBSIDY / 2
        );
        // adjust reward when near MAX_SUPPLY
        let near_max = MAX_SUPPLY - BLOCK_SUBSIDY / 3;
        assert_eq!(
            Blockchain::subsidy_for_height(0, near_max),
            BLOCK_SUBSIDY / 3
        );
        // no reward once MAX_SUPPLY reached
        assert_eq!(Blockchain::subsidy_for_height(0, MAX_SUPPLY), 0);
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
                let tx = coinbase_transaction(&addr, reward).unwrap();
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
                let tx = coinbase_transaction(&addr, reward).unwrap();
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
