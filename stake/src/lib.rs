use bs58;
use coin::{Blockchain, valid_address};
use ripemd::Ripemd160;
use secp256k1::{self, Secp256k1};
use serde_json;
use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet};

const BOND_DELAY: u64 = 1;
const UNBOND_DELAY: u64 = 1;

#[derive(Clone, Debug)]
struct ValidatorInfo {
    stake: u64,
    bonded_at: u64,
    unbonding_height: Option<u64>,
}

#[derive(Clone, Debug)]
pub struct StakeRegistry {
    validators: HashMap<String, ValidatorInfo>,
}

impl StakeRegistry {
    pub fn new() -> Self {
        Self {
            validators: HashMap::new(),
        }
    }

    pub fn total_stake(&self, height: u64) -> u64 {
        self.validators
            .values()
            .filter(|v| {
                height >= v.bonded_at + BOND_DELAY
                    && v.unbonding_height.map_or(true, |h| height < h)
            })
            .map(|v| v.stake)
            .sum()
    }

    pub fn stake(&mut self, chain: &mut Blockchain, addr: &str, amount: u64, height: u64) -> bool {
        if !valid_address(addr) || chain.balance(addr) < amount as i64 {
            return false;
        }
        if !chain.lock_stake(addr, amount) {
            return false;
        }
        self.validators.insert(
            addr.to_string(),
            ValidatorInfo {
                stake: amount,
                bonded_at: height,
                unbonding_height: None,
            },
        );
        true
    }

    pub fn unstake(&mut self, addr: &str, height: u64) -> bool {
        if let Some(v) = self.validators.get_mut(addr) {
            if v.unbonding_height.is_none() {
                v.unbonding_height = Some(height + UNBOND_DELAY);
                return true;
            }
        }
        false
    }

    pub fn process_height(&mut self, chain: &mut Blockchain, height: u64) {
        let to_remove: Vec<String> = self
            .validators
            .iter()
            .filter_map(|(a, v)| match v.unbonding_height {
                Some(h) if h <= height => Some(a.clone()),
                _ => None,
            })
            .collect();
        for addr in to_remove {
            if let Some(info) = self.validators.remove(&addr) {
                chain.unlock_stake(&addr, info.stake);
            }
        }
    }

    pub fn slash(&mut self, addr: &str) {
        self.validators.remove(addr);
    }

    pub fn validators(&self, height: u64) -> HashSet<String> {
        self.validators
            .iter()
            .filter(|(_, v)| height >= v.bonded_at + BOND_DELAY && v.unbonding_height.is_none())
            .map(|(a, _)| a.clone())
            .collect()
    }

    pub fn stake_of(&self, addr: &str) -> u64 {
        self.validators.get(addr).map(|v| v.stake).unwrap_or(0)
    }

    pub fn schedule(&self, slot: u64) -> Option<String> {
        let eligible: Vec<_> = self
            .validators
            .iter()
            .filter(|(_, v)| slot >= v.bonded_at + BOND_DELAY && v.unbonding_height.is_none())
            .collect();
        if eligible.is_empty() {
            return None;
        }
        let mut entries = eligible;
        entries.sort_by(|a, b| a.0.cmp(b.0));
        let total: u64 = entries.iter().map(|(_, v)| v.stake).sum();
        let mut idx = slot % total;
        for (addr, info) in entries {
            if idx < info.stake {
                return Some(addr.clone());
            }
            idx -= info.stake;
        }
        None
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Vote {
    pub validator: String,
    pub block_hash: String,
    pub signature: Vec<u8>,
}

impl Vote {
    pub fn new(validator: String, block_hash: String) -> Self {
        Self {
            validator,
            block_hash,
            signature: Vec::new(),
        }
    }

    pub fn sign(&mut self, sk: &secp256k1::SecretKey) {
        let secp = Secp256k1::new();
        let mut hasher = Sha256::new();
        hasher.update(self.validator.as_bytes());
        hasher.update(self.block_hash.as_bytes());
        let hash = hasher.finalize();
        let msg = secp256k1::Message::from_slice(&hash).expect("32 bytes");
        let sig = secp.sign_ecdsa_recoverable(&msg, sk);
        let (id, data) = sig.serialize_compact();
        self.signature.clear();
        self.signature.push(id.to_i32() as u8);
        self.signature.extend_from_slice(&data);
    }

    pub fn verify(&self) -> bool {
        if self.signature.len() != 65 || !valid_address(&self.validator) {
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
        let mut hasher = Sha256::new();
        hasher.update(self.validator.as_bytes());
        hasher.update(self.block_hash.as_bytes());
        let hash = hasher.finalize();
        let msg = secp256k1::Message::from_slice(&hash).expect("32 bytes");
        let secp = Secp256k1::new();
        let pk = match secp.recover_ecdsa(&msg, &sig) {
            Ok(p) => p,
            Err(_) => return false,
        };
        let pk_bytes = pk.serialize();
        let sha = Sha256::digest(pk_bytes);
        let rip = Ripemd160::digest(sha);
        let mut payload = Vec::with_capacity(25);
        payload.push(0x00);
        payload.extend_from_slice(&rip);
        let check = Sha256::digest(Sha256::digest(&payload));
        payload.extend_from_slice(&check[..4]);
        let addr = bs58::encode(payload).into_string();
        addr == self.validator
    }
}

pub struct ConsensusState {
    registry: StakeRegistry,
    current_hash: Option<String>,
    current_height: u64,
    votes: HashMap<String, String>,
    finalized: HashSet<String>,
}

impl ConsensusState {
    pub fn new(registry: StakeRegistry) -> Self {
        Self {
            registry,
            current_hash: None,
            current_height: 0,
            votes: HashMap::new(),
            finalized: HashSet::new(),
        }
    }

    pub fn start_round(&mut self, block_hash: String, height: u64) {
        self.current_hash = Some(block_hash);
        self.current_height = height;
        self.votes.clear();
    }

    pub fn current_hash(&self) -> Option<String> {
        self.current_hash.clone()
    }

    pub fn register_vote(&mut self, vote: &Vote) -> bool {
        if Some(&vote.block_hash) != self.current_hash.as_ref() || !vote.verify() {
            return false;
        }
        let stake = self.registry.stake_of(&vote.validator);
        if stake == 0 {
            return false;
        }
        if let Some(prev) = self.votes.get(&vote.validator) {
            if prev != &vote.block_hash {
                self.registry.slash(&vote.validator);
                self.votes.remove(&vote.validator);
                return false;
            } else {
                return false;
            }
        }
        self.votes
            .insert(vote.validator.clone(), vote.block_hash.clone());
        if self.voted_stake() * 3 > self.registry.total_stake(self.current_height + 1) * 2 {
            if let Some(h) = self.current_hash.take() {
                self.finalized.insert(h);
            }
            true
        } else {
            false
        }
    }

    pub fn voted_stake(&self) -> u64 {
        self.votes.keys().map(|v| self.registry.stake_of(v)).sum()
    }

    pub fn registry_mut(&mut self) -> &mut StakeRegistry {
        &mut self.registry
    }

    pub fn is_finalized(&self, hash: &str) -> bool {
        self.finalized.contains(hash)
    }

    pub fn finalized_blocks(&self) -> Vec<String> {
        self.finalized.iter().cloned().collect()
    }

    pub fn add_finalized(&mut self, hash: String) {
        self.finalized.insert(hash);
    }

    pub fn save_finalized<P: AsRef<std::path::Path>>(&self, path: P) -> std::io::Result<()> {
        let list: Vec<String> = self.finalized.iter().cloned().collect();
        std::fs::write(path, serde_json::to_vec(&list).unwrap())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use coin::address_from_secret;
    use secp256k1::SecretKey;

    #[test]
    fn vote_sign_verify() {
        let sk = SecretKey::from_slice(&[1u8; 32]).unwrap();
        let addr = address_from_secret(&sk);
        let mut v = Vote::new(addr.clone(), "h".into());
        v.sign(&sk);
        assert!(v.verify());
    }

    #[test]
    fn consensus_finalizes() {
        let sk1 = SecretKey::from_slice(&[1u8; 32]).unwrap();
        let sk2 = SecretKey::from_slice(&[2u8; 32]).unwrap();
        let addr1 = address_from_secret(&sk1);
        let addr2 = address_from_secret(&sk2);
        let mut bc = Blockchain::new();
        bc.add_block(coin::Block {
            header: coin::BlockHeader {
                previous_hash: String::new(),
                merkle_root: String::new(),
                timestamp: 0,
                nonce: 0,
                difficulty: 0,
            },
            transactions: vec![
                coin::coinbase_transaction(&addr1, bc.block_subsidy()),
                coin::coinbase_transaction(&addr2, bc.block_subsidy()),
            ],
        });
        let mut reg = StakeRegistry::new();
        assert!(reg.stake(&mut bc, &addr1, 30, 0));
        assert!(reg.stake(&mut bc, &addr2, 20, 0));
        let total = reg.total_stake(1);
        assert_eq!(total, 50);
        let mut cs = ConsensusState::new(reg);
        cs.start_round("h".into(), 1);
        let mut v1 = Vote::new(addr1.clone(), "h".into());
        v1.sign(&sk1);
        assert!(!cs.register_vote(&v1));
        let mut v2 = Vote::new(addr2.clone(), "h".into());
        v2.sign(&sk2);
        assert!(cs.register_vote(&v2));
        assert!(cs.is_finalized("h"));
    }

    #[test]
    fn registry_operations() {
        let sk = SecretKey::from_slice(&[1u8; 32]).unwrap();
        let addr = address_from_secret(&sk);
        let mut bc = Blockchain::new();
        bc.add_block(coin::Block {
            header: coin::BlockHeader {
                previous_hash: String::new(),
                merkle_root: String::new(),
                timestamp: 0,
                nonce: 0,
                difficulty: 0,
            },
            transactions: vec![coin::coinbase_transaction(&addr, bc.block_subsidy())],
        });
        let mut reg = StakeRegistry::new();
        assert!(reg.stake(&mut bc, &addr, 10, 0));
        assert_eq!(reg.total_stake(1), 10);
        assert_eq!(reg.stake_of(&addr), 10);
        assert_eq!(reg.validators(1).len(), 1);
        assert_eq!(bc.locked_balance(&addr), 10);
        assert_eq!(reg.schedule(1).as_deref(), Some(addr.as_str()));
        assert!(reg.unstake(&addr, 1));
        reg.process_height(&mut bc, 2);
        assert_eq!(bc.locked_balance(&addr), 0);
    }

    #[test]
    fn vote_verify_errors() {
        let sk = SecretKey::from_slice(&[1u8; 32]).unwrap();
        let addr = address_from_secret(&sk);
        let mut v = Vote::new(addr.clone(), "h".into());
        v.signature = vec![1, 2];
        assert!(!v.verify());
        v.signature = vec![0u8; 65];
        assert!(!v.verify());
    }

    #[test]
    fn vote_verify_wrong_address() {
        let sk1 = SecretKey::from_slice(&[1u8; 32]).unwrap();
        let sk2 = SecretKey::from_slice(&[2u8; 32]).unwrap();
        let addr_wrong = address_from_secret(&sk2);
        let mut v = Vote::new(addr_wrong, "h".into());
        v.sign(&sk1);
        assert!(!v.verify());
    }

    #[test]
    fn register_vote_unknown_validator() {
        let sk = SecretKey::from_slice(&[1u8; 32]).unwrap();
        let addr = address_from_secret(&sk);
        let reg = StakeRegistry::new();
        let mut cs = ConsensusState::new(reg);
        cs.start_round("h".into(), 1);
        let mut v = Vote::new(addr.clone(), "h".into());
        v.sign(&sk);
        assert!(!cs.register_vote(&v));
        assert_eq!(cs.current_hash().as_deref(), Some("h"));
    }

    #[test]
    fn schedule_and_consensus_logic() {
        let sk1 = SecretKey::from_slice(&[1u8; 32]).unwrap();
        let sk2 = SecretKey::from_slice(&[2u8; 32]).unwrap();
        let addr1 = address_from_secret(&sk1);
        let addr2 = address_from_secret(&sk2);
        let mut bc = Blockchain::new();
        bc.add_block(coin::Block {
            header: coin::BlockHeader {
                previous_hash: String::new(),
                merkle_root: String::new(),
                timestamp: 0,
                nonce: 0,
                difficulty: 0,
            },
            transactions: vec![
                coin::coinbase_transaction(&addr1, bc.block_subsidy()),
                coin::coinbase_transaction(&addr2, bc.block_subsidy()),
            ],
        });
        let mut reg = StakeRegistry::new();
        assert!(reg.stake(&mut bc, &addr1, 2, 0));
        assert!(reg.stake(&mut bc, &addr2, 1, 0));
        assert_eq!(reg.schedule(1).as_deref(), Some(addr1.as_str()));
        let mut cs = ConsensusState::new(reg);
        cs.start_round("h".into(), 1);
        let mut v = Vote::new(addr1.clone(), "bad".into());
        v.sign(&sk1);
        assert!(!cs.register_vote(&v));
        cs.start_round("h".into(), 1);
        let mut v1 = Vote::new(addr1.clone(), "h".into());
        v1.sign(&sk1);
        assert!(!cs.register_vote(&v1));
        let mut v2 = Vote::new(addr2.clone(), "h".into());
        v2.sign(&sk2);
        assert!(cs.register_vote(&v2));
        assert_eq!(cs.voted_stake(), 3);
        assert!(cs.is_finalized("h"));
    }

    #[test]
    fn empty_registry_schedule_none() {
        let reg = StakeRegistry::new();
        assert!(reg.schedule(0).is_none());
    }

    #[test]
    fn stake_rejects_invalid_inputs() {
        let mut reg = StakeRegistry::new();
        let mut bc = Blockchain::new();
        assert!(!reg.stake(&mut bc, "bad", 10, 0));
        let sk = SecretKey::from_slice(&[1u8; 32]).unwrap();
        let addr = address_from_secret(&sk);
        assert!(!reg.stake(&mut bc, &addr, 10, 0));
    }

    #[test]
    fn bonding_and_unbonding_delays() {
        let sk = SecretKey::from_slice(&[1u8; 32]).unwrap();
        let addr = address_from_secret(&sk);
        let mut bc = Blockchain::new();
        bc.add_block(coin::Block {
            header: coin::BlockHeader {
                previous_hash: String::new(),
                merkle_root: String::new(),
                timestamp: 0,
                nonce: 0,
                difficulty: 0,
            },
            transactions: vec![coin::coinbase_transaction(&addr, bc.block_subsidy())],
        });
        let mut reg = StakeRegistry::new();
        assert!(reg.stake(&mut bc, &addr, 10, 0));
        // before bond delay
        assert!(reg.schedule(0).is_none());
        // after bond delay
        assert_eq!(reg.schedule(1).as_deref(), Some(addr.as_str()));
        assert!(reg.unstake(&addr, 1));
        // immediately removed from schedule
        assert!(reg.schedule(1).is_none());
        reg.process_height(&mut bc, 2);
        assert_eq!(bc.locked_balance(&addr), 0);
    }

    #[test]
    fn equivocation_slashes() {
        let sk = SecretKey::from_slice(&[1u8; 32]).unwrap();
        let addr = address_from_secret(&sk);
        let sk2 = SecretKey::from_slice(&[2u8; 32]).unwrap();
        let addr2 = address_from_secret(&sk2);
        let mut bc = Blockchain::new();
        bc.add_block(coin::Block {
            header: coin::BlockHeader {
                previous_hash: String::new(),
                merkle_root: String::new(),
                timestamp: 0,
                nonce: 0,
                difficulty: 0,
            },
            transactions: vec![
                coin::coinbase_transaction(&addr, bc.block_subsidy()),
                coin::coinbase_transaction(&addr2, bc.block_subsidy()),
            ],
        });
        let mut reg = StakeRegistry::new();
        assert!(reg.stake(&mut bc, &addr, 10, 0));
        assert!(reg.stake(&mut bc, &addr2, 10, 0));
        let mut cs = ConsensusState::new(reg);
        cs.start_round("h1".into(), 1);
        let mut v1 = Vote::new(addr.clone(), "h1".into());
        v1.sign(&sk);
        assert!(!cs.register_vote(&v1));
        let mut v2 = Vote::new(addr.clone(), "h2".into());
        v2.sign(&sk);
        assert!(!cs.register_vote(&v2));
        assert_eq!(cs.registry.stake_of(&addr), 0);
    }
}
