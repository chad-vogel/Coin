use bs58;
use coin::{Blockchain, valid_address};
use ripemd::Ripemd160;
use secp256k1::{self, Secp256k1};
use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet};

/// Number of rounds before a new stake becomes active.
pub const BOND_DELAY: u64 = 1;
/// Number of rounds before a removed stake unlocks.
pub const UNBOND_DELAY: u64 = 1;

#[derive(Clone, Debug)]
pub struct StakeRegistry {
    active: HashMap<String, u64>,
    bonding: HashMap<String, (u64, u64)>,
    unbonding: HashMap<String, (u64, u64)>,
    round: u64,
}

impl StakeRegistry {
    pub fn new() -> Self {
        Self {
            active: HashMap::new(),
            bonding: HashMap::new(),
            unbonding: HashMap::new(),
            round: 0,
        }
    }

    pub fn total_stake(&self) -> u64 {
        self.active.values().sum()
    }

    pub fn stake(&mut self, chain: &mut Blockchain, addr: &str, amount: u64) -> bool {
        if !valid_address(addr) || chain.balance(addr) < amount as i64 {
            return false;
        }
        if !chain.lock_stake(addr, amount) {
            return false;
        }
        let activate = self.round + BOND_DELAY;
        self.bonding.insert(addr.to_string(), (amount, activate));
        true
    }

    pub fn unstake(&mut self, _chain: &mut Blockchain, addr: &str) -> u64 {
        if let Some(v) = self.active.remove(addr) {
            let unlock = self.round + UNBOND_DELAY;
            self.unbonding.insert(addr.to_string(), (v, unlock));
            v
        } else {
            0
        }
    }

    pub fn validators(&self) -> HashSet<String> {
        self.active.keys().cloned().collect()
    }

    pub fn stake_of(&self, addr: &str) -> u64 {
        *self.active.get(addr).unwrap_or(&0)
    }

    pub fn schedule(&self, slot: u64) -> Option<String> {
        if self.active.is_empty() {
            return None;
        }
        let mut entries: Vec<_> = self.active.iter().collect();
        entries.sort_by(|a, b| a.0.cmp(b.0));
        let total: u64 = self.total_stake();
        let mut idx = slot % total;
        for (addr, stake) in entries {
            if idx < *stake {
                return Some(addr.clone());
            }
            idx -= *stake;
        }
        None
    }

    /// Advance the registry by one round, activating and releasing stakes as needed.
    pub fn advance_round(&mut self, chain: &mut Blockchain) {
        self.round += 1;
        let r = self.round;
        let matured: Vec<_> = self
            .bonding
            .iter()
            .filter(|(_, v)| v.1 <= r)
            .map(|(a, v)| (a.clone(), v.0))
            .collect();
        for (addr, amt) in matured {
            self.bonding.remove(&addr);
            *self.active.entry(addr).or_default() += amt;
        }
        let releasing: Vec<_> = self
            .unbonding
            .iter()
            .filter(|(_, v)| v.1 <= r)
            .map(|(a, v)| (a.clone(), v.0))
            .collect();
        for (addr, amt) in releasing {
            self.unbonding.remove(&addr);
            chain.unlock_stake(&addr, amt);
        }
    }

    /// Remove all stake from a misbehaving validator without unlocking it.
    pub fn slash(&mut self, addr: &str) {
        self.active.remove(addr);
        self.bonding.remove(addr);
        self.unbonding.remove(addr);
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
    votes: HashMap<String, u64>,
    voted: HashMap<String, String>,
    finalized: HashSet<String>,
}

impl ConsensusState {
    pub fn new(registry: StakeRegistry) -> Self {
        Self {
            registry,
            current_hash: None,
            votes: HashMap::new(),
            voted: HashMap::new(),
            finalized: HashSet::new(),
        }
    }

    pub fn start_round(&mut self, block_hash: String, chain: &mut Blockchain) {
        self.registry.advance_round(chain);
        self.current_hash = Some(block_hash);
        self.votes.clear();
        self.voted.clear();
    }

    pub fn current_hash(&self) -> Option<String> {
        self.current_hash.clone()
    }

    pub fn register_vote(&mut self, vote: &Vote) -> bool {
        if !vote.verify() {
            return false;
        }
        if Some(&vote.block_hash) != self.current_hash.as_ref() {
            self.registry.slash(&vote.validator);
            return false;
        }
        let stake = self.registry.stake_of(&vote.validator);
        if stake == 0 {
            return false;
        }
        if let Some(prev) = self.voted.get(&vote.validator) {
            if prev != &vote.block_hash {
                self.registry.slash(&vote.validator);
                self.votes.remove(&vote.validator);
                return false;
            } else {
                return false;
            }
        }
        self.voted
            .insert(vote.validator.clone(), vote.block_hash.clone());
        self.votes.insert(vote.validator.clone(), stake);
        if self.voted_stake() * 3 > self.registry.total_stake() * 2 {
            if let Some(h) = self.current_hash.take() {
                self.finalized.insert(h);
            }
            true
        } else {
            false
        }
    }

    pub fn voted_stake(&self) -> u64 {
        self.votes.values().sum()
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

    pub fn mark_finalized(&mut self, hash: &str) {
        self.finalized.insert(hash.to_string());
    }

    pub fn save_finalized<P: AsRef<std::path::Path>>(&self, path: P) -> std::io::Result<()> {
        let list: Vec<String> = self.finalized.iter().cloned().collect();
        let data = bincode::serialize(&list)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;
        std::fs::write(path, data)
    }

    pub fn load_finalized<P: AsRef<std::path::Path>>(&mut self, path: P) {
        if let Ok(data) = std::fs::read(path) {
            if let Ok(list) = bincode::deserialize::<Vec<String>>(&data) {
                self.finalized.extend(list);
            }
        }
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
                coin::coinbase_transaction(&addr1, bc.block_subsidy()).unwrap(),
                coin::coinbase_transaction(&addr2, bc.block_subsidy()).unwrap(),
            ],
        });
        let mut reg = StakeRegistry::new();
        assert!(reg.stake(&mut bc, &addr1, 30));
        assert!(reg.stake(&mut bc, &addr2, 20));
        reg.advance_round(&mut bc);
        let total = reg.total_stake();
        assert_eq!(total, 50);
        let mut cs = ConsensusState::new(reg);
        cs.start_round("h".into(), &mut bc);
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
            transactions: vec![coin::coinbase_transaction(&addr, bc.block_subsidy()).unwrap()],
        });
        let mut reg = StakeRegistry::new();
        assert!(reg.stake(&mut bc, &addr, 10));
        // not active until next round
        assert_eq!(reg.total_stake(), 0);
        reg.advance_round(&mut bc);
        assert_eq!(reg.total_stake(), 10);
        assert_eq!(reg.stake_of(&addr), 10);
        assert_eq!(reg.validators().len(), 1);
        assert_eq!(bc.locked_balance(&addr), 10);
        assert_eq!(reg.schedule(0).as_deref(), Some(addr.as_str()));
        assert_eq!(reg.unstake(&mut bc, &addr), 10);
        // still locked until unbond delay passes
        assert_eq!(bc.locked_balance(&addr), 10);
        reg.advance_round(&mut bc);
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
        let mut bc = Blockchain::new();
        cs.start_round("h".into(), &mut bc);
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
                coin::coinbase_transaction(&addr1, bc.block_subsidy()).unwrap(),
                coin::coinbase_transaction(&addr2, bc.block_subsidy()).unwrap(),
            ],
        });
        let mut reg = StakeRegistry::new();
        assert!(reg.stake(&mut bc, &addr1, 2));
        assert!(reg.stake(&mut bc, &addr2, 1));
        reg.advance_round(&mut bc);
        assert_eq!(reg.schedule(0).as_deref(), Some(addr1.as_str()));
        assert_eq!(reg.schedule(2).as_deref(), Some(addr2.as_str()));
        let mut cs = ConsensusState::new(reg);
        cs.start_round("h".into(), &mut bc);
        let mut v = Vote::new(addr1.clone(), "bad".into());
        v.sign(&sk1);
        assert!(!cs.register_vote(&v));
        cs.start_round("h".into(), &mut bc);
        let mut v1 = Vote::new(addr1.clone(), "h".into());
        v1.sign(&sk1);
        assert!(!cs.register_vote(&v1));
        let mut v2 = Vote::new(addr2.clone(), "h".into());
        v2.sign(&sk2);
        assert!(cs.register_vote(&v2));
        assert_eq!(cs.voted_stake(), 1);
        assert!(cs.is_finalized("h"));
    }

    #[test]
    fn empty_registry_schedule_none() {
        let reg = StakeRegistry::new();
        assert!(reg.schedule(0).is_none());
    }

    #[test]
    fn slash_on_equivocation() {
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
            transactions: vec![coin::coinbase_transaction(&addr, bc.block_subsidy()).unwrap()],
        });
        let mut reg = StakeRegistry::new();
        assert!(reg.stake(&mut bc, &addr, 10));
        reg.advance_round(&mut bc);
        let mut cs = ConsensusState::new(reg);
        cs.start_round("h".into(), &mut bc);
        let mut v1 = Vote::new(addr.clone(), "h".into());
        v1.sign(&sk);
        assert!(cs.register_vote(&v1));
        let mut v2 = Vote::new(addr.clone(), "wrong".into());
        v2.sign(&sk);
        assert!(!cs.register_vote(&v2));
        assert_eq!(cs.registry_mut().stake_of(&addr), 0);
    }

    #[test]
    fn stake_rejects_invalid_inputs() {
        let mut reg = StakeRegistry::new();
        let mut bc = Blockchain::new();
        assert!(!reg.stake(&mut bc, "bad", 10));
        let sk = SecretKey::from_slice(&[1u8; 32]).unwrap();
        let addr = address_from_secret(&sk);
        assert!(!reg.stake(&mut bc, &addr, 10));
    }

    #[test]
    fn save_and_load_finalized() {
        let mut reg = StakeRegistry::new();
        let mut cs = ConsensusState::new(reg.clone());
        cs.mark_finalized("h1");
        cs.mark_finalized("h2");
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("finalized.bin");
        cs.save_finalized(&path).unwrap();
        let mut cs2 = ConsensusState::new(reg);
        cs2.load_finalized(&path);
        assert!(cs2.is_finalized("h1"));
        assert!(cs2.is_finalized("h2"));
    }
}
