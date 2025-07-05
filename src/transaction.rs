use bs58;
use coin_proto::{Transaction, TransactionOutput};
use ripemd::Ripemd160;
use secp256k1;
use sha2::{Digest, Sha256};

#[derive(Debug, PartialEq)]
pub enum Error {
    InvalidAddress,
}

pub type Result<T> = std::result::Result<T, Error>;

pub fn new_transaction_with_fee(
    sender: impl Into<String>,
    recipient: impl Into<String>,
    amount: u64,
    fee: u64,
) -> Result<Transaction> {
    let sender = sender.into();
    let recipient = recipient.into();
    if !valid_address(&sender) || !valid_address(&recipient) {
        return Err(Error::InvalidAddress);
    }
    Ok(Transaction {
        sender,
        recipient,
        amount,
        fee,
        signature: Vec::new(),
        encrypted_message: Vec::new(),
        inputs: Vec::new(),
        outputs: Vec::new(),
    })
}

pub fn new_transaction(
    sender: impl Into<String>,
    recipient: impl Into<String>,
    amount: u64,
) -> Result<Transaction> {
    new_transaction_with_fee(sender, recipient, amount, 0)
}

pub fn new_multi_transaction_with_fee(
    sender: impl Into<String>,
    outputs: Vec<(String, u64)>,
    fee: u64,
) -> Result<Transaction> {
    let sender = sender.into();
    if !valid_address(&sender) {
        return Err(Error::InvalidAddress);
    }
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
    if !valid_address(&recipient) || extra.iter().any(|o| !valid_address(&o.address)) {
        return Err(Error::InvalidAddress);
    }
    Ok(Transaction {
        sender,
        recipient,
        amount,
        fee,
        signature: Vec::new(),
        encrypted_message: Vec::new(),
        inputs: Vec::new(),
        outputs: extra,
    })
}

pub fn coinbase_transaction(miner: impl Into<String>, amount: u64) -> Result<Transaction> {
    let miner = miner.into();
    if !valid_address(&miner) {
        return Err(Error::InvalidAddress);
    }
    Ok(Transaction {
        sender: String::new(),
        recipient: miner,
        amount,
        fee: 0,
        signature: Vec::new(),
        encrypted_message: Vec::new(),
        inputs: Vec::new(),
        outputs: Vec::new(),
    })
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
) -> Result<Transaction> {
    let sender = sender.into();
    let recipient = recipient.into();
    if !valid_address(&sender) || !valid_address(&recipient) {
        return Err(Error::InvalidAddress);
    }
    Ok(Transaction {
        sender,
        recipient,
        amount,
        fee,
        signature: Vec::new(),
        encrypted_message: encrypt_message(message, sender_sk, recipient_pk),
        inputs: Vec::new(),
        outputs: Vec::new(),
    })
}

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
