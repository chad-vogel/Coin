mod bip32;
mod bip39;

use crate::bip32::{DerivationPath, Prefix, XPrv, XPub};
use crate::bip39::Mnemonic;
use bs58;
use rand::rngs::OsRng;
use ripemd::Ripemd160;
use sha2::{Digest, Sha256};

/// HD wallet holding a master extended private key.
#[derive(Clone)]
pub struct Wallet {
    master: XPrv,
    mnemonic: Option<Mnemonic>,
}

impl Wallet {
    /// Create a wallet from raw seed bytes.
    pub fn from_seed(seed: &[u8]) -> bip32::Result<Self> {
        let master = XPrv::new(seed)?;
        Ok(Self {
            master,
            mnemonic: None,
        })
    }

    /// Create a wallet from a BIP39 mnemonic phrase and optional password.
    pub fn from_mnemonic(phrase: &str, password: &str) -> bip32::Result<Self> {
        let mnemonic =
            Mnemonic::new(phrase, Default::default()).map_err(|_| bip32::Error::InvalidMnemonic)?;
        let seed = mnemonic.to_seed(password);
        let master = XPrv::new(&seed)?;
        Ok(Self {
            master,
            mnemonic: Some(mnemonic),
        })
    }

    /// Generate a new random wallet using the OS RNG.
    pub fn generate(password: &str) -> bip32::Result<Self> {
        let mnemonic = Mnemonic::random(&mut OsRng, Default::default());
        let seed = mnemonic.to_seed(password);
        let master = XPrv::new(&seed)?;
        Ok(Self {
            master,
            mnemonic: Some(mnemonic),
        })
    }

    /// Derive a child extended private key for the given path (e.g. "m/0'/1").
    pub fn derive_priv(&self, path: &str) -> bip32::Result<XPrv> {
        let dp: DerivationPath = path.parse()?;
        let mut key = self.master.clone();
        for child in dp.into_iter() {
            key = key.derive_child(child)?;
        }
        Ok(key)
    }

    /// Derive a child extended public key for the given path.
    pub fn derive_pub(&self, path: &str) -> bip32::Result<XPub> {
        Ok(self.derive_priv(path)?.public_key())
    }

    /// Derive an address string from a BIP32 path.
    pub fn derive_address(&self, path: &str) -> bip32::Result<String> {
        let xpub = self.derive_pub(path)?;
        Ok(address_from_xpub(&xpub))
    }

    /// Serialize the master private key using the `xprv` prefix.
    pub fn master_xprv_string(&self) -> String {
        self.master.to_string(Prefix::XPRV).to_string()
    }

    /// Get the underlying mnemonic phrase if present.
    pub fn mnemonic(&self) -> Option<&Mnemonic> {
        self.mnemonic.as_ref()
    }
}

/// Convert an extended public key to a Base58Check encoded address.
fn address_from_xpub(xpub: &XPub) -> String {
    let pk_bytes = xpub.public_key().serialize();
    let sha = Sha256::digest(pk_bytes);
    let rip = Ripemd160::digest(sha);
    let mut payload = Vec::with_capacity(25);
    payload.push(0x00); // mainnet prefix
    payload.extend_from_slice(&rip);
    let checksum = Sha256::digest(Sha256::digest(&payload));
    payload.extend_from_slice(&checksum[..4]);
    bs58::encode(payload).into_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use hex_literal::hex;

    // Values from BIP32 test vector 1
    const SEED: [u8; 16] = hex!("000102030405060708090a0b0c0d0e0f");
    const MASTER: &str = "xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi";
    const CHILD_0H: &str = "xprv9uHRZZhk6KAJC1avXpDAp4MDc3sQKNxDiPvvkX8Br5ngLNv1TxvUxt4cV1rGL5hj6KCesnDYUhd7oWgT11eZG7XnxHrnYeSvkzY7d2bhkJ7";
    const ADDR_0H_0_0: &str = "1BvgsfsZQVtkLS69NvGF8rw6NZW2ShJQHr";
    const ADDR_0H_0_1: &str = "1B1TKfsCkW5LQ6R1kSXUx7hLt49m1kwz75";

    #[test]
    fn master_from_seed() {
        let wallet = Wallet::from_seed(&SEED).unwrap();
        assert_eq!(wallet.master_xprv_string(), MASTER);
    }

    #[test]
    fn derive_child() {
        let wallet = Wallet::from_seed(&SEED).unwrap();
        let child = wallet.derive_priv("m/0'").unwrap();
        let encoded = child.to_string(Prefix::XPRV);
        assert_eq!(encoded.as_str(), CHILD_0H);
    }

    #[test]
    fn from_mnemonic() {
        let phrase = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art";
        let wallet = Wallet::from_mnemonic(phrase, "").unwrap();
        assert!(wallet.mnemonic().is_some());
    }

    #[test]
    fn derive_addresses() {
        let wallet = Wallet::from_seed(&SEED).unwrap();
        let addr0 = wallet.derive_address("m/0'/0/0").unwrap();
        let addr1 = wallet.derive_address("m/0'/0/1").unwrap();
        assert_eq!(addr0, ADDR_0H_0_0);
        assert_eq!(addr1, ADDR_0H_0_1);
    }
}
