use hmac::{Hmac, Mac};
use secp256k1::{PublicKey, Scalar, Secp256k1, SecretKey};
use sha2::{Digest, Sha256, Sha512};

#[derive(Debug)]
pub enum Error {
    InvalidKey,
    InvalidChild,
    InvalidPath,
    InvalidMnemonic,
}

pub type Result<T> = std::result::Result<T, Error>;

const HARDENED_BIT: u32 = 1 << 31;

#[derive(Clone, Copy)]
pub enum Prefix {
    XPRV,
    XPUB,
}

#[derive(Clone, Copy)]
pub struct ChildNumber(u32);

impl ChildNumber {
    pub fn new(index: u32, hardened: bool) -> Self {
        ChildNumber(if hardened {
            index | HARDENED_BIT
        } else {
            index
        })
    }
    pub fn is_hardened(self) -> bool {
        self.0 & HARDENED_BIT != 0
    }
    pub fn index(self) -> u32 {
        self.0 & !HARDENED_BIT
    }
    pub fn value(self) -> u32 {
        self.0
    }
}

#[derive(Clone)]
pub struct DerivationPath(Vec<ChildNumber>);

impl std::str::FromStr for DerivationPath {
    type Err = Error;
    fn from_str(s: &str) -> Result<Self> {
        let mut parts = s.split('/');
        if parts.next() != Some("m") {
            return Err(Error::InvalidPath);
        }
        let mut nums = Vec::new();
        for p in parts {
            let hardened = p.ends_with("'");
            let nstr = if hardened { &p[..p.len() - 1] } else { p };
            let idx: u32 = nstr.parse().map_err(|_| Error::InvalidPath)?;
            nums.push(ChildNumber::new(idx, hardened));
        }
        Ok(DerivationPath(nums))
    }
}

impl IntoIterator for DerivationPath {
    type Item = ChildNumber;
    type IntoIter = std::vec::IntoIter<ChildNumber>;
    fn into_iter(self) -> Self::IntoIter {
        self.0.into_iter()
    }
}

#[derive(Clone)]
pub struct XPrv {
    secret: SecretKey,
    chain_code: [u8; 32],
    depth: u8,
    parent_fingerprint: [u8; 4],
    child_number: u32,
}

#[derive(Clone)]
pub struct XPub {
    public_key: PublicKey,
    chain_code: [u8; 32],
    depth: u8,
    parent_fingerprint: [u8; 4],
    child_number: u32,
}

fn fingerprint(pk: &PublicKey) -> [u8; 4] {
    let sha = Sha256::digest(pk.serialize());
    let rip = ripemd::Ripemd160::digest(sha);
    [rip[0], rip[1], rip[2], rip[3]]
}

impl XPrv {
    pub fn new(seed: &[u8]) -> Result<Self> {
        let mut hmac = Hmac::<Sha512>::new_from_slice(b"Bitcoin seed").unwrap();
        hmac.update(seed);
        let res = hmac.finalize().into_bytes();
        let (k, c) = res.split_at(32);
        let secret = SecretKey::from_slice(k).map_err(|_| Error::InvalidKey)?;
        let mut chain_code = [0u8; 32];
        chain_code.copy_from_slice(c);
        Ok(XPrv {
            secret,
            chain_code,
            depth: 0,
            parent_fingerprint: [0u8; 4],
            child_number: 0,
        })
    }

    pub fn derive_child(&self, child: ChildNumber) -> Result<Self> {
        let secp = Secp256k1::new();
        let mut mac = Hmac::<Sha512>::new_from_slice(&self.chain_code).unwrap();
        if child.is_hardened() {
            mac.update(&[0u8]);
            mac.update(&self.secret.secret_bytes());
        } else {
            let pk = PublicKey::from_secret_key(&secp, &self.secret);
            mac.update(&pk.serialize());
        }
        mac.update(&child.value().to_be_bytes());
        let res = mac.finalize().into_bytes();
        let (il, ir) = res.split_at(32);
        let mut il_arr = [0u8; 32];
        il_arr.copy_from_slice(il);
        let tweak = Scalar::from_be_bytes(il_arr).map_err(|_| Error::InvalidChild)?;
        let sk = self
            .secret
            .add_tweak(&tweak)
            .map_err(|_| Error::InvalidChild)?;
        let mut cc = [0u8; 32];
        cc.copy_from_slice(ir);
        let fp = fingerprint(&PublicKey::from_secret_key(&secp, &self.secret));
        Ok(XPrv {
            secret: sk,
            chain_code: cc,
            depth: self.depth + 1,
            parent_fingerprint: fp,
            child_number: child.value(),
        })
    }

    pub fn public_key(&self) -> XPub {
        let secp = Secp256k1::new();
        let pk = PublicKey::from_secret_key(&secp, &self.secret);
        XPub {
            public_key: pk,
            chain_code: self.chain_code,
            depth: self.depth,
            parent_fingerprint: self.parent_fingerprint,
            child_number: self.child_number,
        }
    }

    pub fn secret_key(&self) -> &SecretKey {
        &self.secret
    }

    pub fn to_string(&self, prefix: Prefix) -> String {
        let secp = Secp256k1::new();
        let mut data = Vec::with_capacity(78);
        let ver = match prefix {
            Prefix::XPRV => 0x0488ade4u32,
            Prefix::XPUB => 0x0488b21eu32,
        };
        data.extend_from_slice(&ver.to_be_bytes());
        data.push(self.depth);
        data.extend_from_slice(&self.parent_fingerprint);
        data.extend_from_slice(&self.child_number.to_be_bytes());
        data.extend_from_slice(&self.chain_code);
        match prefix {
            Prefix::XPRV => {
                data.push(0u8);
                data.extend_from_slice(&self.secret.secret_bytes());
            }
            Prefix::XPUB => {
                let pk = PublicKey::from_secret_key(&secp, &self.secret);
                data.extend_from_slice(&pk.serialize());
            }
        }
        let checksum = Sha256::digest(Sha256::digest(&data));
        let mut out = data.clone();
        out.extend_from_slice(&checksum[..4]);
        bs58::encode(out).into_string()
    }
}

impl XPub {
    pub fn public_key(&self) -> PublicKey {
        self.public_key
    }
}
