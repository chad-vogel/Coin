use pbkdf2::pbkdf2_hmac;
use rand::RngCore;
use sha2::Sha512;

#[derive(Debug)]
pub enum Error {
    InvalidWord(String),
}

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Clone, Copy)]
pub enum Language {
    English,
}

impl Default for Language {
    fn default() -> Self {
        Language::English
    }
}

#[derive(Clone)]
pub struct Mnemonic {
    phrase: String,
}

impl Mnemonic {
    pub fn new(phrase: &str, _lang: Language) -> Result<Self> {
        for w in phrase.split_whitespace() {
            if !WORDLIST.contains(&w) {
                return Err(Error::InvalidWord(w.to_string()));
            }
        }
        Ok(Mnemonic {
            phrase: phrase.to_string(),
        })
    }

    pub fn random<R: RngCore>(rng: &mut R, _lang: Language) -> Self {
        let mut words = Vec::with_capacity(24);
        for _ in 0..24 {
            let idx = (rng.next_u32() as usize) % WORDLIST.len();
            words.push(WORDLIST[idx]);
        }
        Mnemonic {
            phrase: words.join(" "),
        }
    }

    pub fn to_seed(&self, password: &str) -> Vec<u8> {
        let salt = format!("mnemonic{}", password);
        let mut seed = [0u8; 64];
        pbkdf2_hmac::<Sha512>(self.phrase.as_bytes(), salt.as_bytes(), 2048, &mut seed);
        seed.to_vec()
    }

    pub fn phrase(&self) -> &str {
        &self.phrase
    }
}

const WORDLIST: [&str; 2048] = include!("wordlist.in");
