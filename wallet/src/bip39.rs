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

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::mock::StepRng;

    #[test]
    fn random_produces_expected_phrase() {
        // StepRng with zero increment yields the same value on each call
        let mut rng = StepRng::new(1, 0);
        let m = Mnemonic::random(&mut rng, Language::English);
        let expected_word = WORDLIST[1];
        let expected = std::iter::repeat(expected_word)
            .take(24)
            .collect::<Vec<_>>()
            .join(" ");
        assert_eq!(m.phrase(), expected);
    }

    #[test]
    fn phrase_returns_input() {
        let phrase = "abandon ability ability ability ability ability ability ability ability ability ability ability ability ability ability ability ability ability ability ability ability ability ability art";
        let m = Mnemonic::new(phrase, Language::English).unwrap();
        assert_eq!(m.phrase(), phrase);
    }

    #[test]
    fn invalid_word_fails() {
        let res = Mnemonic::new("abandon foobar", Language::English);
        assert!(matches!(res, Err(Error::InvalidWord(ref w)) if w == "foobar"));
    }
}
