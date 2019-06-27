extern crate rand;
extern crate base64;
extern crate chacha20_poly1305_aead;
extern crate miscreant;
extern crate ed25519_dalek;

use std::io;
use std::fmt;
use std::str::FromStr;

use rand::RngCore;
use miscreant::IV_SIZE; // 16
use miscreant::aead::{Aead, Aes256SivAead};


const KEY_SIZE: usize = 64;
const SKEY_SIZE: usize = KEY_SIZE + IV_SIZE * 2;


#[derive(Clone, Copy)]
pub struct Aes256Key {
    key:   [u8; KEY_SIZE],
    ad:    [u8; IV_SIZE],
    nonce: [u8; IV_SIZE],
}

impl fmt::Debug for Aes256Key {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "\"{}\"", self)
    }
}

impl fmt::Display for Aes256Key {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut skey  = [0u8; SKEY_SIZE];
        &mut skey[..KEY_SIZE].copy_from_slice(&self.key);
        (&mut skey[KEY_SIZE..KEY_SIZE + IV_SIZE]).copy_from_slice(&self.ad);
        (&mut skey[KEY_SIZE + IV_SIZE..]).copy_from_slice(&self.nonce);

        write!(f, "{}", base64::encode(&skey[..]))
    }
}

impl FromStr for Aes256Key {
    type Err = base64::DecodeError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let skey = base64::decode(s)?;
        if skey.len() != SKEY_SIZE {
            return Err(base64::DecodeError::InvalidLength);
        }
        
        let mut key   = [0u8; KEY_SIZE];
        let mut ad    = [0u8; IV_SIZE]; // IV_SIZE
        let mut nonce = [0u8; IV_SIZE]; // IV_SIZE
        key.copy_from_slice(&skey[..KEY_SIZE]);
        ad.copy_from_slice(&skey[KEY_SIZE..KEY_SIZE+IV_SIZE]);
        nonce.copy_from_slice(&skey[KEY_SIZE+IV_SIZE..KEY_SIZE+IV_SIZE+IV_SIZE]);

        Ok(Self { key, ad, nonce })
    }
}


pub struct AesSiv256 {
    key: Aes256Key,
    siv: Aes256SivAead,
}

impl AesSiv256 {    
    pub fn keygen() -> Aes256Key {
        let mut key   = [0u8; KEY_SIZE];
        let mut ad    = [0u8; IV_SIZE]; // IV_SIZE
        let mut nonce = [0u8; IV_SIZE]; // IV_SIZE

        let mut rng = rand::thread_rng();

        rng.fill_bytes(&mut key);
        rng.fill_bytes(&mut ad);
        rng.fill_bytes(&mut nonce);

        Aes256Key { key, ad, nonce }
    }

    pub fn new(key: Aes256Key) -> Self {
        let siv = Aes256SivAead::new(&key.key);
        Self { key, siv }
    }

    pub fn key(&self) -> Aes256Key {
        self.key
    }

    pub fn seal<T: AsRef<[u8]>>(&mut self, plaintext: T) -> Vec<u8> {
        self.siv.seal(&self.key.nonce, &self.key.ad, plaintext.as_ref())
    }

    pub fn open<T: AsRef<[u8]>>(&mut self, ciphertext: T) -> Result<Vec<u8>, io::Error> {
        self.siv.open(&self.key.nonce, &self.key.ad, ciphertext.as_ref())
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
    }
}


#[test]
fn test_seal() {
    let s = "dFtWlIRdXy1nHhJsETSw90ccnTmzbL2XP/EGfmr4vBI0ZVHWfEcnUl7a1+y8F2SDnsd2DzDStUiB+AVrq6U2relh1fFBrap+kDangv2IYzw87Q/b6e+mouhyaimvx7gG";
    let key = s.parse::<Aes256Key>().unwrap();
    let mut siv = AesSiv256::new(key);
    let plaintext = "吾乃万王之王是也，盖世功业，敢叫天公折服！".as_bytes();
    let ciphertext = siv.seal(&plaintext);
    assert_eq!(ciphertext,
        vec![44u8, 21, 224, 33, 54, 237, 98, 140, 205, 74, 43, 169, 52, 42, 232, 136, 121, 96, 
        66, 52, 175, 76, 133, 169, 158, 73, 231, 166, 200, 241, 150, 154, 192, 94, 198, 
        3, 240, 180, 126, 220, 12, 14, 46, 206, 148, 232, 118, 12, 13, 99, 51, 205, 207, 
        79, 93, 76, 74, 160, 181, 174, 246, 51, 130, 5, 80, 178, 6, 168, 127, 43, 210, 
        168, 240, 53, 135, 194, 129, 191, 253]);
}

#[test]
fn test_open() {
    let s = "dFtWlIRdXy1nHhJsETSw90ccnTmzbL2XP/EGfmr4vBI0ZVHWfEcnUl7a1+y8F2SDnsd2DzDStUiB+AVrq6U2relh1fFBrap+kDangv2IYzw87Q/b6e+mouhyaimvx7gG";
    let key = s.parse::<Aes256Key>().unwrap();
    let mut siv = AesSiv256::new(key);
    let ciphertext = vec![44, 21, 224, 33, 54, 237, 98, 140, 205, 74, 43, 169, 52, 42, 232, 136, 121, 96, 
        66, 52, 175, 76, 133, 169, 158, 73, 231, 166, 200, 241, 150, 154, 192, 94, 198, 
        3, 240, 180, 126, 220, 12, 14, 46, 206, 148, 232, 118, 12, 13, 99, 51, 205, 207, 
        79, 93, 76, 74, 160, 181, 174, 246, 51, 130, 5, 80, 178, 6, 168, 127, 43, 210, 
        168, 240, 53, 135, 194, 129, 191, 253];
    let plaintext = siv.open(&ciphertext).unwrap();
    assert_eq!(std::str::from_utf8(&plaintext), Ok("吾乃万王之王是也，盖世功业，敢叫天公折服！"));
}


