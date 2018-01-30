

use test;

use openssl::{self, pkey};
use openssl::rsa::{Rsa, Padding};
use openssl::error::ErrorStack;

use error::Error;

use std::str;
use std::io;
use std::io::Read;
use std::io::Write;
use std::fs::File;
use std::fs::OpenOptions;



fn read_file(filename: &str) -> Result<Vec<u8>, io::Error> {
    match File::open(filename) {
        Ok(mut file) => {
            let mut data: Vec<u8> = vec![];
            match file.read_to_end(&mut data) {
                Ok(_) => Ok(data),
                Err(e) => Err(e)
            }
        }
        Err(e) => Err(e)
    }
}

#[allow(dead_code)]
fn write_file(filename: &str, data: &[u8]) -> Result<(), io::Error> {
    match OpenOptions::new().create(true).write(true).append(false).open(filename) {
        Ok(mut file) => {
            match file.write(&data) {
                Ok(_) => Ok(()),
                Err(e) => Err(e)
            }
        }
        Err(e) => Err(e)
    }
}


#[derive(Debug)]
pub enum Key {
    Public(PubKey),
    Private(PriKey)
}

#[derive(Debug)]
pub struct PubKey {
    inner: Rsa<pkey::Public>
}

#[derive(Debug)]
pub struct PriKey {
    inner: Rsa<pkey::Private>
}

impl PubKey {
    pub fn from_file(filename: &str) -> Result<PubKey, Error>{
        match read_file(filename) {
            Ok(bytes) => PubKey::from_pem(&bytes),
            Err(e) => Err(Error::Io(e))
        }
    }

    pub fn from_pem(pem_bytes: &[u8]) -> Result<PubKey, Error> {
        match Rsa::public_key_from_pem(&pem_bytes){
            Ok(rsa) => Ok(PubKey { inner: rsa}),
            Err(e) => Err(Error::OpenSsl(e))
        }
    }

    pub fn to_pem(&self) -> Vec<u8> {
        match self.inner.public_key_to_pem() {
            Ok(pem_bytes) => pem_bytes,
            Err(_) => unreachable!()
        }
    }

    pub fn from_der(der: &[u8]) -> Result<PubKey, ErrorStack> {
        match Rsa::public_key_from_der(der) {
            Ok(rsa) => Ok(PubKey { inner: rsa }),
            Err(e) => Err(e)
        }
    }

    pub fn to_der(&self) -> Vec<u8> {
        match self.inner.public_key_to_der() {
            Ok(der_bytes) => der_bytes,
            Err(_) => unreachable!()
        }
    }

    pub fn size(&self) -> usize {
        self.inner.size() as usize
    }

    pub fn encrypt(&self, input: &[u8], output: &mut [u8]) -> Result<usize, ErrorStack> {
        self.inner.public_encrypt(input, output, Padding::PKCS1)
    }
    
    pub fn decrypt(&self, input: &[u8], output: &mut [u8]) -> Result<usize, ErrorStack> {
        self.inner.public_decrypt(input, output, Padding::PKCS1)
    }
}

impl PriKey {
    pub fn gen(bits: u32) -> Result<PriKey, io::Error> {
        match Rsa::generate(bits) {
            Ok(rsa) => Ok(PriKey { inner: rsa}),
            Err(_) => Err(io::Error::new(io::ErrorKind::Other, "Ooops ..."))
        }
    }

    pub fn from_file(filename: &str) -> Result<PriKey, Error>{
        match read_file(filename) {
            Ok(bytes) => PriKey::from_pem(&bytes),
            Err(e) => Err(Error::Io(e))
        }
    }

    pub fn from_pem(pem_bytes: &[u8]) -> Result<PriKey, Error>{
        match Rsa::private_key_from_pem(&pem_bytes){
            Ok(rsa) => Ok(PriKey { inner: rsa}),
            Err(e) => Err(Error::OpenSsl(e))
        }
    }

    pub fn to_pem(&self) -> Vec<u8> {
        match self.inner.private_key_to_pem() {
            Ok(pem_bytes) => pem_bytes,
            Err(_) => unreachable!()
        }
    }

    pub fn from_der(der: &[u8]) -> Result<PriKey, ErrorStack> {
        match Rsa::private_key_from_der(der) {
            Ok(rsa) => Ok(PriKey { inner: rsa }),
            Err(e) => Err(e)
        }
    }

    pub fn to_der(&self) -> Vec<u8> {
        match self.inner.private_key_to_der() {
            Ok(der_bytes) => der_bytes,
            Err(_) => unreachable!()
        }
    }

    pub fn pubkey(&self) -> PubKey {
        match self.inner.public_key_to_der() {
            Ok(pub_der_bytes) => PubKey::from_der(&pub_der_bytes).unwrap(),
            Err(_) => unreachable!()
        }
    }

    pub fn size(&self) -> usize {
        self.inner.size() as usize
    }

    pub fn encrypt(&self, input: &[u8], output: &mut [u8]) -> Result<usize, ErrorStack> {
        self.inner.private_encrypt(input, output, Padding::PKCS1)
    }

    pub fn decrypt(&self, input: &[u8], output: &mut [u8]) -> Result<usize, ErrorStack> {
        self.inner.private_decrypt(input, output, Padding::PKCS1)
    }
}

#[test]
fn test_rsa_key_gen() {
    let key_bits: usize = 1024 * 4;

    let prikey_ = PriKey::gen(key_bits as u32);
    assert!(prikey_.is_ok());

    let prikey = prikey_.unwrap();
    let pubkey = prikey.pubkey();

    assert_eq!(prikey.size(), key_bits / 8);
    assert_eq!(pubkey.size(), key_bits / 8);

    assert_eq!(prikey.size(), pubkey.size());
}

#[test]
fn test_rsa_key_parse() {
    let pri_key_pem = b"-----BEGIN RSA PRIVATE KEY-----
MIICXgIBAAKBgQDCWa7l2OrSWYv2Yg1UHsI5T4yDc/QraCYqdJwkb+771JkXuiUh
6AAl4bv/64NokaHLZvAje5BPAeqK1TkfiY/SiKdpX6AViuWPUuahihyD3uvISOXw
S0CvW2Czhdaua1MSKXJWxw4O8aTkkXe0f+NQUwU10l92uEDpxRMApuEKMwIDAQAB
AoGAc9y/VatRooFb3VBrHcEQjNYNsLhJ0i7OwfSuuVI5qMv/UJPaWzJSFENUrqca
uhZH3FjLxHt/dnpv9sBSw6hgollhpPPbwuWqzFjIbLUIlUZffsTYiVfypqYjujgY
wQgoVQyia2XZT+bHkUfFZzbVmk9WGBqrGcdyRj2+04MP1FECQQD0XUjkPcdULs0I
o0neaCvChIZgfZLwl4JKcAottNhON/XDaZZAOODp0hsL5tb7e1cBy7RcxyUsvw4h
OKm5LOcFAkEAy5q+pUnBaFs/tGSQ8RXXTHq5OUf+rsej+Q+WEYSL7A8qJvOj5CWD
Xh8HpGxFQ/OzntPytH1VQ1o+m0Mn23QB1wJBAOKdtCB+rmECegCdtb586sAcuKW5
LtDSIPE5UCctBEAdo1wSilWKqgINaCm0bQCRVJIEwIId6PrDP65NZxCkdKUCQQCr
jKfDdsCKIBAt+2oQZ9mu69xywhF5zGaBbLuB6Q9IB4L5rOFTUrQ8MqLqy/sUhRq7
4VMm9k9H35rOkSfdBQKjAkEAgTjfHNdYAR4gSG8LdjJxAdXfiYmXMMZ96xk0h81i
TwctwMd5KmHFCFAkXqZ2o6TYAfvLRLR7flfrlymK9fXe3A==
-----END RSA PRIVATE KEY-----";
    let pub_key_pem = b"-----BEGIN PUBLIC KEY-----
MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDCWa7l2OrSWYv2Yg1UHsI5T4yD
c/QraCYqdJwkb+771JkXuiUh6AAl4bv/64NokaHLZvAje5BPAeqK1TkfiY/SiKdp
X6AViuWPUuahihyD3uvISOXwS0CvW2Czhdaua1MSKXJWxw4O8aTkkXe0f+NQUwU1
0l92uEDpxRMApuEKMwIDAQAB
-----END PUBLIC KEY-----";
    
    let prikey_ = PriKey::from_pem(pri_key_pem);
    assert!(prikey_.is_ok());
    let prikey = prikey_.unwrap();

    let pubkey = prikey.pubkey();
    let pubkey_ = PubKey::from_pem(pub_key_pem);
    assert!(pubkey_.is_ok());

    assert_eq!(pubkey_.unwrap().to_der(), pubkey.to_der());

    assert_eq!(prikey.size(), 128);
    assert_eq!(prikey.size(), pubkey.size());
}

#[test]
fn test_rsa_pubencrypt_and_pridecrypt() {
    let pri_key_pem = b"-----BEGIN RSA PRIVATE KEY-----
MIICXgIBAAKBgQDCWa7l2OrSWYv2Yg1UHsI5T4yDc/QraCYqdJwkb+771JkXuiUh
6AAl4bv/64NokaHLZvAje5BPAeqK1TkfiY/SiKdpX6AViuWPUuahihyD3uvISOXw
S0CvW2Czhdaua1MSKXJWxw4O8aTkkXe0f+NQUwU10l92uEDpxRMApuEKMwIDAQAB
AoGAc9y/VatRooFb3VBrHcEQjNYNsLhJ0i7OwfSuuVI5qMv/UJPaWzJSFENUrqca
uhZH3FjLxHt/dnpv9sBSw6hgollhpPPbwuWqzFjIbLUIlUZffsTYiVfypqYjujgY
wQgoVQyia2XZT+bHkUfFZzbVmk9WGBqrGcdyRj2+04MP1FECQQD0XUjkPcdULs0I
o0neaCvChIZgfZLwl4JKcAottNhON/XDaZZAOODp0hsL5tb7e1cBy7RcxyUsvw4h
OKm5LOcFAkEAy5q+pUnBaFs/tGSQ8RXXTHq5OUf+rsej+Q+WEYSL7A8qJvOj5CWD
Xh8HpGxFQ/OzntPytH1VQ1o+m0Mn23QB1wJBAOKdtCB+rmECegCdtb586sAcuKW5
LtDSIPE5UCctBEAdo1wSilWKqgINaCm0bQCRVJIEwIId6PrDP65NZxCkdKUCQQCr
jKfDdsCKIBAt+2oQZ9mu69xywhF5zGaBbLuB6Q9IB4L5rOFTUrQ8MqLqy/sUhRq7
4VMm9k9H35rOkSfdBQKjAkEAgTjfHNdYAR4gSG8LdjJxAdXfiYmXMMZ96xk0h81i
TwctwMd5KmHFCFAkXqZ2o6TYAfvLRLR7flfrlymK9fXe3A==
-----END RSA PRIVATE KEY-----";
    let pub_key_pem = b"-----BEGIN PUBLIC KEY-----
MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDCWa7l2OrSWYv2Yg1UHsI5T4yD
c/QraCYqdJwkb+771JkXuiUh6AAl4bv/64NokaHLZvAje5BPAeqK1TkfiY/SiKdp
X6AViuWPUuahihyD3uvISOXwS0CvW2Czhdaua1MSKXJWxw4O8aTkkXe0f+NQUwU1
0l92uEDpxRMApuEKMwIDAQAB
-----END PUBLIC KEY-----";

    let prikey_ = PriKey::from_pem(pri_key_pem);
    assert!(prikey_.is_ok());
    let prikey = prikey_.unwrap();

    let pubkey = prikey.pubkey();
    let pubkey_ = PubKey::from_pem(pub_key_pem);
    assert!(pubkey_.is_ok());

    assert_eq!(prikey.size(), 128);
    assert_eq!(pubkey.size(), 128);

    let input = [44, 1, 35, 253, 135, 0, 173, 39, 34, 203, 182, 241,
    172, 144, 79, 25, 181, 97, 20, 128, 160, 248, 22, 142, 140, 240,
    116, 14, 28, 173, 218, 186, 164, 194, 160, 146, 236, 255, 16,
    142, 214, 239, 252, 3, 46, 135, 201, 142, 12, 172, 17, 176, 213,
    179, 210, 1, 226, 65, 109, 97, 89, 14, 194, 8, 66, 235, 91, 9,
    147, 171, 51, 112, 191, 205, 105, 111, 161, 109, 233, 64, 193,
    89, 76, 249, 46, 109, 114, 135, 151, 150, 68, 86, 68, 175, 230,
    204, 22, 76, 22, 134, 96, 144, 117, 102, 174, 225, 133, 16, 26,
    88, 196, 11];

    let mut ciphertext: Vec<u8> = vec![0u8; pubkey.size()];
    assert!(pubkey.encrypt(&input, &mut ciphertext).is_ok());

    let mut plaintext: Vec<u8> = vec![0u8; prikey.size()];
    let ret = prikey.decrypt(&ciphertext, &mut plaintext);
    assert!(ret.is_ok());

    let size = ret.unwrap();
    assert_eq!(&plaintext[..size],
               &input[..]);
}

#[test]
fn test_rsa_priencrypt_and_pubdecrypt() {
    let pri_key_pem = b"-----BEGIN RSA PRIVATE KEY-----
MIICXgIBAAKBgQDCWa7l2OrSWYv2Yg1UHsI5T4yDc/QraCYqdJwkb+771JkXuiUh
6AAl4bv/64NokaHLZvAje5BPAeqK1TkfiY/SiKdpX6AViuWPUuahihyD3uvISOXw
S0CvW2Czhdaua1MSKXJWxw4O8aTkkXe0f+NQUwU10l92uEDpxRMApuEKMwIDAQAB
AoGAc9y/VatRooFb3VBrHcEQjNYNsLhJ0i7OwfSuuVI5qMv/UJPaWzJSFENUrqca
uhZH3FjLxHt/dnpv9sBSw6hgollhpPPbwuWqzFjIbLUIlUZffsTYiVfypqYjujgY
wQgoVQyia2XZT+bHkUfFZzbVmk9WGBqrGcdyRj2+04MP1FECQQD0XUjkPcdULs0I
o0neaCvChIZgfZLwl4JKcAottNhON/XDaZZAOODp0hsL5tb7e1cBy7RcxyUsvw4h
OKm5LOcFAkEAy5q+pUnBaFs/tGSQ8RXXTHq5OUf+rsej+Q+WEYSL7A8qJvOj5CWD
Xh8HpGxFQ/OzntPytH1VQ1o+m0Mn23QB1wJBAOKdtCB+rmECegCdtb586sAcuKW5
LtDSIPE5UCctBEAdo1wSilWKqgINaCm0bQCRVJIEwIId6PrDP65NZxCkdKUCQQCr
jKfDdsCKIBAt+2oQZ9mu69xywhF5zGaBbLuB6Q9IB4L5rOFTUrQ8MqLqy/sUhRq7
4VMm9k9H35rOkSfdBQKjAkEAgTjfHNdYAR4gSG8LdjJxAdXfiYmXMMZ96xk0h81i
TwctwMd5KmHFCFAkXqZ2o6TYAfvLRLR7flfrlymK9fXe3A==
-----END RSA PRIVATE KEY-----";
    let pub_key_pem = b"-----BEGIN PUBLIC KEY-----
MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDCWa7l2OrSWYv2Yg1UHsI5T4yD
c/QraCYqdJwkb+771JkXuiUh6AAl4bv/64NokaHLZvAje5BPAeqK1TkfiY/SiKdp
X6AViuWPUuahihyD3uvISOXwS0CvW2Czhdaua1MSKXJWxw4O8aTkkXe0f+NQUwU1
0l92uEDpxRMApuEKMwIDAQAB
-----END PUBLIC KEY-----";

    let prikey_ = PriKey::from_pem(pri_key_pem);
    assert!(prikey_.is_ok());
    let prikey = prikey_.unwrap();

    let pubkey = prikey.pubkey();
    let pubkey_ = PubKey::from_pem(pub_key_pem);
    assert!(pubkey_.is_ok());

    assert_eq!(prikey.size(), 128);
    assert_eq!(pubkey.size(), 128);

    let input = [44, 1, 35, 253, 135, 0, 173, 39, 34, 203, 182, 241,
    172, 144, 79, 25, 181, 97, 20, 128, 160, 248, 22, 142, 140, 240,
    116, 14, 28, 173, 218, 186, 164, 194, 160, 146, 236, 255, 16,
    142, 214, 239, 252, 3, 46, 135, 201, 142, 12, 172, 17, 176, 213,
    179, 210, 1, 226, 65, 109, 97, 89, 14, 194, 8, 66, 235, 91, 9,
    147, 171, 51, 112, 191, 205, 105, 111, 161, 109, 233, 64, 193,
    89, 76, 249, 46, 109, 114, 135, 151, 150, 68, 86, 68, 175, 230,
    204, 22, 76, 22, 134, 96, 144, 117, 102, 174, 225, 133, 16, 26,
    88, 196, 11];

    let mut ciphertext: Vec<u8> = vec![0u8; pubkey.size()];
    assert!(prikey.encrypt(&input, &mut ciphertext).is_ok());

    let mut plaintext: Vec<u8> = vec![0u8; prikey.size()];
    let ret = pubkey.decrypt(&ciphertext, &mut plaintext);
    assert!(ret.is_ok());

    let size = ret.unwrap();
    assert_eq!(&plaintext[..size],
               &input[..]);
}

#[bench]
fn bench_rsa_2048_pubkey_encrypt(b: &mut test::Bencher) {
    let prikey = PriKey::gen(2048).unwrap();
    let pubkey = prikey.pubkey();

    let mut input = vec![0u8; pubkey.size() - 16];
    openssl::rand::rand_bytes(&mut input).unwrap();
    
    let mut ciphertext: Vec<u8> = vec![0u8; pubkey.size()];

    b.iter(|| {
        pubkey.encrypt(&input, &mut ciphertext).unwrap();
    });
}

#[bench]
fn bench_rsa_2048_prikey_decrypt(b: &mut test::Bencher) {
    let prikey = PriKey::gen(2048).unwrap();
    let pubkey = prikey.pubkey();

    let mut input = vec![0u8; pubkey.size() - 16];
    openssl::rand::rand_bytes(&mut input).unwrap();
    
    let mut ciphertext: Vec<u8> = vec![0u8; pubkey.size()];
    pubkey.encrypt(&input, &mut ciphertext).unwrap();

    let mut plaintext: Vec<u8> = vec![0u8; pubkey.size()];
    b.iter(|| {
        prikey.decrypt(&ciphertext, &mut plaintext).unwrap();
    });
}

#[bench]
fn bench_rsa_4096_pubkey_encrypt(b: &mut test::Bencher) {
    let prikey = PriKey::gen(4096).unwrap();
    let pubkey = prikey.pubkey();

    let mut input = vec![0u8; pubkey.size() - 16];
    openssl::rand::rand_bytes(&mut input).unwrap();
    
    let mut ciphertext: Vec<u8> = vec![0u8; pubkey.size()];

    b.iter(|| {
        pubkey.encrypt(&input, &mut ciphertext).unwrap();
    });
}

#[bench]
fn bench_rsa_4096_prikey_decrypt(b: &mut test::Bencher) {
    let prikey = PriKey::gen(4096).unwrap();
    let pubkey = prikey.pubkey();

    let mut input = vec![0u8; pubkey.size() - 16];
    openssl::rand::rand_bytes(&mut input).unwrap();
    
    let mut ciphertext: Vec<u8> = vec![0u8; pubkey.size()];
    pubkey.encrypt(&input, &mut ciphertext).unwrap();

    let mut plaintext: Vec<u8> = vec![0u8; pubkey.size()];
    b.iter(|| {
        prikey.decrypt(&ciphertext, &mut plaintext).unwrap();
    });
}

#[bench]
fn bench_rsa_8192_pubkey_encrypt(b: &mut test::Bencher) {
    let prikey = PriKey::gen(8192).unwrap();
    let pubkey = prikey.pubkey();

    let mut input = vec![0u8; pubkey.size() - 16];
    openssl::rand::rand_bytes(&mut input).unwrap();
    
    let mut ciphertext: Vec<u8> = vec![0u8; pubkey.size()];

    b.iter(|| {
        pubkey.encrypt(&input, &mut ciphertext).unwrap();
    });
}

#[bench]
fn bench_rsa_8192_prikey_decrypt(b: &mut test::Bencher) {
    let prikey = PriKey::gen(8192).unwrap();
    let pubkey = prikey.pubkey();

    let mut input = vec![0u8; pubkey.size() - 16];
    openssl::rand::rand_bytes(&mut input).unwrap();
    
    let mut ciphertext: Vec<u8> = vec![0u8; pubkey.size()];
    pubkey.encrypt(&input, &mut ciphertext).unwrap();

    let mut plaintext: Vec<u8> = vec![0u8; pubkey.size()];
    b.iter(|| {
        prikey.decrypt(&ciphertext, &mut plaintext).unwrap();
    });
}

