
use test;

use rand;
use openssl::{self, symm};
use openssl::error::ErrorStack;

use error::Error;

use std::fmt;



#[allow(non_camel_case_types)]
#[derive(Debug, Clone, Copy)]
pub enum Method {
    AES_128_ECB,
    AES_128_CBC,
    AES_128_XTS,
    AES_128_CTR,
    AES_128_CFB1,
    AES_128_CFB128,
    AES_128_CFB8,
    AES_128_GCM,
    AES_256_ECB,
    AES_256_CBC,
    AES_256_XTS,
    AES_256_CTR,
    AES_256_CFB1,
    AES_256_CFB128,
    AES_256_CFB8,
    AES_256_GCM,
    BF_CBC,
    BF_ECB,
    BF_CFB64,
    BF_OFB,
    DES_CBC,
    DES_ECB,
    RC4,
    // CHACHA20,
    // CHACHA20_POLY1305,
}

impl Method {
    pub fn cipher(&self) -> symm::Cipher {
        use self::Method::*;

        match *self {
            AES_128_ECB => symm::Cipher::aes_128_ecb(),
            AES_128_CBC => symm::Cipher::aes_128_cbc(),
            AES_128_XTS => symm::Cipher::aes_128_xts(),
            AES_128_CTR => symm::Cipher::aes_128_ctr(),
            AES_128_CFB1 => symm::Cipher::aes_128_cfb1(),
            AES_128_CFB128 => symm::Cipher::aes_128_cfb128(),
            AES_128_CFB8 => symm::Cipher::aes_128_cfb8(),
            AES_128_GCM => symm::Cipher::aes_128_gcm(),
            AES_256_ECB => symm::Cipher::aes_256_ecb(),
            AES_256_CBC => symm::Cipher::aes_256_cbc(),
            AES_256_XTS => symm::Cipher::aes_256_xts(),
            AES_256_CTR => symm::Cipher::aes_256_ctr(),
            AES_256_CFB1 => symm::Cipher::aes_256_cfb1(),
            AES_256_CFB128 => symm::Cipher::aes_256_cfb128(),
            AES_256_CFB8 => symm::Cipher::aes_256_cfb8(),
            AES_256_GCM => symm::Cipher::aes_256_gcm(),
            BF_CBC => symm::Cipher::bf_cbc(),
            BF_ECB => symm::Cipher::bf_ecb(),
            BF_CFB64 => symm::Cipher::bf_cfb64(),
            BF_OFB => symm::Cipher::bf_ofb(),
            DES_CBC => symm::Cipher::des_cbc(),
            DES_ECB => symm::Cipher::des_ecb(),
            RC4 => symm::Cipher::rc4(),
            // CHACHA20 => symm::Cipher::chacha20(),
            // CHACHA20_POLY1305 => symm::Cipher::chacha20_poly1305(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct Output {
    inner: Vec<u8>
}

impl Output {
    pub fn new() -> Output {
        Output { inner: Vec::new() }
    }

    pub fn len(&self) -> usize {
        self.inner.len()
    }

    pub fn ensure_size(&mut self, size: usize) {
        if self.inner.len() < size {
            self.inner.resize(size, 0u8);
        }
    }

    pub fn seek_to(&mut self, pos: usize) -> &mut [u8] {
        &mut self.inner[pos..]
    }

    pub fn range(&self, start: usize, end: usize) -> &[u8] {
        &self.inner[start..end]
    }
}



#[derive(Clone)]
pub struct Aes {
    method: Method,
    key_len: usize,
    iv_len: Option<usize>,
    block_size: usize,

    cipher: symm::Cipher,

    key: Vec<u8>,
    iv: Option<Vec<u8>>,
}

impl fmt::Debug for Aes {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "Aes {{ method: {:?}, key_len: {:?}, iv_len: {:?}, block_size: {}, key: {:?}, iv: {:?} }}",
            self.method,
            self.key_len,
            self.iv_len,
            self.block_size,
            self.key,
            self.iv)
    }
}

impl Aes {
    pub fn new(method: Method, _key: &[u8], _iv: &[u8]) -> Result<Aes, ErrorStack> {
        let cipher: symm::Cipher = method.cipher();
        let key_len = cipher.key_len();
        let iv_len = cipher.iv_len();
        let block_size = cipher.block_size();

        let mut key: Vec<u8> = vec![0u8; key_len];
        for idx in 0..key_len {
            if _key.len() > idx {
                key[idx] = _key[idx];
            } else {
                key[idx] = rand::random::<u8>();
            }
        }

        let iv: Option<Vec<u8>> = match iv_len {
            Some(size) => {
                let mut iv: Vec<u8> = vec![0u8; size];
                for idx in 0..size {
                    if _iv.len() > idx {
                        iv[idx] = _iv[idx];
                    } else {
                        iv[idx] = rand::random::<u8>();
                    }
                }
                Some(iv)
            }
            None => None
        };

        Ok(Aes {
            method: method,
            key_len: key_len,
            iv_len: iv_len,
            block_size: block_size,

            cipher: cipher,

            key: key,
            iv: iv,
        })
    }

    pub fn method(&self) -> Method {
        self.method
    }

    pub fn key(&self) -> &[u8] {
        &self.key[..]
    }

    pub fn iv(&mut self) -> Option<&[u8]> {
        match self.iv {
            Some(ref iv) => Some(&iv[..]),
            None => None
        }
    }

    pub fn block_size(&self) -> usize {
        self.block_size
    }

    pub fn encrypt(&mut self, input: &[u8], output: &mut Output) -> Result<usize, ErrorStack> {
        output.ensure_size(input.len() + self.block_size);

        let iv = match self.iv {
            Some(ref iv_) => Some(&iv_[..]),
            None => None,
        };

        match symm::Crypter::new(self.cipher, symm::Mode::Encrypt, &self.key, iv) {
            Ok(mut encrypter) => {
                encrypter.pad(true);
                let mut size = 0;
                match encrypter.update(input, &mut output.seek_to(0) ) {
                    Ok(amt) => { size += amt; }
                    Err(e) => return Err(e)
                };
                match encrypter.finalize(&mut output.seek_to(size) ) {
                    Ok(amt) => { size += amt; }
                    Err(e) => return Err(e)
                };
                Ok(size)
            }
            Err(e) => Err(e)
        }
    }

    pub fn decrypt(&mut self, input: &[u8], output: &mut Output) -> Result<usize, ErrorStack> {
        output.ensure_size(input.len() + self.block_size);
        
        let iv = match self.iv {
            Some(ref iv_) => Some(&iv_[..]),
            None => None,
        };

        match symm::Crypter::new(self.cipher, symm::Mode::Decrypt, &self.key, iv) {
            Ok(mut decrypter) => {
                decrypter.pad(true);
                let mut size = 0;
                match decrypter.update(input, &mut output.seek_to(0) ) {
                    Ok(amt) => { size += amt; }
                    Err(e) => return Err(e)
                };
                match decrypter.finalize(&mut output.seek_to(size) ) {
                    Ok(amt) => { size += amt; }
                    Err(e) => return Err(e)
                };
                Ok(size)
            }
            Err(e) => Err(e)
        }
    }
}

#[test]
fn test_aes_128_ecb() {
    let key = [73, 77, 80, 65, 83, 83, 87, 79, 82, 68, 121, 58, 65, 45, 51, 46];
    let iv = [];
    let mut aes = Aes::new(Method::AES_128_ECB, &key, &iv).unwrap();
    
    let input = "Hello, 世界！".as_bytes();
    let mut output = Output::new();

    let size = aes.encrypt(&input, &mut output).unwrap();

    assert_eq!(&output.range(0, size),
               &[24, 81, 44, 120, 55, 161, 223, 115, 74, 93, 72, 214, 45, 35, 172, 
                 124, 148, 132, 227, 154, 235, 252, 241, 245, 23, 135, 177, 114,
                 206, 186, 27, 245]);

    let input2 = &output.range(0, size).to_vec();
    let size2 = aes.decrypt(&input2,
                            &mut output).unwrap();

    assert_eq!(&output.range(0, size2),
               &input);
}

#[test]
fn test_aes_256_ecb() {
    let key = [73, 77, 80, 65, 83, 83, 87, 79, 82, 68, 12, 57, 163, 242, 12, 224, 78, 
               166, 163, 25, 253, 3, 101, 212, 237, 174, 40, 42, 62, 4, 118, 25];
    let iv = [];
    let mut aes = Aes::new(Method::AES_256_ECB, &key, &iv).unwrap();
    
    let input = "Hello, 世界！".as_bytes();
    let mut output = Output::new();

    let size = aes.encrypt(&input, &mut output).unwrap();

    assert_eq!(&output.range(0, size),
               &[207, 239, 14, 41, 204, 100, 239, 24, 45, 53, 210, 145, 57, 234, 65, 
                 179, 230, 211, 35, 133, 151, 16, 46, 203, 118, 40, 13, 241, 233, 
                 253, 140, 48]);

    let input2 = &output.range(0, size).to_vec();
    let size2 = aes.decrypt(&input2,
                            &mut output).unwrap();

    assert_eq!(&output.range(0, size2),
               &input);
}

#[test]
fn test_aes_128_cbc() {
    let key = [73, 77, 80, 65, 83, 83, 87, 79, 82, 68, 35, 142, 93, 207, 52, 190];
    let iv = [73, 86, 32, 67, 79, 68, 69, 138, 176, 11, 36, 143, 175, 146, 69, 40];
    let mut aes = Aes::new(Method::AES_128_CBC, &key, &iv).unwrap();
    
    let input = "Hello, 世界！".as_bytes();
    let mut output = Output::new();

    let size = aes.encrypt(&input, &mut output).unwrap();

    assert_eq!(&output.range(0, size),
               &[182, 64, 139, 210, 40, 243, 31, 73, 213, 175, 48, 2, 108, 254, 136,
                 9, 88, 220, 255, 20, 11, 48, 5, 42, 42, 55, 9, 142, 88, 181, 16, 239]);

    let input2 = &output.range(0, size).to_vec();
    let size2 = aes.decrypt(&input2,
                            &mut output).unwrap();

    assert_eq!(&output.range(0, size2),
               &input);
}

#[test]
fn test_aes_256_cbc() {
    let key = [73, 77, 80, 65, 83, 83, 87, 79, 82, 68, 235, 142, 167, 113, 73, 201, 
               192, 151, 255, 25, 135, 240, 111, 210, 37, 195, 180, 79, 45, 243, 
               87, 251];
    let iv = [73, 86, 32, 67, 79, 68, 69, 96, 110, 235, 73, 101, 156, 162, 64, 33];
    let mut aes = Aes::new(Method::AES_256_CBC, &key, &iv).unwrap();
    
    let input = "Hello, 世界！".as_bytes();
    let mut output = Output::new();

    let size = aes.encrypt(&input, &mut output).unwrap();

    assert_eq!(&output.range(0, size),
               &[254, 117, 99, 81, 126, 75, 21, 111, 217, 254, 124, 194, 255, 130, 161,
                 15, 107, 222, 251, 16, 108, 191, 148, 80, 72, 130, 160, 134, 22, 155, 
                 29, 116]);

    let input2 = &output.range(0, size).to_vec();
    let size2 = aes.decrypt(&input2,
                            &mut output).unwrap();

    assert_eq!(&output.range(0, size2),
               &input);
}

#[bench]
fn bench_aes_128_ecb_encrypt(b: &mut test::Bencher) {
    let mut aes = Aes::new(Method::AES_128_ECB,
                           "IMPASSWORD".as_bytes(),
                           "IV CODE".as_bytes()).unwrap();
    
    let mut input = [0u8; 1500];
    let mut output = Output::new();

    openssl::rand::rand_bytes(&mut input).unwrap();

    b.iter(|| {
        aes.encrypt(&input, &mut output).unwrap();
    });
}

#[bench]
fn bench_aes_128_ecb_decrypt(b: &mut test::Bencher) {
    let mut aes = Aes::new(Method::AES_128_ECB,
                          "IMPASSWORD".as_bytes(),
                          "IV CODE".as_bytes()).unwrap();
    
    let mut input = [0u8; 1500];
    let mut output = Output::new();

    openssl::rand::rand_bytes(&mut input).unwrap();

    let size = aes.encrypt(&input, &mut output).unwrap();

    let sinput = &output.range(0, size).to_vec();

    b.iter(|| {
        aes.decrypt(&sinput, &mut output).unwrap();
    });
}

#[bench]
fn bench_aes_128_cbc_encrypt(b: &mut test::Bencher) {
    let mut aes = Aes::new(Method::AES_128_CBC,
                          "IMPASSWORD".as_bytes(),
                          "IV CODE".as_bytes()).unwrap();
    
    let mut input = [0u8; 1500];
    let mut output = Output::new();

    openssl::rand::rand_bytes(&mut input).unwrap();

    b.iter(|| {
        aes.encrypt(&input, &mut output).unwrap();
    });
}

#[bench]
fn bench_aes_128_cbc_decrypt(b: &mut test::Bencher) {
    let mut aes = Aes::new(Method::AES_128_CBC,
                          "IMPASSWORD".as_bytes(),
                          "IV CODE".as_bytes()).unwrap();
    
    let mut input = [0u8; 1500];
    let mut output = Output::new();

    openssl::rand::rand_bytes(&mut input).unwrap();

    let size = aes.encrypt(&input, &mut output).unwrap();

    let sinput = &output.range(0, size).to_vec();

    b.iter(|| {
        aes.decrypt(&sinput, &mut output).unwrap();
    });
}

#[bench]
fn bench_aes_256_ecb_encrypt(b: &mut test::Bencher) {
    let mut aes = Aes::new(Method::AES_256_ECB,
                          "IMPASSWORD".as_bytes(),
                          "IV CODE".as_bytes()).unwrap();
    
    let mut input = [0u8; 1500];
    let mut output = Output::new();

    openssl::rand::rand_bytes(&mut input).unwrap();

    b.iter(|| {
        aes.encrypt(&input, &mut output).unwrap();
    });
}

#[bench]
fn bench_aes_256_ecb_decrypt(b: &mut test::Bencher) {
    let mut aes = Aes::new(Method::AES_256_ECB,
                          "IMPASSWORD".as_bytes(),
                          "IV CODE".as_bytes()).unwrap();
    
    let mut input = [0u8; 1500];
    let mut output = Output::new();

    openssl::rand::rand_bytes(&mut input).unwrap();

    let size = aes.encrypt(&input, &mut output).unwrap();

    let sinput = &output.range(0, size).to_vec();

    b.iter(|| {
        aes.decrypt(&sinput, &mut output).unwrap();
    });
}

#[bench]
fn bench_aes_256_cbc_encrypt(b: &mut test::Bencher) {
    let mut aes = Aes::new(Method::AES_256_CBC,
                           "IMPASSWORD".as_bytes(),
                           "IV CODE".as_bytes()).unwrap();
    
    let mut input = [0u8; 1500];
    let mut output = Output::new();

    openssl::rand::rand_bytes(&mut input).unwrap();

    b.iter(|| {
        aes.encrypt(&input, &mut output).unwrap();
    });
}

#[bench]
fn bench_aes_256_cbc_decrypt(b: &mut test::Bencher) {
    let mut aes = Aes::new(Method::AES_256_CBC,
                          "IMPASSWORD".as_bytes(),
                          "IV CODE".as_bytes()).unwrap();
    
    let mut input = [0u8; 1500];
    let mut output = Output::new();

    openssl::rand::rand_bytes(&mut input).unwrap();

    let size = aes.encrypt(&input, &mut output).unwrap();

    let sinput = &output.range(0, size).to_vec();

    b.iter(|| {
        aes.decrypt(&sinput, &mut output).unwrap();
    });
}
