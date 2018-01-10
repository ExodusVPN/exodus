use openssl;
use rand;


use std::io;
use std::io::Read;
use std::io::Write;

use std::fs::File;
use std::fs::OpenOptions;

use std::str::FromStr;
use std::string::ToString;
use std::str;



pub fn read_file(filename: &str) -> Result<Vec<u8>, io::Error> {
    match File::open(filename) {
        Ok(mut file) => {
            let mut data: Vec<u8> = vec![];
            match file.read_to_end(&mut data) {
                Ok(amt) => Ok(data),
                Err(e) => Err(e)
            }
        }
        Err(e) => Err(e)
    }
}

pub fn write_file(filename: &str, data: &[u8]) -> Result<(), io::Error> {
    match OpenOptions::new().create(true).write(true).append(false).open(filename) {
        Ok(mut file) => {
            match file.write(&data) {
                Ok(amt) => Ok(()),
                Err(e) => Err(e)
            }
        }
        Err(e) => Err(e)
    }
}

#[allow(non_snake_case)]
pub mod rsa {
    use super::{io, Read, Write, read_file, write_file, openssl};

    use openssl::rsa::Rsa;
    use openssl::rsa::{NO_PADDING, PKCS1_OAEP_PADDING, PKCS1_PADDING};
    use openssl::error::ErrorStack;


    #[derive(Debug)]
    pub enum Key {
        Public(PubKey),
        Private(PriKey)
    }

    #[derive(Debug)]
    pub struct PubKey {
        inner: Rsa
    }

    #[derive(Debug)]
    pub struct PriKey {
        inner: Rsa
    }

    impl PubKey {
        pub fn from_file(filename: &str) -> Result<PubKey, io::Error>{
            match read_file(filename) {
                Ok(bytes) => match Rsa::public_key_from_pem(&bytes){
                    Ok(rsa) => Ok(PubKey { inner: rsa}),
                    Err(e) => Err(io::Error::new(io::ErrorKind::Other, "Ooops ..."))
                }
                Err(e) => Err(e)
            }
        }

        pub fn from_bytes(der: &[u8]) -> Result<PubKey, ErrorStack> {
            match Rsa::public_key_from_der(der) {
                Ok(rsa) => Ok(PubKey { inner: rsa }),
                Err(e) => Err(e)
            }
        }

        pub fn to_bytes(&self) -> Vec<u8> {
            self.inner.public_key_to_der().unwrap()
        }

        pub fn to_pem(&self) -> Vec<u8> {
            match self.inner.public_key_to_pem() {
                Ok(pem_bytes) => pem_bytes,
                Err(_) => unreachable!()
            }
        }

        pub fn to_der(&self) -> Vec<u8> {
            match self.inner.public_key_to_der() {
                Ok(der_bytes) => der_bytes,
                Err(_) => unreachable!()
            }
        }

        pub fn size(&self) -> usize {
            self.inner.size()
        }

        pub fn encrypt(&self, input: &[u8], output: &mut [u8]) -> Result<usize, ErrorStack> {
            self.inner.public_encrypt(input, output, PKCS1_PADDING)
        }
        
        pub fn decrypt(&self, input: &[u8], output: &mut [u8]) -> Result<usize, ErrorStack> {
            self.inner.public_decrypt(input, output, PKCS1_PADDING)
        }
    }

    impl PriKey {
        pub fn gen(bits: u32) -> Result<PriKey, io::Error> {
            match Rsa::generate(bits) {
                Ok(rsa) => Ok(PriKey { inner: rsa}),
                Err(e) => Err(io::Error::new(io::ErrorKind::Other, "Ooops ..."))
            }
        }

        pub fn from_file(filename: &str) -> Result<PriKey, io::Error>{
            match read_file(filename) {
                Ok(bytes) => match Rsa::private_key_from_pem(&bytes){
                    Ok(rsa) => Ok(PriKey { inner: rsa}),
                    Err(e) => Err(io::Error::new(io::ErrorKind::Other, "Ooops ..."))
                }
                Err(e) => Err(e)
            }
        }

        pub fn from_bytes(der: &[u8]) -> Result<PriKey, ErrorStack> {
            match Rsa::private_key_from_der(der) {
                Ok(rsa) => Ok(PriKey { inner: rsa }),
                Err(e) => Err(e)
            }
        }

        pub fn to_bytes(&self) -> Vec<u8> {
            self.inner.private_key_to_der().unwrap()
        }

        pub fn to_pem(&self) -> Vec<u8> {
            match self.inner.private_key_to_pem() {
                Ok(pem_bytes) => pem_bytes,
                Err(_) => unreachable!()
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
                Ok(pub_der_bytes) => PubKey::from_bytes(&pub_der_bytes).unwrap(),
                Err(_) => unreachable!()
            }
        }

        pub fn size(&self) -> usize {
            self.inner.size()
        }

        pub fn encrypt(&self, input: &[u8], output: &mut [u8]) -> Result<usize, ErrorStack> {
            self.inner.private_encrypt(input, output, PKCS1_PADDING)
        }

        pub fn decrypt(&self, input: &[u8], output: &mut [u8]) -> Result<usize, ErrorStack> {
            self.inner.private_decrypt(input, output, PKCS1_PADDING)
        }
    }
}

#[allow(non_snake_case)]
pub mod aes {
    use super::{io, Read, Write, read_file, write_file, openssl, rand};

    use openssl::symm;
    use openssl::error::ErrorStack;
    

    pub fn method() -> symm::Cipher {
        symm::Cipher::aes_128_cbc()
    }
    
    pub fn make_key(input: &[u8], method: &symm::Cipher) -> Vec<u8> {
        let mut key: Vec<u8> = vec![0u8; method.key_len()];
        for idx in 0..method.key_len() {
            if input.len() > idx {
                key[idx] = input[idx];
            } else {
                key[idx] = rand::random::<u8>();
            }
        }
        key
    }

    pub fn make_iv(input: &[u8], method: &symm::Cipher) -> Vec<u8> {
        match method.iv_len() {
            Some(size) => {
                let mut iv: Vec<u8> = vec![0u8; size];
                for idx in 0..size {
                    if input.len() > idx {
                        iv[idx] = input[idx];
                    } else {
                        iv[idx] = rand::random::<u8>();
                    }
                }
                iv
            }
            None => Vec::new()
        }
    }

    pub fn encrypt(method: symm::Cipher, input: &[u8], output: &mut [u8], key: &[u8], iv: Option<&[u8]>) -> Result<usize, ErrorStack> {
        match symm::Crypter::new(method, symm::Mode::Encrypt, key, iv) {
            Ok(mut encrypter) => {
                encrypter.pad(true);
                let mut size = 0;
                match encrypter.update(input, &mut output[0..]) {
                    Ok(amt) => { size += amt; }
                    Err(e) => return Err(e)
                };
                match encrypter.finalize(&mut output[size..]) {
                    Ok(amt) => { size += amt; }
                    Err(e) => return Err(e)
                };
                Ok(size)
            }
            Err(e) => Err(e)
        }
    }

    pub fn decrypt(method: symm::Cipher, input: &[u8], output: &mut [u8], key: &[u8], iv: Option<&[u8]>) -> Result<usize, ErrorStack> {
        match symm::Crypter::new(method, symm::Mode::Decrypt, key, iv) {
            Ok(mut decrypter) => {
                decrypter.pad(true);
                let mut size = 0;
                match decrypter.update(input, &mut output[0..]) {
                    Ok(amt) => { size += amt; }
                    Err(e) => return Err(e)
                };
                match decrypter.finalize(&mut output[size..]) {
                    Ok(amt) => { size += amt; }
                    Err(e) => return Err(e)
                };
                Ok(size)
            }
            Err(e) => Err(e)
        }
    }
}






fn test_rsa() {
    println!("\n\n=========RSA TEST==========\n");
    let message = "Hello, world!";
    let prikey = rsa::PriKey::gen(1024).unwrap();
    let pubkey = prikey.pubkey();

    println!("PriKey: \n{}", String::from_utf8(prikey.to_pem()).unwrap() );
    println!("PubKey: \n{}", String::from_utf8(pubkey.to_pem()).unwrap() );

    let input = message.as_bytes();
    println!("消息: {:?}\n比特: {:?}", message, input);

    let mut output: Vec<u8> = vec![0u8; prikey.size()];
    let size = prikey.encrypt(&input, &mut output).unwrap();
    let ciphertexts = &output[..size];
    println!("密文: {:?}", &ciphertexts );

    let mut output2: Vec<u8> = vec![0u8; prikey.size()];
    let amt = pubkey.decrypt(&output, &mut output2).unwrap();
    println!("明文: {:?}", str::from_utf8(&output2[..amt]).unwrap() );
}

fn test_aes() {
    println!("\n\n=========AES TEST==========\n");
    let message = "Hello, world!";
    let input = message.as_bytes();

    let method = aes::method();
    let key = aes::make_key("oooo一把钥匙一oooo".as_bytes(), &method);
    let iv = aes::make_iv("okayokay.".as_bytes(), &method);
    let block_size = method.block_size();

    let mut output: Vec<u8> = vec![0u8; input.len() + block_size];

    println!("AES Key: {:?}", key);
    println!("AES IV: {:?}", iv);
    println!("AES Method Block Size: {:?}", block_size);

    let size = aes::encrypt(method, &input, &mut output, &key, Some(&iv)).unwrap();
    println!("密文: {:?}", &output[..size]);

    let mut output2: Vec<u8> = vec![0u8; &output[..size].len() + block_size];
    let size = aes::decrypt(method, &output[..size], &mut output2, &key, Some(&iv)).unwrap();
    println!("明文: {:?}", str::from_utf8(&output2[..size]).unwrap() );
}



// CommandLine:
// openssl genpkey -algorithm RSA -out private_key.pem -pkeyopt rsa_keygen_bits:4096
// openssl rsa -pubout -in private_key.pem -out public_key.pem

// openssl rsa -pubin -in private_key.pem -inform PEM -RSAPrivateKey_out -outform DER -out private_key.der
// openssl rsa -pubin -in public_key.pem -inform PEM -RSAPublicKey_out -outform DER -out public_key.der

fn main() {
    test_rsa();
    test_aes();
}