// A treat to make things work with multiple networks.
// We'll use this more in the future.

pub mod ethereum;

use std::fs::OpenOptions;
use std::io::{BufReader, BufWriter};
use std::str::FromStr;
use anyhow::Result;
use secp256k1::{PublicKey, SecretKey};
use serde::{Serialize, Deserialize};
use web3::types::Address;
use yubico_manager::Yubico;
use yubico_manager::config::{Config, Mode, Slot};
use std::ops::Deref;

// For encryption
use aes_gcm::{Aes256Gcm, Key, Nonce};
use aes_gcm::aead::{Aead, NewAead};
use argon2::Argon2;
use rand::RngCore;
use rand::rngs::{OsRng, EntropyRng}; // May want to use EntropyRing as a fallback

#[derive(Serialize, Deserialize, Debug)]
pub struct Wallet {
    pub name: String, // wallet/file name
    sec_key: Vec<u8>, // encrypted secret key
    pub pub_key: String,
    // Honestly later we will probably want to either get rid of this, or store addresses for all networks,
    // because they will be different for different networks.
    pub addr: String,
    nonce: Vec<u8>
}

impl Wallet {
    pub fn new(name: &str, sec_key: &SecretKey, pub_key: &PublicKey, addr: &Address) -> Self {
        // this will panic if encrypt fails
        let mut nonce = [0u8; 12];
        let sec_key = sec_key.as_ref();
        let ciphertext = encrypt(sec_key, &mut nonce).unwrap();
        Self { // Could also say "EthWallet" instead
            name: String::from(name),
            sec_key: ciphertext,
            pub_key: pub_key.to_string(),
            nonce: Vec::from(nonce),
            addr: format!("{:?}", addr) // if we just use to_string() it gets truncated
        }
    }

    pub fn write_to_file(&self) -> Result<()> {
        let file = OpenOptions::new().write(true).create(true).open(&self.name)?;
        let writer = BufWriter::new(file);
        serde_json::to_writer_pretty(writer, self)?;

        Ok(())
    }

    pub fn read_from_file(path: &str) -> Result<Wallet> {
        println!("Reading from file: {}", path);
        let file = OpenOptions::new().read(true).open(path)?;
        let reader = BufReader::new(file);
        Ok(serde_json::from_reader(reader)?)
    }

    // Every time the secret key is retrieved here, it must be decrypted and then re-encrypted with new
    // salt, nonce, etc
    pub fn get_sec_key(&mut self) -> Result<SecretKey> {
        let plaintext = decrypt(&self.sec_key, &self.nonce)?;
        let sec_key = SecretKey::from_slice(&plaintext)?;
        self.sec_key = encrypt(&plaintext, &mut self.nonce)?;
        Ok(sec_key)
    }

    pub fn get_pub_key(&self) -> Result<PublicKey> {
        Ok(PublicKey::from_str(&self.pub_key)?)
    }

    // Example of how to encrypt and decrypt
    pub fn encrypt_decrypt(message: &str) {
        let key = Key::from_slice(b"an example very very secret key."); // this has to be 256 bits
        let cipher = Aes256Gcm::new(key);
        let nonce = Nonce::from_slice(b"unique nonce");

        if let Ok(ciphertext) = cipher.encrypt(nonce, message.as_bytes()) {
            // If encryption failed that's ok, it's still encrypted on-disk. Is this a problem?
            if let Ok(plaintext) = cipher.decrypt(nonce, ciphertext.as_ref()) {
                println!("{:?} {:?}", &plaintext, message.as_bytes());
                assert_eq!(&plaintext, message.as_bytes());
            }
        }
    }
}

fn encrypt(message: &[u8], nonce: &mut [u8]) -> Result<Vec<u8>> {
    let mut key: [u8; 32] = [0u8; 32];

    let mut rand = OsRng::new()?;
    rand.fill_bytes(nonce);

    let password = "dummy password";
    let mut composite = get_yk_response(nonce)?;
    composite.extend(password.as_bytes());
    let kdf = Argon2::default(); // set these params manually later!
    kdf.hash_password_into(&composite, nonce, &mut key);

    let nonce = Nonce::from_slice(nonce);
    let key = Key::from_slice(&key);
    let cipher = Aes256Gcm::new(key);

    println!("encryption key: {:?}", key);
    if let Ok(ciphertext) = cipher.encrypt(nonce, message) {
        Ok(ciphertext)
    } else {
        panic!("Encryption failed!");
    }
}

fn decrypt(ciphertext: &[u8], nonce: &[u8]) -> Result<Vec<u8>> {
    let mut key: [u8; 32] = [0u8; 32];

    let password = "dummy password";
    let mut composite = get_yk_response(nonce)?;
    composite.extend(password.as_bytes());
    let kdf = Argon2::default();
    kdf.hash_password_into(&composite, nonce, &mut key);

    let nonce = Nonce::from_slice(nonce);
    let key = Key::from_slice(&key);
    let cipher = Aes256Gcm::new(key);

    println!("decryption key: {:?}", key);
    match cipher.decrypt(nonce, ciphertext.as_ref()) {
        Ok(plaintext) => Ok(plaintext),
        Err(_) => panic!("Failed to decrypt!")
    }
}

fn get_yk_response(challenge: &[u8]) -> Result<Vec<u8>> {
    let mut yubi = Yubico::new();
    if let Ok(device) = yubi.find_yubikey() {
        println!("Vendor ID: {:?}", device.vendor_id);
        println!("Product ID: {:?}", device.product_id);

        let config = Config::default()
            .set_vendor_id(device.vendor_id)
            .set_product_id(device.product_id)
            .set_variable_size(true)
            .set_mode(Mode::Sha1)
            .set_slot(Slot::Slot2);

        //let challenge = String::from("mychallenge");

        // FIXME handle the case where this fails
        let hmac_result = yubi.challenge_response_hmac(challenge, config).unwrap();

        let hexval = hmac_result.deref();
        println!("{:?}", hmac_result);
        let hexstring = hex::encode(hexval);
        println!("Response: {}", hexstring);

        Ok(Vec::from(hmac_result.deref()))
    } else {
        panic!("Yubikey not found.");
    }
}
