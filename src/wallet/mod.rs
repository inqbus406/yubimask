// A generic wallet to make things work with multiple networks.
// We'll use this more in the future.

pub mod ethereum;

use std::fs::OpenOptions;
use std::io;
use std::io::{BufReader, BufWriter, Write};
use std::str::FromStr;
use anyhow::Result;
use secp256k1::{PublicKey, SecretKey};
use serde::{Serialize, Deserialize};
use web3::types::Address;
use yubico_manager::Yubico;
use yubico_manager::config::{Command, Config, Mode, Slot};
use std::ops::Deref;

// For encryption
use aes_gcm::{Aes256Gcm, Key, Nonce};
use aes_gcm::aead::{Aead, NewAead};
use argon2::Argon2;
use rand::{Rng, RngCore, thread_rng};
use rand::distributions::Alphanumeric;
use rand::rngs::{OsRng, EntropyRng};
use yubico_manager::configure::DeviceModeConfig;
use yubico_manager::hmacmode::HmacKey; // May want to use EntropyRing as a fallback

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
    pub fn new(name: &str, sec_key: &SecretKey, pub_key: &PublicKey, addr: &Address, debug: bool) -> Self {
        // this will panic if encrypt fails
        let mut nonce = [0u8; 12];
        let sec_key = sec_key.as_ref();
        std::io::stdout().flush();
        let password = match rpassword::prompt_password("Set new wallet password: ") {
            Ok(p) => p,
            Err(_) => panic!("Password is required for wallet creation") // Should probably make this more graceful, re-prompt, etc
        };
        match rpassword::prompt_password("Re-enter password: ") {
            Ok(password2) => if password2 != password {
                panic!("Passwords don't match!");
            },
            Err(_) => panic!("Password must be entered twice!")
        }
        let ciphertext = encrypt(&password, sec_key, &mut nonce, debug).unwrap();
        Self { // Could also say "EthWallet" instead
            name: String::from(name),
            sec_key: ciphertext,
            pub_key: pub_key.to_string(),
            nonce: Vec::from(nonce),
            addr: format!("{:?}", addr) // if we just use to_string() it gets truncated
        }
    }

    pub fn write_to_file(&self) -> Result<()> {
        let file = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(&self.name)?;
        let writer = BufWriter::new(file);
        serde_json::to_writer(writer, self)?;

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
    pub fn get_sec_key(&mut self, debug: bool) -> Result<SecretKey> {
        //println!("Trying to retrieve secret key");
        let password = rpassword::prompt_password("Wallet password: ")?;
        std::io::stdout().flush();

        let plaintext = decrypt(&password, &self.sec_key, &self.nonce, debug)?;
        let sec_key = SecretKey::from_slice(&plaintext)?;
        self.sec_key = encrypt(&password, &plaintext, &mut self.nonce, debug)?;
        self.write_to_file();
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

fn encrypt(password: &str, message: &[u8], nonce: &mut [u8], debug: bool) -> Result<Vec<u8>> {
    let mut key: [u8; 32] = [0u8; 32];

    let mut rand = OsRng::new()?;
    rand.fill_bytes(nonce);

    let mut composite = match debug {
        false => get_yk_response(nonce)?,
        true => Vec::new()
    };
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

fn decrypt(password: &str, ciphertext: &[u8], nonce: &[u8], debug: bool) -> Result<Vec<u8>> {
    let mut key: [u8; 32] = [0u8; 32];

    let mut composite = match debug {
        false => get_yk_response(nonce)?,
        true => Vec::new()
    };
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

pub fn get_yk_response(challenge: &[u8]) -> Result<Vec<u8>> {
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
        println!("Please touch your Yubikey...");
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

// A function to program any number of yubikeys alike for a new wallet.
pub fn program_keys() -> Result<()> {
    let mut yubi = Yubico::new();
    let mut cont = String::from('y');
    let mut count = 0;

    let mut rng = thread_rng();
    let secret: String = rng.sample_iter(&Alphanumeric).take(20).collect();
    let hmac_key: HmacKey = HmacKey::from_slice(secret.as_bytes());

    while cont.to_lowercase().contains('y') {
        count += 1;
        println!("Configuring key #{}", count);

        // Let's make sure this key isn't already programmed...
        if is_programmed() {
            print!("This key is already programmed, are you sure you want to overwrite? (y/n) ");
            io::stdout().flush();
            io::stdin().read_line(&mut cont);
            if !cont.to_lowercase().contains('y') {
                continue
            }
        }

        if let Ok(device) = yubi.find_yubikey() {
            println!("Vendor ID: {:?}", device.vendor_id);
            println!("Product ID: {:?}", device.product_id);

            let config = Config::default()
                .set_vendor_id(device.vendor_id)
                .set_product_id(device.product_id)
                .set_command(Command::Configuration2);

            let mut device_config = DeviceModeConfig::default();
            // First bool is for variable length challenges, second is requiring a button press
            device_config.challenge_response_hmac(&hmac_key, true, true);

            if let Err(e) = yubi.write_config(config, &mut device_config) {
                println!("{:?}", e);
            } else {
                println!("Successfully programmed!")
            }
            print!("Program another? (y/n) ");
            io::stdout().flush();
            cont.clear();
            io::stdin().read_line(&mut cont);

        } else {
            println!("Yubikey not found.");
            return Ok(());
        }
    }

    println!("Done programming!");
    Ok(())
}

pub fn is_programmed() -> bool {
    let mut yubi = Yubico::new();

    if let Ok(device) = yubi.find_yubikey() {
        let config = Config::default()
            .set_vendor_id(device.vendor_id)
            .set_product_id(device.product_id)
            .set_variable_size(true)
            .set_mode(Mode::Sha1)
            .set_slot(Slot::Slot2);

        println!("Please touch your Yubikey...");
        if let Ok(_) = yubi.challenge_response_hmac(&[0], config) {
            true
        } else {
            false
        }
    } else {
        false
    }
}
