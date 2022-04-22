// A generic wallet to make things work with multiple networks.
// We'll use this more in the future.

pub mod ethereum;

use std::collections::HashMap;
use std::fs::OpenOptions;
use std::io;
use std::io::{BufReader, BufWriter, Write};
use std::str::FromStr;
use anyhow::{bail, Result};
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
use web3::transports::WebSocket;
use web3::Web3;
use yubico_manager::configure::DeviceModeConfig;
use yubico_manager::hmacmode::HmacKey;

// HD wallet stuff
//use bip39::{Language, Mnemonic, MnemonicType};
use bip32::{Mnemonic, Language};

// The networks we support
const NETWORKS: [&str; 2] = ["ETH", "BTC"];

// TODO probably should store the language of the wallet
#[derive(Serialize, Deserialize, Debug)]
struct FileData {
    ciphertext: Vec<u8>, // encrypted seed phrase/mnemonic entropy
    nonce: Vec<u8>, // unique number used to encrypt this data
    debug: bool
}

pub struct Wallet {
    pub name: String, // wallet/file name
    mnemonic: Mnemonic,
    pub addrs: HashMap<String, String>,
    filedata: FileData
}

impl Wallet {
    pub fn new(name: &str, debug: bool) -> Self {
        // this will panic if encrypt fails
        //let mnemonic = Mnemonic::new(MnemonicType::Words24, Language::English); // this was using bip39 crate

        let mnemonic = Mnemonic::random(&mut rand_core::OsRng, Default::default());
        let phrase = mnemonic.phrase();
        let entropy = mnemonic.entropy();
        println!("Generating new wallet from entropy: {:?}", entropy);
        println!("Seed phrase: {}", phrase);

        let mut nonce = [0u8; 12];
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

        // println!("Mnemonic bytes: {}", mnemonic.entropy().len());
        // let test: [u8; 32] = Vec::from(mnemonic.entropy().as_slice()).try_into().unwrap();
        // println!("Test value is: {:?}", test);
        // let test = encrypt(&password, mnemonic.entropy(), &mut nonce, debug).unwrap();
        // println!("Test value is: {:?}", test);

        // FIXME this will panic if it's the wrong size, do it better!
        let ciphertext = encrypt(&password, mnemonic.entropy(), &mut nonce, debug).unwrap();

        // Compute our public addresses
        let mut addrs = HashMap::new();
        for s in NETWORKS {
            // For now, let's lazy-load the addresses. Might want to add them all here in the future, though
            // This will also allow us to convert to a Vec<String> later for HD wallets
            addrs.insert(String::from(s), String::new());
        }

        let filedata = FileData {
            ciphertext,
            nonce: Vec::from(nonce),
            debug
        };

        Self { // Could also say "EthWallet" instead
            name: String::from(name),
            mnemonic,
            filedata,
            addrs // For each one, use this macro format!("{:?}", addr) // if we just use to_string() it gets truncated
        }
    }

    pub fn write_to_file(&self) -> Result<()> {
        let file = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(&self.name)?;
        let writer = BufWriter::new(file);
        serde_json::to_writer(writer, &self.filedata)?;

        Ok(())
    }

    pub fn read_from_file(path: &str) -> Result<Wallet> {
        println!("Reading from file: {}", path);
        let file = OpenOptions::new().read(true).open(path)?;
        let reader = BufReader::new(file);
        let filedata: FileData = serde_json::from_reader(reader)?;

        let entropy: [u8; 32] = decrypt(&get_password()?, &filedata.ciphertext, &filedata.nonce, filedata.debug)?
            .try_into().unwrap();
        let mnemonic = Mnemonic::from_entropy(entropy, Default::default());

        let wallet = Wallet {
            name: String::from(path),
            addrs: HashMap::new(),
            filedata,
            mnemonic
        };
        Ok(wallet)
    }

    // Every time the secret key is retrieved here, it must be decrypted and then re-encrypted with new
    // salt, nonce, etc
    pub fn get_mnemonic(&mut self) -> Result<Mnemonic> {
        //println!("Trying to retrieve secret key");
        let password = get_password()?;

        // This could totally blow up if the sizes don't line up
        let plaintext = decrypt(&password, &self.filedata.ciphertext, &self.filedata.nonce, self.filedata.debug)?
            .try_into().unwrap();
        let mnemonic = Mnemonic::from_entropy(plaintext, Language::English);

        self.filedata.ciphertext = encrypt(&password, &self.filedata.ciphertext, &mut self.filedata.nonce, self.filedata.debug)?;
        self.write_to_file();
        Ok(mnemonic)
    }

    pub fn receive(&mut self) -> Result<()> {
        let addr = match get_network().deref() {
            "ETH" => ethereum::get_addr(&self)?,
            _ => bail!("Unsupported network")
        };
        println!("Wallet address: {:?}", addr);
        Ok(())
    }

    // TODO need to generalize this more so it works with any connection
    pub async fn print_balances(&self, conn: &Web3<WebSocket>) -> Result<()> {
        // Print out the wallet balance
        let balance = ethereum::get_balance_eth(&self, &conn).await?;
        println!("Wallet balance: {} ETH", &balance);

        Ok(())
    }

    // TODO same here
    pub async fn send(&mut self, conn: &Web3<WebSocket>) -> Result<()> {
        println!("Sending!");
        match get_network().deref() {
            "ETH" => ethereum::send(&conn, self).await,
            _ => bail!("Unsupported network.")
        }
    }
}

fn get_password() -> Result<String> {
    let password = rpassword::prompt_password("Wallet password: ")?;
    std::io::stdout().flush();
    Ok(password)
}

// Ask the user what network they are looking to send/receive
fn get_network() -> String {
    String::from("ETH")
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

    //println!("decryption key: {:?}", key);
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
        println!("{}", cont.to_lowercase());
        count += 1;
        println!("Configuring key #{}", count);

        // Let's make sure this key isn't already programmed...
        if is_programmed() {
            print!("This key is already programmed, are you sure you want to overwrite? (y/n) ");
            io::stdout().flush();
            cont.clear();
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
                println!("Successfully programmed!");
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
