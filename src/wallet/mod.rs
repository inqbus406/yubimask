// A generic wallet to make things work with multiple networks.
// We'll use this more in the future.

pub mod ethereum; // this was only public for testing, can be made private later
mod bitcoin;

use std::collections::HashMap;
use std::fs::OpenOptions;
use std::io;
use std::io::{BufReader, BufWriter, Write};
use std::str::FromStr;
use anyhow::{bail, Result};
use serde::{Serialize, Deserialize};
use yubico_manager::Yubico;
use yubico_manager::config::{Command, Config, Mode, Slot};
use std::ops::Deref;

// For encryption
use aes_gcm::{Aes256Gcm, Key, Nonce};
use aes_gcm::aead::{Aead, NewAead};
use argon2::Argon2;
use rand::{Rng, RngCore, thread_rng};
use rand::distributions::Alphanumeric;
use rand::rngs::{EntropyRng}; // Was using OsRng but switched to EntropyRng for availability from feedback
use yubico_manager::configure::DeviceModeConfig;
use yubico_manager::hmacmode::HmacKey;

// HD wallet stuff
//use bip39::{Language, Mnemonic, MnemonicType};
use bip32::{Mnemonic, Language};

// To make storing secrets in memory safer
use zeroize::Zeroize;

// The networks we support
const NETWORKS: [&str; 2] = ["ETH", "BTC"];

// I feel like this enum could be useful down the line, but maybe not?
enum Network {
    ETH,
    BTC
}

// I feel like it could be useful to have some type of trait with all the networks implementing its
// methods, but I haven't quite figured out how to store instances, dispatch, etc, elegantly
// trait Network {
//
// }

impl FromStr for Network {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_uppercase().deref() {
            "0" | "ETH" => Ok(Self::ETH),
            "1" | "BTC" => Ok(Self::BTC),
            _ => Err(String::from("Not a valid network."))
        }
    }
}

// TODO probably should store the language of the wallet
#[derive(Serialize, Deserialize, Debug)]
struct FileData {
    ciphertext: Vec<u8>, // encrypted seed phrase/mnemonic entropy
    nonce: Vec<u8>, // unique number used to encrypt this data
    debug: bool
}

pub struct Wallet {
    pub name: String, // wallet/file name
    pub addrs: HashMap<String, String>,
    filedata: FileData
}

impl Wallet {
    pub fn new(name: &str, debug: bool) -> Self {
        // this will panic if encrypt fails
        //let mnemonic = Mnemonic::new(MnemonicType::Words24, Language::English); // this was using bip39 crate

        let mnemonic = Mnemonic::random(&mut rand_core::OsRng, Default::default());
        // let phrase = mnemonic.phrase();
        // let entropy = mnemonic.entropy();
        // println!("Generating new wallet from entropy: {:?}", entropy);
        // println!("Seed phrase: {}", phrase);

        let mut nonce = [0u8; 12];
        let mut password = match rpassword::prompt_password("Set new wallet password: ") {
            Ok(p) => p,
            Err(_) => panic!("Password is required for wallet creation") // Should probably make this more graceful, re-prompt, etc
        };
        match rpassword::prompt_password("Re-enter password: ") {
            Ok(password2) => if password2 != password {
                panic!("Passwords don't match!");
            },
            Err(_) => panic!("Password must be entered twice!")
        }

        let ciphertext = encrypt(&password, mnemonic.entropy(), &mut nonce, debug).unwrap();
        password.zeroize();

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

        Self { // Could also say Wallet instead
            name: String::from(name),
            //mnemonic,
            filedata,
            addrs // For each one, use this macro format!("{:?}", addr) // if we just use to_string() it gets truncated
        }
    }

    pub fn import(name: &str, seed_phrase: &str, debug: bool) -> Option<Self> {
        let mnemonic = match Mnemonic::new(seed_phrase.to_lowercase(), Default::default()) {
            Ok(m) => m,
            Err(_) => return None
        };
        let phrase = mnemonic.phrase();
        println!("Importing wallet from phrase: {}", phrase);

        let mut nonce = [0u8; 12];
        let mut password = match rpassword::prompt_password("Set new wallet password: ") {
            Ok(p) => p,
            Err(_) => panic!("Password is required for wallet creation") // Should probably make this more graceful, re-prompt, etc
        };
        match rpassword::prompt_password("Re-enter password: ") {
            Ok(password2) => if password2 != password {
                panic!("Passwords don't match!");
            },
            Err(_) => panic!("Password must be entered twice!")
        }

        let ciphertext = encrypt(&password, mnemonic.entropy(), &mut nonce, debug).unwrap();
        password.zeroize();

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

        Some(Self { // Could also say "Wallet" instead
            name: String::from(name),
            //mnemonic,
            filedata,
            addrs // For each one, use this macro format!("{:?}", addr) // if we just use to_string() it gets truncated
        })
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

        let wallet = Wallet {
            name: String::from(path),
            addrs: HashMap::new(),
            filedata,
            //mnemonic
        };
        Ok(wallet)
    }

    // Every time the secret key is retrieved here, it must be decrypted and then re-encrypted with new
    // salt, nonce, etc
    pub fn get_mnemonic(&mut self) -> Result<Mnemonic> {
        for _ in 0..3 {
            let mut password = match get_password() {
                Ok(pw) => pw,
                Err(_) => continue
            };

            // This could totally blow up if the sizes don't line up because the file was corrupted
            let plaintext = match decrypt(&password, &self.filedata.ciphertext, &self.filedata.nonce, self.filedata.debug) {
                Ok(data) => data.try_into().unwrap(),
                Err(_) => {
                    println!("Incorrect password, try again.");
                    continue
                }
            };
            let mnemonic = Mnemonic::from_entropy(plaintext, Language::English);

            self.filedata.ciphertext = encrypt(&password, &plaintext, &mut self.filedata.nonce, self.filedata.debug)?;
            self.write_to_file()?;
            password.zeroize();
            return Ok(mnemonic)
        }
        eprintln!("Failed three password attempts; exiting...");
        bail!("Failed three password attempts; exiting...")
    }

    pub fn show_seed_phrase(&mut self) -> Result<()> {
        let mnemonic = self.get_mnemonic()?;
        let seed_phrase = String::from(mnemonic.phrase());
        println!("Wallet seed/recovery phrase: {}", &seed_phrase);
        Ok(())
    }

    pub fn receive(&mut self) -> Result<()> {
        let addr = match get_network() {
            Network::ETH => format!("{:?}", ethereum::get_addr(self)?),
            Network::BTC => bitcoin::get_addr(self)?.to_string(),
            // _ => bail!("Unsupported network")
        };
        println!("Wallet address: {}", addr);
        Ok(())
    }

    pub async fn print_balances(&mut self) -> Result<()> {
        // Print out the wallet balance
        let balance = ethereum::get_balance_eth(self).await?;
        // now get the USD value of the balance
        let value = ethereum::get_eth_value(balance).await?;
        println!("Wallet balance: {} ETH ~ ${:.2} USD", &balance, &value);
        // println!("Value of balance: ${:.2} USD", &value);
        Ok(())
    }

    pub async fn send(&mut self) -> Result<()> {
        match get_network() {
            Network::ETH => ethereum::send(self).await,
            _ => bail!("Unsupported network.")
        }
    }
}

fn get_password() -> Result<String> {
    let password = rpassword::prompt_password("Wallet password: ")?;
    io::stdout().flush()?;
    Ok(password)
}

// Ask the user what network they are looking to send/receive
fn get_network() -> Network {
    let mut network = String::new();
    println!("What network?");
    for (i, name) in NETWORKS.iter().enumerate() {
        println!("{}: {}", i, name);
    }
    loop {
        network.clear();
        print!("> ");
        if let Ok(_) = io::stdout().flush() {
            match io::stdin().read_line(&mut network) {
                Ok(_) => {},
                Err(_) => continue
            }
        }
        if let Ok(response) = Network::from_str(network.trim()) {
            return response;
        } else {
            println!("Not recognized, try again");
        }
    }
}

fn encrypt(password: &str, message: &[u8], nonce: &mut [u8], debug: bool) -> Result<Vec<u8>> {
    let mut key: [u8; 32] = [0u8; 32];

    // let mut rand = OsRng::new()?;
    let mut rand = EntropyRng::new();
    rand.fill_bytes(nonce);

    let mut composite = match debug {
        false => get_yk_response(nonce)?,
        true => Vec::new()
    };
    composite.extend(password.as_bytes());
    let kdf = Argon2::default(); // set these params manually later!
    match kdf.hash_password_into(&composite, nonce, &mut key) {
        Ok(_) => {},
        Err(_) => return Err(anyhow::Error::msg("Key derivation failed"))
    }

    let nonce = Nonce::from_slice(nonce);
    let key = Key::from_slice(&key);
    let cipher = Aes256Gcm::new(key);

    // println!("encryption key: {:?}", key);
    if let Ok(ciphertext) = cipher.encrypt(nonce, message) {
        Ok(ciphertext)
    } else {
        bail!("Encryption failed!");
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
    match kdf.hash_password_into(&composite, nonce, &mut key) {
        Ok(_) => {},
        Err(_) => return Err(anyhow::Error::msg("Key derivation failed"))
    }

    // Important note: Using AES-GCM here protects us from padding oracle attacks. If we were to switch
    // to other AES modes like CBC, we should do encrypt-then-MAC to validate messages before decrypting.
    let nonce = Nonce::from_slice(nonce);
    let key = Key::from_slice(&key);
    let cipher = Aes256Gcm::new(key);

    //println!("decryption key: {:?}", key);
    match cipher.decrypt(nonce, ciphertext.as_ref()) {
        Ok(plaintext) => Ok(plaintext),
        Err(_) => Err(anyhow::Error::msg("Decryption failed"))
    }
}

pub fn get_yk_response(challenge: &[u8]) -> Result<Vec<u8>> {
    let mut yubi = Yubico::new();
    if let Ok(device) = yubi.find_yubikey() {
        // println!("Vendor ID: {:?}", device.vendor_id);
        // println!("Product ID: {:?}", device.product_id);

        let config = Config::default()
            .set_vendor_id(device.vendor_id)
            .set_product_id(device.product_id)
            .set_variable_size(true)
            .set_mode(Mode::Sha1)
            .set_slot(Slot::Slot2);

        // FIXME handle the case where this fails
        println!("Please touch your Yubikey...");
        let hmac_result = yubi.challenge_response_hmac(challenge, config).unwrap();

        // let hexval = hmac_result.deref();
        // println!("{:?}", hmac_result);
        // let hexstring = hex::encode(hexval);
        // println!("Response: {}", hexstring);

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
            io::stdout().flush()?;
            cont.clear();
            io::stdin().read_line(&mut cont)?;
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
            io::stdout().flush()?;
            cont.clear();
            io::stdin().read_line(&mut cont)?;

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
        match yubi.challenge_response_hmac(&[0], config) {
            Ok(_) => true,
            _ => false
        }
    } else {
        false
    }
}
