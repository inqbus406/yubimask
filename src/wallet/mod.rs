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

#[derive(Serialize, Deserialize, Debug)]
pub struct Wallet {
    pub sec_key: String,
    pub pub_key: String,
    // Honestly later we will probably want to either get rid of this, or store addresses for all networks,
    // because they will be different for different networks.
    pub addr: String
}

impl Wallet {
    pub fn new(sec_key: &SecretKey, pub_key: &PublicKey, addr: &Address) -> Self {
        Self { // Could also say "EthWallet" instead
            sec_key: sec_key.to_string(),
            pub_key: pub_key.to_string(),
            addr: format!("{:?}", addr) // if we just use to_string() it gets truncated
        }
    }

    pub fn write_to_file(&self, path: &str) -> Result<()> {
        let file = OpenOptions::new().write(true).create(true).open(path)?;
        let writer = BufWriter::new(file);
        serde_json::to_writer_pretty(writer, self)?;

        Ok(())
    }

    pub fn read_from_file(path: &str) -> Result<Wallet> {
        let file = OpenOptions::new().read(true).open(path)?;
        let reader = BufReader::new(file);
        Ok(serde_json::from_reader(reader)?)
    }

    pub fn get_sec_key(&self) -> Result<SecretKey> {
        Ok(SecretKey::from_str(&self.sec_key)?)
    }

    pub fn get_pub_key(&self) -> Result<PublicKey> {
        Ok(PublicKey::from_str(&self.pub_key)?)
    }
}

fn get_yk_response() {
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

        let challenge = String::from("mychallenge");

        // FIXME handle the case where this fails
        let hmac_result = yubi.challenge_response_hmac(challenge.as_bytes(), config).unwrap();

        let hexval = hmac_result.deref();
        println!("{:?}", hmac_result);
        let hexstring = hex::encode(hexval);
        println!("Response: {}", hexstring);

    } else {
        println!("Yubikey not found.");
    }
}
