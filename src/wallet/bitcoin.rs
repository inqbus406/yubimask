/// A module containing necessary functions to implement a Bitcoin wallet.

use std::str::FromStr;

use anyhow::Result;
use bip32::Mnemonic;
use bitcoin::{Address, PublicKey};
use bitcoin::secp256k1::ffi::types::AlignedType;
use bitcoin::secp256k1::Secp256k1;
use bitcoin::util::bip32::{ChildNumber, DerivationPath, ExtendedPrivKey, ExtendedPubKey};
use crate::Wallet;

const NETWORK_NAME: &str = "BTC";

// This will have to return some type of connection. Might have to be async
pub fn connect() {
    todo!();
}

pub fn get_addr(wallet: &mut Wallet) -> Result<Address> {
    if let Some(addr) = wallet.addrs.get(NETWORK_NAME) {
        Ok(Address::from_str(addr).unwrap())
    } else {
        let addr = derive_addr(&wallet.get_mnemonic()?);
        wallet.addrs.insert(String::from(NETWORK_NAME), addr.to_string()); // to_string truncates the address
        Ok(addr)
    }
}

fn derive_addr(mnemonic: &Mnemonic) -> Address {
    let network = bitcoin::Network::Testnet; // testnet for now
    println!("Network: {:?}", network);

    let seed = mnemonic.to_seed("");

    // we need secp256k1 context for key derivation
    let mut buf: Vec<AlignedType> = Vec::new();
    buf.resize(Secp256k1::preallocate_size(), AlignedType::zeroed());
    let secp = Secp256k1::preallocated_new(buf.as_mut_slice()).unwrap();

    // derive root key from seed
    let root = ExtendedPrivKey::new_master(network, seed.as_ref()).unwrap();
    println!("Root key: {}", root);

    // derive child xpub
    let path = DerivationPath::from_str("m/84h/0h/0h").unwrap();
    let child = root.derive_priv(&secp, &path).unwrap();
    println!("Child at {}: {}", path, child);
    let xpub = ExtendedPubKey::from_priv(&secp, &child);
    println!("Public key at {}: {}", path, xpub);

    // generate first receiving address at m/0/0
    // manually creating indexes this time
    let zero = ChildNumber::from_normal_idx(0).unwrap();
    let public_key = xpub.derive_pub(&secp, &vec![zero, zero])
        .unwrap()
        .public_key;
    let address = Address::p2wpkh(&PublicKey::new(public_key), network).unwrap();
    println!("First receiving address: {}", address);

    address
}

fn get_sec_key() {
    todo!();
}

pub fn get_balance() {
    todo!();
}

pub fn send() -> Result<()> {
    todo!()
}

// A possible structure if we use a trait to implement functionality
// pub(super) struct Bitcoin {
//
// }
//
// impl super::Network for Bitcoin {
//
// }
