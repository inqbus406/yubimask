/// A wallet module specifically for the Ethereum network.

use std::io::Write;
use std::str::FromStr;
use secp256k1::{PublicKey, SecretKey};
use secp256k1::rand::{rngs, SeedableRng};
use tiny_keccak::keccak256;
use rand::RngCore;
use rand::rngs::{OsRng, EntropyRng}; // May want to use EntropyRing as a fallback
use web3::{transports, Web3};
use web3::transports::WebSocket;
use web3::types::{Address, H256, TransactionParameters, U256};
use anyhow::Result;
//use bip39::Mnemonic;
use bip32::{Mnemonic, XPrv};
use crate::wallet;
use crate::wallet::Wallet;

// For connecting to the ETH network
const ETH_MAINNET_ENDPOINT: &str = "wss://mainnet.infura.io/ws/v3/465e5058a793440bb743994f856841af";
const ETH_RINKEBY_ENDPOINT: &str = "wss://rinkeby.infura.io/ws/v3/465e5058a793440bb743994f856841af";
const INFURA_PROJECT_ID: &str = "465e5058a793440bb743994f856841af";
const INFURA_PROJECT_SECRET: &str = "adfcf1aac28349c4a67cd80b04287e91"; // Probably shouldn't have this in plaintext...
//const NETWORK_NAME: &str = "ETH";

// This is deprecated
pub fn gen_keypair() -> (SecretKey, PublicKey) {
    let secp = secp256k1::Secp256k1::new();
    let mut rng;
    let num;
    // let rand = match OsRng::new() {
    //     Ok(mut r) => r.next_u64(),
    //     Err(_) => EntropyRng::new().next_u64()
    // };
    if let Ok(mut rand) = OsRng::new() {
        num = rand.next_u64();
        println!("Random number: {}", num);
    } else {
        let mut rand = EntropyRng::new();
        num = rand.next_u64();
        println!("Backup random number: {}", num);
    }
    rng = rngs::StdRng::seed_from_u64(num);
    secp.generate_keypair(&mut rng)
}

pub fn address_from_pubkey(pub_key: &PublicKey) -> Address {
    let pub_key = pub_key.serialize_uncompressed();

    debug_assert_eq!(pub_key[0], 0x04);

    let hash = keccak256(&pub_key[1..]);

    Address::from_slice(&hash[12..])
}

pub async fn connect() -> Result<Web3<WebSocket>> {
    let url = ETH_RINKEBY_ENDPOINT;
    let conn = transports::WebSocket::new(url).await?;
    Ok(Web3::new(conn))
}

pub fn get_addr(wallet: &Wallet) -> Result<Address> {
    Ok(address_from_pubkey(&get_pub_key(&wallet.mnemonic)?))
}

pub fn get_pub_key(mnemonic: &Mnemonic) -> Result<PublicKey> {
    // Derive a BIP39 seed value using the given password
    let seed = mnemonic.to_seed(""); // Not using a password for now

    // Derive the root `XPrv` from the `seed` value
    let root_xprv = XPrv::new(&seed)?;
    assert_eq!(root_xprv, XPrv::derive_from_path(&seed, &"m".parse()?)?);

    // Derive a child `XPrv` using the provided BIP32 derivation path
    let child_path = "m/0/2147483647'/1/2147483646'";
    let child_xprv = XPrv::derive_from_path(&seed, &child_path.parse()?)?;

    // Get the `XPub` associated with `child_xprv`.
    let child_xpub = child_xprv.public_key();

    let result = PublicKey::from_slice(&child_xpub.to_bytes())?;
    Ok(result)
}

fn get_sec_key(mnemonic: &Mnemonic) -> Result<SecretKey> {
    // Derive a BIP39 seed value using the given password
    let seed = mnemonic.to_seed(""); // Not using a password for now

    // Derive the root `XPrv` from the `seed` value
    let root_xprv = XPrv::new(&seed)?;
    assert_eq!(root_xprv, XPrv::derive_from_path(&seed, &"m".parse()?)?);

    // Derive a child `XPrv` using the provided BIP32 derivation path
    let child_path = "m/0/2147483647'/1/2147483646'";
    let child_xprv = XPrv::derive_from_path(&seed, &child_path.parse()?)?;

    let result = SecretKey::from_slice(&child_xprv.to_bytes())?;
    Ok(result)
}

// Returns the balance in wei
pub async fn get_balance(wallet: &Wallet) -> Result<U256> {
    // Connect to the network
    let conn = wallet::ethereum::connect().await?;
    // Print out the current block number
    let block = conn.eth().block_number().await?;
    println!("Block number: {}", &block);

    // TODO populate the wallet map of addresses
    // let addr = Address::from_str(&wallet.addrs.get(NETWORK_NAME).unwrap())?;

    // For now, just calculate the address each time
    let addr = get_addr(wallet)?;

    Ok(conn.eth().balance(addr, None).await?)
}

pub async fn get_balance_eth(wallet: &Wallet) -> Result<f64> {
    Ok(wei_to_eth(get_balance(wallet).await?))
}

fn create_txn(addr: Address, eth: f64) -> TransactionParameters {
    TransactionParameters {
        to: Some(addr),
        value: eth_to_wei(eth),
        ..Default::default()
    }
}

pub async fn sign_and_send(txn: TransactionParameters, sec_key: &SecretKey) -> Result<H256> {
    // Connect to the network
    let conn = wallet::ethereum::connect().await?;
    // Print out the current block number
    let block = conn.eth().block_number().await?;
    println!("Block number: {}", &block);

    let txn = conn.accounts().sign_transaction(txn, sec_key).await?;
    let result = conn.eth().send_raw_transaction(txn.raw_transaction).await?;
    Ok(result)
}

pub async fn send(wallet: &mut Wallet) -> Result<()> {
    println!("Sending ETH...");
    let mut input = String::new();
    let to_addr;
    loop {
        print!("What address would you like to send to? ");
        std::io::stdout().flush()?;
        std::io::stdin().read_line(&mut input)?;
        if let Ok(addr) = Address::from_str(&input) {
            to_addr = addr;
            break
        } else {
            println!("Invalid address, try again.");
            input.clear();
        }
    }

    input.clear();
    print!("What amount would you like to send? ");
    std::io::stdout().flush()?;
    std::io::stdin().read_line(&mut input)?;
    let mut amount = input.trim().parse();
    while let Err(_) = amount {
        print!("Could not parse, try again: ");
        std::io::stdout().flush()?;
        input.clear();
        match std::io::stdin().read_line(&mut input) {
            Ok(_) => amount = f64::from_str(&input.trim()), // just doing it different ways for funsies
            Err(_) => {}
        }
    }
    let amount = amount.unwrap();
    println!("Sending {} ETH", amount);

    let txn = wallet::ethereum::create_txn(to_addr, amount);

    let mnemonic = wallet.get_mnemonic()?;
    let sec_key = get_sec_key(&mnemonic)?;

    let txn_hash = wallet::ethereum::sign_and_send(txn, &sec_key).await?;
    println!("Transaction hash: {:?}", txn_hash);

    Ok(())
}

// UTILITY FUNCTIONS

pub fn wei_to_eth(wei: U256) -> f64 {
    // We're losing some precision here
    let wei = wei.as_u128() as f64;
    wei / 1_000_000_000_000_000_000.0
}

pub fn eth_to_wei(eth: f64) -> U256 {
    let wei = eth * 1_000_000_000_000_000_000.0;
    U256::from(wei as u128)
}
