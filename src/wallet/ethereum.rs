// A wallet module specifically for the Ethereum network.
// We might want to make a "wallets" module later to include all
// networks if we add more.
// A substantial portion of this code is taken from https://tms-dev-blog.com/build-a-crypto-wallet-using-rust/

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
use crate::wallet;
use crate::wallet::Wallet;

// For connecting to the ETH network
const ETH_MAINNET_ENDPOINT: &str = "wss://mainnet.infura.io/ws/v3/465e5058a793440bb743994f856841af";
const ETH_RINKEBY_ENDPOINT: &str = "wss://rinkeby.infura.io/ws/v3/465e5058a793440bb743994f856841af";
const INFURA_PROJECT_ID: &str = "465e5058a793440bb743994f856841af";
const INFURA_PROJECT_SECRET: &str = "adfcf1aac28349c4a67cd80b04287e91"; // Probably shouldn't have this in plaintext...

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

// Returns the balance in wei
pub async fn get_balance(wallet: &Wallet, conn: &Web3<WebSocket>) -> Result<U256> {
    let addr = Address::from_str(&wallet.addr)?;
    Ok(conn.eth().balance(addr, None).await?)
}

pub async fn get_balance_eth(wallet: &Wallet, conn: &Web3<WebSocket>) -> Result<f64> {
    Ok(wei_to_eth(get_balance(wallet, conn).await?))
}

pub fn create_txn(addr: Address, eth: f64) -> TransactionParameters {
    TransactionParameters {
        to: Some(addr),
        value: eth_to_wei(eth),
        ..Default::default()
    }
}

pub async fn sign_and_send(conn: &Web3<WebSocket>, txn: TransactionParameters, sec_key: &SecretKey) -> Result<H256> {
    let txn = conn.accounts().sign_transaction(txn, sec_key).await?;
    let result = conn.eth().send_raw_transaction(txn.raw_transaction).await?;
    Ok(result)
}

pub async fn send(conn: &Web3<WebSocket>, sec_key: &SecretKey) -> Result<()> {
    println!("Sending ETH...");
    let mut input = String::new();
    print!("What address would you like to send to? ");
    std::io::stdout().flush();
    std::io::stdin().read_line(&mut input);
    let to_addr = Address::from_str(&input)?;

    input.clear();
    print!("What amount would you like to send? ");
    std::io::stdout().flush();
    std::io::stdin().read_line(&mut input);
    let mut amount = input.trim().parse();
    while let Err(_) = amount {
        print!("Could not parse, try again: ");
        std::io::stdout().flush();
        input.clear();
        std::io::stdin().read_line(&mut input);
        amount = f64::from_str(&input.trim()); // just doing it different ways for funsies
    }
    let amount = amount.unwrap();
    println!("Sending {} ETH", amount);

    //let to_addr = Address::from_str("0x5841eb5ccb285C262AD4d9A4144f63B5358DB54e")?;
    //let amount = 0.001;
    let txn = wallet::ethereum::create_txn(to_addr, amount);

    let txn_hash = wallet::ethereum::sign_and_send(&conn, txn, &sec_key).await?;
    println!("Transaction hash: {:?}", txn_hash);

    Ok(())
}

pub fn wei_to_eth(wei: U256) -> f64 {
    // We're losing some precision here
    let wei = wei.as_u128() as f64;
    wei / 1_000_000_000_000_000_000.0
}

pub fn eth_to_wei(eth: f64) -> U256 {
    let wei = eth * 1_000_000_000_000_000_000.0;
    U256::from(wei as u128)
}
