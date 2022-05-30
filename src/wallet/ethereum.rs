/// A wallet module specifically for the Ethereum network.

use std::io::Write;
use std::str::FromStr;
use secp256k1::{PublicKey, SecretKey};
use tiny_keccak::keccak256;
use web3::Web3;
use web3::transports::WebSocket;
use web3::types::{Address, H256, TransactionParameters, U256};
use anyhow::Result;
use bip32::{Mnemonic, XPrv};
use serde::{Serialize, Deserialize};

use crate::wallet::Wallet;

// For connecting to the ETH network
const ETH_MAINNET_ENDPOINT: &str = "wss://mainnet.infura.io/ws/v3/465e5058a793440bb743994f856841af";
const ETH_RINKEBY_ENDPOINT: &str = "wss://rinkeby.infura.io/ws/v3/465e5058a793440bb743994f856841af";
const INFURA_PROJECT_ID: &str = "465e5058a793440bb743994f856841af";
const NETWORK_NAME: &str = "ETH";

fn address_from_pubkey(pub_key: &PublicKey) -> Address {
    let pub_key = pub_key.serialize_uncompressed();

    debug_assert_eq!(pub_key[0], 0x04);

    let hash = keccak256(&pub_key[1..]);

    Address::from_slice(&hash[12..])
}

async fn connect() -> Result<Web3<WebSocket>> {
    let url = ETH_RINKEBY_ENDPOINT;
    let conn = WebSocket::new(url).await?;
    Ok(Web3::new(conn))
}

pub fn get_addr(wallet: &mut Wallet) -> Result<Address> {
    if let Some(addr) = wallet.addrs.get(NETWORK_NAME) {
        Ok(Address::from_str(addr).unwrap())
    } else {
        let addr = address_from_pubkey(&get_pub_key(&wallet.get_mnemonic()?)?);
        wallet.addrs.insert(String::from(NETWORK_NAME), format!("{:?}", addr)); // to_string truncates the address
        Ok(addr)
    }
}

fn get_pub_key(mnemonic: &Mnemonic) -> Result<PublicKey> {
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
pub async fn get_balance(wallet: &mut Wallet) -> Result<U256> {
    // Connect to the network
    let conn = connect().await?;
    // Print out the current block number
    let block = conn.eth().block_number().await?;
    println!("Block number: {}", &block);

    if let Ok(addr) = get_addr(wallet) {
        Ok(conn.eth().balance(addr, None).await?)
    } else {
        Err(anyhow::Error::msg("Could not compute wallet address"))
    }
}

pub async fn get_balance_eth(wallet: &mut Wallet) -> Result<f64> {
    Ok(wei_to_eth(get_balance(wallet).await?))
}

pub async fn get_eth_value(eth: f64) -> Result<f64> {
    #[derive(Serialize, Deserialize)]
    struct Value {
        usd: f64
    }
    #[derive(Serialize, Deserialize)]
    struct Currency {
        ethereum: Value
    }
    let base = "https://api.coingecko.com/api/v3/simple/price";
    let params = [
        ("ids", "ethereum"),
        ("vs_currencies", "usd")
    ];
    let url = reqwest::Url::parse_with_params(base, &params)?;
    let response = reqwest::get(url).await?;
    let text = response.text().await?;
    // convert to json to parse the value
    let json: Currency = serde_json::from_str(&text).unwrap();
    Ok(json.ethereum.usd * eth)
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
    let conn = connect().await?;
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

    let txn = create_txn(to_addr, amount);

    let mnemonic = wallet.get_mnemonic()?;
    let sec_key = get_sec_key(&mnemonic)?;

    let txn_hash = sign_and_send(txn, &sec_key).await?;
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
