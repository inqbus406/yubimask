/// A module containing necessary functions to implement a Bitcoin wallet.

use std::str::FromStr;
use std::net::{IpAddr, Ipv4Addr, Shutdown, SocketAddr, TcpStream};
use std::time::{SystemTime, UNIX_EPOCH};
use std::{env, process};
use std::io::{Write, BufReader};

use bitcoin::consensus::{encode, Decodable};
use bitcoin::network::{address, constants, message, message_network};
use bitcoin::secp256k1;
use rand::Rng;

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
    test_handshake();

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

fn test_handshake() {
    let node = "195.179.201.150:8333";

    let address = SocketAddr::from_str(&node).unwrap();
    // let address: SocketAddr = node.parse().unwrap();

    let version_message = build_version_message(address);

    let first_message = message::RawNetworkMessage {
        magic: constants::Network::Bitcoin.magic(),
        payload: version_message,
    };

    if let Ok(mut stream) = TcpStream::connect(address) {
        // Send the message
        let _ = stream.write_all(encode::serialize(&first_message).as_slice());
        println!("Sent version message");

        // Setup StreamReader
        let read_stream = stream.try_clone().unwrap();
        let mut stream_reader = BufReader::new(read_stream);
        loop {
            // Loop an retrieve new messages
            let reply = message::RawNetworkMessage::consensus_decode(&mut stream_reader).unwrap();
            match reply.payload {
                message::NetworkMessage::Version(_) => {
                    println!("Received version message: {:?}", reply.payload);

                    let second_message = message::RawNetworkMessage {
                        magic: constants::Network::Bitcoin.magic(),
                        payload: message::NetworkMessage::Verack,
                    };

                    let _ = stream.write_all(encode::serialize(&second_message).as_slice());
                    println!("Sent verack message");
                }
                message::NetworkMessage::Verack => {
                    println!("Received verack message: {:?}", reply.payload);
                    break;
                }
                _ => {
                    println!("Received unknown message: {:?}", reply.payload);
                    break;
                }
            }
        }
        let _ = stream.shutdown(Shutdown::Both);
    } else {
        eprintln!("Failed to open connection");
    }
}

fn build_version_message(address: SocketAddr) -> message::NetworkMessage {
    // Building version message, see https://en.bitcoin.it/wiki/Protocol_documentation#version
    let my_address = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)), 0);

    // "bitfield of features to be enabled for this connection"
    let services = constants::ServiceFlags::NONE;

    // "standard UNIX timestamp in seconds"
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("Time error")
        .as_secs();

    // "The network address of the node receiving this message"
    let addr_recv = address::Address::new(&address, constants::ServiceFlags::NONE);

    // "The network address of the node emitting this message"
    let addr_from = address::Address::new(&my_address, constants::ServiceFlags::NONE);

    // "Node random nonce, randomly generated every time a version packet is sent. This nonce is used to detect connections to self."
    let nonce: u64 = rand::thread_rng().gen();

    // "User Agent (0x00 if string is 0 bytes long)"
    let user_agent = String::from("rust-example");

    // "The last block received by the emitting node"
    let start_height: i32 = 0;

    // Construct the message
    message::NetworkMessage::Version(message_network::VersionMessage::new(
        services,
        timestamp as i64,
        addr_recv,
        addr_from,
        nonce,
        user_agent,
        start_height,
    ))
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
