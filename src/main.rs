//extern crate core; // What tf is this and where did it come from? Seems to work without it??

use std::env;
use std::io::Write;
use std::str::FromStr;
use anyhow::Result;
use clap::Parser;
use crate::wallet::{get_yk_response, Wallet}; // only for testing
use secp256k1::{key, SecretKey};
use web3::transports::WebSocket;

// For ethereum
use web3::types::Address;
use web3::Web3;

mod wallet;

#[tokio::main]
async fn main() -> Result<()> {
    println!("Welcome to YubiMask!");
    let args = Args::parse();

    // For testing if yubikey chal/resp works on Windows
    // match wallet::is_programmed() {
    //     true => println!("Yubikey already programmed"),
    //     false => println!("Yubikey not programmed")
    // }
    // println!("{}", wallet::is_programmed());
    // let chal = b"test chal";
    // println!("{:?}", get_yk_response(chal)?);
    // return Ok(());

    // This is ihow I was doing it before I started using clap for parsing
    // let args: Vec<String> = env::args().skip(1).collect();
    // if args.contains(&String::from("-v")) {
    //     MainWindow::new().run();
    // }
    // if args.contains(&String::from("--new")) {
    if args.vis {
        MainWindow::new().run();
    }
    if args.create {
        // print!("Wallet name? ");
        // let mut fname = String::new();
        // std::io::stdin().read_line(&mut fname);
        let fname = args.name.clone();

        if !args.debug {
            let mut response = String::new();
            print!("Would you like to program your keys alike? This only needs to be done once. (y/n) ");
            std::io::stdout().flush();
            std::io::stdin().read_line(&mut response);
            if response.to_lowercase().contains('y') {
                wallet::program_keys();
            }
        }

        let (sec_key, pub_key) = wallet::ethereum::gen_keypair();
        println!("Secret key: {}", sec_key.to_string());
        println!("Public key: {}", pub_key.to_string());

        let addr = wallet::ethereum::address_from_pubkey(&pub_key);
        println!("Wallet address: {:?}", addr);

        let wallet = wallet::Wallet::new(&fname, &sec_key, &pub_key, &addr, args.debug);
        println!("{:?}", &wallet);
        wallet.write_to_file()?;
    } else {
        let mut wallet = match wallet::Wallet::read_from_file(&args.name) {
            Ok(w) => w,
            Err(e) => panic!("File not found! {}", e)
        };
        //println!("Read from file: {:?}", &wallet);

        // Connect to the network
        let conn = wallet::ethereum::connect().await?;

        // Print out the current block number
        let block = conn.eth().block_number().await?;
        println!("Block number: {}", &block);

        let addr = wallet::ethereum::address_from_pubkey(&wallet.get_pub_key()?);
        println!("Wallet address: {:?}", addr);

        // Print out the wallet balance
        let balance = wallet::ethereum::get_balance_eth(&wallet, &conn).await?;
        println!("Wallet balance: {} ETH", &balance);

        if args.send {
            println!("Sending!");
            if let Ok(sec_key) = wallet.get_sec_key(args.debug) {
                //println!("Decrypted secret key: {:?}", sec_key);
                wallet::ethereum::send(&conn, &sec_key).await?;
            } else {
                println!("Failed to decrypt secret key.");
            }
        }
    }
    //wallet::Wallet::encrypt_decrypt("test_message_string");

    Ok(())
}

/// A secure cryptocurrency wallet leveraging encryption with hardware second factors.
#[derive(Parser, Debug)]
#[clap(author, version, about, long_about = None)]
struct Args {
    /// Create a new wallet
    #[clap(short, long)]
    create: bool,

    /// Wallet name
    #[clap(short, long)]
    name: String,

    /// Start GUI
    #[clap(short, long)]
    vis: bool,

    /// Send (default 0.001 ETH)
    #[clap(short, long)]
    send: bool,

    /// Debug mode (no yubikey)
    #[clap(short, long)]
    debug: bool
}

slint::slint! {
    MainWindow := Window {
        Text {
            text: "Welcome to YubiMask!";
            color: green;
        }
    }
}
