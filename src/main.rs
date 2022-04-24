//extern crate core; // What tf is this and where did it come from? Seems to work without it??

use std::env;
use std::io::Write;
use std::ops::Deref;
use std::str::FromStr;
use anyhow::{bail, Result};
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

        // TODO ask for wallet language here

        let wallet = wallet::Wallet::new(&fname, args.debug);
        wallet.write_to_file()?;
    } else if args.import {
        let mut name = String::new();
        let mut seed_phrase = String::new();
        print!("What would you like to name this wallet? ");
        std::io::stdout().flush();
        std::io::stdin().read_line(&mut name);

        print!("Enter 24-word seed phrase: ");
        std::io::stdout().flush();
        std::io::stdin().read_line(&mut seed_phrase);

        // TODO ask for wallet language here

        let wallet = wallet::Wallet::import(name.trim(), seed_phrase.trim(), args.debug)
            .expect("Couldn't import from this seed phrase, is it valid?");
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

        loop {
            println!("What would you like to do?");
            println!("  1) view balance");
            println!("  2) send");
            println!("  3) receive (get wallet address)");
            println!("  4) exit");
            println!("  5) show seed phrase");

            let mut response = String::new();
            print!("> ");
            std::io::stdout().flush();
            std::io::stdin().read_line(&mut response);
            match response.trim().deref() {
                "1" => { wallet.print_balances(&conn).await?; },
                "2" => { wallet.send(&conn).await?; },
                "3" => { wallet.receive(); },
                "4" => { break; },
                "5" => { wallet.show_seed_phrase()? }
                _ => {}
            };
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
    #[clap(short, long, default_value = "wallet.ym")]
    name: String,

    /// Start GUI
    #[clap(short, long)]
    vis: bool,

    /// Import a wallet from a 24-word BIP39 seed phrase.
    #[clap(short, long)]
    import: bool,

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
