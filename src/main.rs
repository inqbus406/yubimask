//extern crate core; // What tf is this and where did it come from? Seems to work without it??
#![allow(dead_code)]
use std::io::Write;
use std::ops::Deref;
use anyhow::{bail, Result};
use clap::Parser;
use crate::wallet::{get_yk_response, Wallet}; // only for testing
use colored::*;

mod wallet;

#[tokio::main]
async fn main() -> Result<()> {
    println!("{}", " __   __          _       _   __  __                 _    ".color("yellow"));
    println!("{}", " \\ \\ / /  _   _  | |__   (_) |  \\/  |   __ _   ___  | | __".color("yellow"));
    println!("{}", "  \\ V /  | | | | | \'_ \\  | | | |\\/| |  / _` | / __| | |/ /".color("yellow"));
    println!("{}", "   | |   | |_| | | |_) | | | | |  | | | (_| | \\__ \\ |   < ".color("yellow"));
    println!("{}", "   |_|    \\__,_| |_.__/  |_| |_|  |_|  \\__,_| |___/ |_|\\_\\\n".color("yellow"));
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

    // Not pursuing a GUI for the time being
    // if args.vis {
    //     MainWindow::new().run();
    // }

    if args.create {
        let fname = args.name.clone();

        if !args.debug {
            let mut response = String::new();
            print!("Would you like to program your keys alike? This only needs to be done once. (y/n) ");
            std::io::stdout().flush()?;
            std::io::stdin().read_line(&mut response)?;
            if response.to_lowercase().contains('y') {
                wallet::program_keys()?;
            }
        }

        // TODO ask for wallet language here

        let wallet = Wallet::new(&fname, args.debug);
        wallet.write_to_file()?;
    } else if args.import {
        let mut name = String::new();
        let mut seed_phrase = String::new();
        print!("What would you like to name this wallet? ");
        std::io::stdout().flush()?;
        std::io::stdin().read_line(&mut name)?;

        print!("Enter 24-word seed phrase: ");
        std::io::stdout().flush()?;
        std::io::stdin().read_line(&mut seed_phrase)?;

        // TODO ask for wallet language here

        let wallet = Wallet::import(name.trim(), seed_phrase.trim(), args.debug)
            .expect("Couldn't import from this seed phrase, is it valid?");
        wallet.write_to_file()?;
    } else {
        let mut wallet = match Wallet::read_from_file(&args.name) {
            Ok(w) => w,
            Err(e) => {
                println!("{}", "No wallet found! Try creating a wallet with the argument -c.".color("red"));
                panic!("File not found! {}", e)}
        };

        show_help();
        loop {
            let mut response = String::new();
            print!("> ");
            std::io::stdout().flush()?;
            std::io::stdin().read_line(&mut response)?;
            match response.trim().to_lowercase().deref() {
                "view" => { wallet.print_balances().await?; },
                "send" => { wallet.send().await?; },
                "receive" => { wallet.receive()?; },
                "exit" | "quit" => { break; },
                "export" => { wallet.show_seed_phrase()? },
                "help" => { show_help(); },
                _ => { println!("Unrecognized command! Try \"help\"") }
            };
        }
    }

    Ok(())
}

fn show_help() {
    println!("What would you like to do?");
    println!("{} {}", "  view: ".green().bold(), "view balances".italic());
    println!("{} {}", "  send: ".green().bold(), "send crypto".italic());
    println!("{} {}", "  receive: ".green().bold(), "get wallet address".italic());
    println!("{} {}", "  export: ".green().bold(), "show seed phrase".italic());
    println!("{} {}", "  help: ".green().bold(), "show this description of commands".italic());
    println!("{} {}", "  exit: ".green().bold(), "quit YubiMask".italic());
}

/// A secure cryptocurrency wallet leveraging encryption with hardware second factors.
#[derive(Parser, Debug)]
#[clap(author, version, about, long_about = None)]
struct Args {
    /// Create a new wallet
    #[clap(short, long)]
    create: bool,

    /// Wallet name (default: wallet.ym)
    #[clap(short, long, default_value = "wallet.ym")]
    name: String,

    // /// Start GUI
    // #[clap(short, long)]
    // vis: bool,

    /// Import a wallet from a 24-word BIP39 seed phrase.
    #[clap(short, long)]
    import: bool,

    /// Debug mode (no yubikey)
    #[clap(short, long)]
    debug: bool
}

// GUI is a stretch goal, and it sounds like slint might not be the best framework to use from a security
// perspective... RIP

// slint::slint! {
//     MainWindow := Window {
//         Text {
//             text: "Welcome to YubiMask!";
//             color: green;
//         }
//     }
// }
