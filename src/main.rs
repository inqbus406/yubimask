extern crate core;

use std::env;
use anyhow::Result;

mod wallet;

fn main() -> Result<()> {
    println!("Welcome to YubiMask!");
    let args: Vec<String> = env::args().skip(1).collect();
    if args.contains(&String::from("-v")) {
        MainWindow::new().run();
    }
    if args.contains(&String::from("--new")) {
        let (sec_key, pub_key) = wallet::ethereum::gen_keypair();
        println!("Secret key: {}", sec_key.to_string());
        println!("Public key: {}", pub_key.to_string());

        let addr = wallet::ethereum::address_from_pubkey(&pub_key);
        println!("Wallet address: {:?}", addr);

        let wallet = wallet::Wallet::new("test_wallet2.ym", &sec_key, &pub_key, &addr);
        println!("{:?}", &wallet);
        wallet.write_to_file()?;
    } else {
        let mut wallet = match wallet::Wallet::read_from_file("test_wallet2.ym") {
            Ok(w) => w,
            Err(e) => panic!("File not found! {}", e)
        };
        println!("Read from file: {:?}", &wallet);
        println!("Decrypted secret key: {:?}", &mut wallet.get_sec_key().unwrap())
    }
    //wallet::Wallet::encrypt_decrypt("test_message_string");

    Ok(())
}

slint::slint! {
    MainWindow := Window {
        Text {
            text: "Welcome to YubiMask!";
            color: green;
        }
    }
}
