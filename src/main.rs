use std::ops::Deref;
use yubico_manager::Yubico;
use yubico_manager::config::{Config, Mode, Slot};

mod ethereum;

fn main() {
    MainWindow::new().run();
    println!("Welcome to YubiMask!");
    get_yk_response();
}

slint::slint! {
    MainWindow := Window {
        Text {
            text: "Welcome to YubiMask!";
            color: green;
        }
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
        let hmac_result = yubi.challenge_response_hmac(challenge.as_bytes(), config)
            .unwrap();

        let hexval = hmac_result.deref();
        println!("{:?}", hmac_result);
        let hexstring = hex::encode(hexval);
        println!("Response: {}", hexstring);

    } else {
        println!("Yubikey not found.");
    }
}
