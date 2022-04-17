// A wallet module specifically for the Ethereum network.
// We might want to make a "wallets" module later to include all
// networks if we add more.
// A substantial portion of this code is taken from https://tms-dev-blog.com/build-a-crypto-wallet-using-rust/

use secp256k1::{PublicKey, SecretKey};
use secp256k1::rand::{rngs, SeedableRng};
use web3::types::Address;
use tiny_keccak::keccak256;
use rand::RngCore;
use rand::rngs::{OsRng, EntropyRng}; // May want to use EntropyRing as a fallback

pub fn gen_keypair() -> (SecretKey, PublicKey) {
    let secp = secp256k1::Secp256k1::new();
    let mut rng;
    let num;
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
