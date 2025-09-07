use std::fs;
use tls::tls_main;
use crate::cryptography::pem::{FromPemContent, ToPemContent};
use crate::cryptography::rsa;
use crate::cryptography::rsa::PrivateKey;

mod cryptography;
mod util;
mod tls;

pub fn main() {
    // tls_main::start_server().unwrap();
    let (pub_key, prv_key) = rsa::generate_key!(128);

    println!("{:#?}", prv_key);

    let pem = prv_key.to_pem_content();
    fs::write("private_key2.pem", pem.clone()).unwrap();

    let from_pem = PrivateKey::<2>::from_pem_content(pem).unwrap();

    println!("---------------------------------------------");
    println!("{:#?}", from_pem);

    println!("---------------------------------------------");
    println!("Eq: {}", prv_key == from_pem);
}
