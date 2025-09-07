use crate::cryptography::pem::ToPemContent;
use crate::cryptography::rsa;
use std::fs;

mod cryptography;
mod util;
mod tls;

pub fn main() {
    // tls_main::start_server().unwrap();
    let (pub_key, prv_key) = rsa::generate_key!(3072);

    println!("{:#?}", prv_key);

    let pem = prv_key.to_pem_content();
    fs::write("private_key2.pem", pem.clone()).unwrap();
}
