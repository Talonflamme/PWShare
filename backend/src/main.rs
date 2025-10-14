use crate::tls::tls_main;

mod cryptography;
mod util;
mod tls;

fn hex_to_vec(hex: &str) -> Vec<u8> {
    (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..=i+1], 16).unwrap())
        .collect()
}

pub fn main() {
    tls_main::start_server().unwrap();
}
