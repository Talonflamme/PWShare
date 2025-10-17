use crate::tls::tls_main;

mod cryptography;
mod tls;
mod util;

pub fn main() {
    tls_main::start_server().unwrap();
}
