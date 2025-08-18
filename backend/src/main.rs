use tls::tls_main;

mod cryptography;
mod util;
mod tls;

pub fn main() {
    tls_main::start_server().unwrap();
}
