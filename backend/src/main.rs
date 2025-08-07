use crate::cryptography::aes::{self, AESKey256};
use crate::cryptography::pem::{FromPemContent, ToPemContent};
use crate::cryptography::rsa::{self};
use crate::util::UintDisplay;
use crypto_bigint::{BitOps, Uint};
use cryptography::oaep;
use rouille::{input::plain_text_body, try_or_400, Request, Response};
use std::fs;
use std::sync::Mutex;

mod cryptography;
mod util;

fn handle_request(request: &Request, message: &Mutex<Option<String>>) -> Response {
    let method = request.method();
    let response = match method {
        "POST" => handle_post(request, message),
        "GET" => handle_get(request, message),
        "DELETE" => handle_delete(request, message),
        _ => Response::text(format!("HTTP Method `{}` unsupported.", method)).with_status_code(501), // Not Implemented
    };
    response
}

fn handle_post(request: &Request, message: &Mutex<Option<String>>) -> Response {
    let content = try_or_400!(plain_text_body(request));

    *message.lock().unwrap() = Some(content); // assign content to message

    // basic 201 response
    Response::empty_400().with_status_code(201) // Created
}

fn handle_get(request: &Request, message: &Mutex<Option<String>>) -> Response {
    let lock = message.lock().unwrap();

    if let Some(msg) = lock.as_ref() {
        Response::text(msg)
    } else {
        Response::empty_404() // not found
    }
}

fn handle_delete(request: &Request, message: &Mutex<Option<String>>) -> Response {
    *message.lock().unwrap() = None;

    Response::empty_400().with_status_code(200) // OK
}

fn start_server() {
    let mutex: Mutex<Option<String>> = Mutex::new(None);

    rouille::start_server("0.0.0.0:4981", move |request| {
        handle_request(request, &mutex).with_additional_header("Access-Control-Allow-Origin", "*")
        // TODO: Cors
    });
}

fn rsa_demo() {
    let (pub_key, prv_key) = rsa::generate_key!(48);

    let message: Uint<1> = Uint::from(69420u32);
    let message = message.to_be_bytes();

    let padded = oaep::pad(&message, pub_key.n.bytes_precision()).unwrap();
    let encoded = pub_key.encode(Uint::from_be_slice(padded.as_slice()));

    println!("Encoded: {}", encoded.hex());

    let decoded = prv_key.decode(encoded).to_be_bytes();
    let unpadded = oaep::unpad(&decoded, pub_key.n.bytes_precision()).unwrap();

    println!("Decoded: {}", unpadded.hex());
}

fn pem_demo() {
    let (pub_key, prv_key) = rsa::generate_key!(48);

    let pem = pub_key.to_pem_content();
    fs::write("public_key.pem", pem).unwrap();

    let pem = prv_key.to_pem_content();
    fs::write("private_key.pem", pem).unwrap();
}

pub fn main() {
    let key = AESKey256::new_random();
    let message: u128 = 0x1169420;
    let cipher: u128 = aes::aes_encrypt(message, key);

    println!("Message: {:x}", message);
    println!("Cipher : {:x}", cipher);
}
