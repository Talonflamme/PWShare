use super::certificate_request::CertificateRequest;
use super::certificate_verify::CertificateVerify;
use super::client_hello::ClientHello;
use super::client_key_exchange::ClientKeyExchange;
use super::finished::Finished;
use super::hello_request::HelloRequest;
use super::server_certificate::ServerCertificate;
use super::server_hello::ServerHello;
use super::server_hello_done::ServerHelloDone;
use super::server_key_exchange::ServerKeyExchange;
use crate::tls::ReadableFromStream;
use pwshare_macros::ReadableFromStream;
use std::fmt::Debug;
use std::io::{self, ErrorKind, Result};

#[repr(u8)]
#[derive(Debug, ReadableFromStream)]
pub enum HandshakeType {
    HelloRequest(HelloRequest) = 0,              // 0x00
    ClientHello(ClientHello) = 1,                // 0x01
    ServerHello(ServerHello) = 2,                // 0x02
    Certificate(ServerCertificate) = 11,         // 0x0b // TODO: not sure which to use here
    ServerKeyExchange(ServerKeyExchange) = 12,   // 0x0c
    CertificateRequest(CertificateRequest) = 13, // 0x0d
    ServerHelloDone(ServerHelloDone) = 14,       // 0x0e
    CertificateVerify(CertificateVerify) = 15,   // 0x0f
    ClientKeyExchange(ClientKeyExchange) = 16,   // 0x10
    Finished(Finished) = 20,                     // 0x14
}

#[derive(Debug)]
/// Part of a record, a `Handshake` contains the message type, a length and a body (inside the `msg_type`).
pub struct Handshake {
    msg_type: HandshakeType,
    /// This length is actually 24 bits, not 32
    length: u32,
}

impl Handshake {
    /// Reads the handshake from the supplied bytes.
    pub fn read_from_bytes(bytes: &[u8]) -> Result<Handshake> {
        // in TLS, the length is u24
        // since there is no u24 type in rust, the first byte of the u32 is 0.
        let length = u32::from_be_bytes([0x00, bytes[1], bytes[2], bytes[3]]);

        // we need to do a bit of trickery here:
        // our `read` expects first the msg_type (1 byte) followed by the actual
        // content, but the `msg_type` is at bytes[0] followed by 3 bytes we need to ignore (length)
        // and then the content. Therefore, we prepend the `msg_type` byte followed by the content
        // to correctly parse it
        let mut iter =
            std::iter::once(bytes[0]).chain(bytes.iter().skip(4).take(length as usize).copied());

        let typ = HandshakeType::read(&mut iter)?;

        Ok(Handshake {
            length,
            msg_type: typ,
        })
    }
}
