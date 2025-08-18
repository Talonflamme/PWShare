use super::certificate_request::CertificateRequest;
use super::certificate_verify::CertificateVerify;
use super::client_certificate::ClientCertificate;
use super::client_hello::ClientHello;
use super::client_key_exchange::ClientKeyExchange;
use super::finished::Finished;
use super::hello_request::HelloRequest;
use super::server_certificate::ServerCertificate;
use super::server_hello::ServerHello;
use super::server_hello_done::ServerHelloDone;
use super::server_key_exchange::ServerKeyExchange;
use std::fmt::Debug;
use std::io::{self, ErrorKind, Result};

#[repr(u8)]
#[derive(Debug)]
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

        let rem_bytes = &bytes[..length as usize];

        let typ = match bytes[0] {
            0 => Ok(HandshakeType::HelloRequest(HelloRequest::new(rem_bytes)?)),
            1 => Ok(HandshakeType::ClientHello(ClientHello::new(rem_bytes)?)),
            2 => Ok(HandshakeType::ServerHello(ServerHello::new(rem_bytes)?)),
            11 => Ok(HandshakeType::Certificate(ServerCertificate::new(
                rem_bytes,
            )?)),
            12 => Ok(HandshakeType::ServerKeyExchange(ServerKeyExchange::new(
                rem_bytes,
            )?)),
            13 => Ok(HandshakeType::CertificateRequest(CertificateRequest::new(
                rem_bytes,
            )?)),
            14 => Ok(HandshakeType::ServerHelloDone(ServerHelloDone::new(
                rem_bytes,
            )?)),
            15 => Ok(HandshakeType::CertificateVerify(CertificateVerify::new(
                rem_bytes,
            )?)),
            16 => Ok(HandshakeType::ClientKeyExchange(ClientKeyExchange::new(
                rem_bytes,
            )?)),
            20 => Ok(HandshakeType::Finished(Finished::new(rem_bytes)?)),
            _ => Err(io::Error::new(
                ErrorKind::InvalidData,
                format!("Unexpected handshake type: {:02x}", bytes[0]),
            )),
        }?;

        Ok(Handshake {
            length,
            msg_type: typ,
        })
    }
}
