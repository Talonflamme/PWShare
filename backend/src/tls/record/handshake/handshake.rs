use super::hello::{ClientHello, HelloRequest, ServerHello, ServerHelloDone};
use super::{
    CertificateRequest, CertificateVerify, ClientKeyExchange, Finished,
    ServerKeyExchange,
};
use crate::tls::record::certificate::Certificate;
use crate::tls::record::writable_to_sink::{Sink, WritableToSink};
use crate::tls::record::{ContentType, RecordFragment};
use crate::tls::ReadableFromStream;
use pwshare_macros::{ReadableFromStream, WritableToSink};
use std::fmt::Debug;
use std::io::{Error, ErrorKind, Result};

#[repr(u8)]
#[derive(Debug, ReadableFromStream, WritableToSink)]
pub enum HandshakeType {
    HelloRequest(HelloRequest) = 0,              // 0x00
    ClientHello(ClientHello) = 1,                // 0x01
    ServerHello(ServerHello) = 2,                // 0x02
    Certificate(Certificate) = 11,               // 0x0b
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
    pub msg_type: HandshakeType,
}

impl Handshake {
    pub fn new(msg_type: HandshakeType) -> Self {
        Handshake { msg_type }
    }
}

impl ReadableFromStream for Handshake {
    fn read(stream: &mut impl Iterator<Item = u8>) -> Result<Self> {
        let [bytes0, bytes1, bytes2, bytes3] = u32::read(stream)?.to_be_bytes();

        // in TLS, the length is u24
        // since there is no u24 type in rust, the first byte of the u32 is 0.
        let length = u32::from_be_bytes([0x00, bytes1, bytes2, bytes3]);

        // we need to do a bit of trickery here:
        // our `read` expects first the msg_type (1 byte) followed by the actual
        // content, but the `msg_type` is at bytes[0] followed by 3 bytes we need to ignore (length)
        // and then the content. Therefore, we prepend the `msg_type` byte followed by the content
        // to correctly parse it
        let mut iter = std::iter::once(bytes0).chain(stream.take(length as usize));

        let typ = HandshakeType::read(&mut iter)?;

        Ok(Handshake { msg_type: typ })
    }
}

impl WritableToSink for Handshake {
    fn write(&self, buffer: &mut impl Sink<u8>) -> Result<()> {
        let mut body_buffer: Vec<u8> = Vec::new();

        let typ = match &self.msg_type {
            HandshakeType::HelloRequest(hr) => {
                hr.write(&mut body_buffer)?;
                0
            }
            HandshakeType::ClientHello(ch) => {
                ch.write(&mut body_buffer)?;
                1
            }
            HandshakeType::ServerHello(sh) => {
                sh.write(&mut body_buffer)?;
                2
            }
            HandshakeType::Certificate(c) => {
                c.write(&mut body_buffer)?;
                11
            }
            HandshakeType::ServerKeyExchange(ske) => {
                ske.write(&mut body_buffer)?;
                12
            }
            HandshakeType::CertificateRequest(cr) => {
                cr.write(&mut body_buffer)?;
                13
            }
            HandshakeType::ServerHelloDone(shd) => {
                shd.write(&mut body_buffer)?;
                14
            }
            HandshakeType::CertificateVerify(cv) => {
                cv.write(&mut body_buffer)?;
                15
            }
            HandshakeType::ClientKeyExchange(cke) => {
                cke.write(&mut body_buffer)?;
                16
            }
            HandshakeType::Finished(f) => {
                f.write(&mut body_buffer)?;
                20
            }
        };

        buffer.push(typ);

        if body_buffer.len() >= (1 << 24) {
            return Err(Error::new(
                ErrorKind::InvalidData,
                format!(
                    "Length is too large: {}, only 24 bytes allowed.",
                    body_buffer.len()
                ),
            ));
        }

        let len_bytes_be = body_buffer.len().to_be_bytes();

        // save length as 24-bit integer
        buffer.extend_from_slice(&len_bytes_be[len_bytes_be.len() - 3..]); // least significant 3 bytes

        // body
        buffer.extend(body_buffer.into_iter());

        Ok(())
    }
}

impl RecordFragment for Handshake {
    const CONTENT_TYPE: ContentType = ContentType::Handshake;

    fn to_data(&self) -> Result<Vec<u8>> {
        let mut buf = Vec::new();
        self.write(&mut buf)?;
        Ok(buf)
    }
}
