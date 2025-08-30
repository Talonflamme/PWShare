use super::hello::{ClientHello, HelloRequest, ServerHello, ServerHelloDone};
use super::{
    CertificateRequest, CertificateVerify, ClientKeyExchange, Finished, ServerCertificate,
    ServerKeyExchange,
};
use crate::tls::ReadableFromStream;
use pwshare_macros::{ReadableFromStream, WritableToSink};
use std::fmt::Debug;
use std::io::Result;
use crate::tls::record::{ContentType, RecordFragment};
use crate::tls::record::writable_to_sink::{Sink, WritableToSink};

#[repr(u8)]
#[derive(Debug, ReadableFromStream, WritableToSink)]
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
    pub msg_type: HandshakeType,
    /// This length is actually 24 bits, not 32
    length: u32,
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

        Ok(Handshake {
            length,
            msg_type: typ,
        })
    }
}

impl WritableToSink for Handshake {
    fn write(&self, buffer: &mut impl Sink<u8>) -> Result<()> {
        todo!()
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
