use crate::tls::record::alert::{Alert, Result};
use crate::tls::{ReadableFromStream, Sink, WritableToSink};
use pwshare_macros::{ReadableFromStream, WritableToSink};
use super::ecdhe::elliptic_curve::ServerECDHParams;

#[derive(Debug)]
pub enum ServerKeyExchange {
    EcDiffieHellman(ServerKeyExchangeEcDiffieHellman),
}

impl ReadableFromStream for ServerKeyExchange {
    fn read(_: &mut impl Iterator<Item = u8>) -> Result<Self> {
        // In order to actually read this, we would need to change the
        // `ReadableFromStream` trait to somehow know about the KeyExchangeAlgorithm,
        // which is used. This change is not necessary though, since we only implement
        // the server and the Client will never send it. Therefore, we will never have to read
        // it.
        Err(Alert::internal_error("Can't read `ServerKeyExchange`"))
    }
}

impl WritableToSink for ServerKeyExchange {
    fn write(&self, buffer: &mut impl Sink<u8>) -> Result<()> {
        match self {
            ServerKeyExchange::EcDiffieHellman(ecdh) => ecdh.write(buffer),
        }
    }
}

#[derive(Debug, ReadableFromStream, WritableToSink)]
pub struct ServerKeyExchangeEcDiffieHellman {
    pub params: ServerECDHParams,
    pub signed_params: Signature,
}

#[derive(Debug)]
pub struct Signature {
    bytes: Vec<u8>,
}

impl ReadableFromStream for Signature {
    fn read(stream: &mut impl Iterator<Item=u8>) -> Result<Self> {
        todo!()
    }
}

impl WritableToSink for Signature {
    fn write(&self, buffer: &mut impl Sink<u8>) -> Result<()> {
        todo!()
    }
}
