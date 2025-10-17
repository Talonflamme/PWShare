use super::ecdhe::elliptic_curve::ServerECDHParams;
use crate::tls::record::alert::{Alert, Result};
use crate::tls::record::ciphers::cipher_suite::CipherConfig;
use crate::tls::record::ciphers::key_exchange_algorithm::KeyExchangeAlgorithm;
use crate::tls::record::signature::Signature;
use crate::tls::{ReadableFromStream, Sink, WritableToSink};
use pwshare_macros::{ReadableFromStream, WritableToSink};

#[derive(Debug)]
pub enum ServerKeyExchange {
    EcDiffieHellman(ServerKeyExchangeEcDiffieHellman),
}

impl ReadableFromStream for ServerKeyExchange {
    fn read(stream: &mut impl Iterator<Item = u8>, suite: Option<&CipherConfig>) -> Result<Self> {
        let s = suite.ok_or(Alert::internal_error(
            "Reading Signature when no cipher suite is negotiated",
        ))?;

        match s.key_exchange {
            KeyExchangeAlgorithm::Null => Err(Alert::unexpected_message()),
            KeyExchangeAlgorithm::Rsa => Err(Alert::unexpected_message()),
            KeyExchangeAlgorithm::Ecdhe => Ok(ServerKeyExchange::EcDiffieHellman(
                ServerKeyExchangeEcDiffieHellman::read(stream, suite)?,
            )),
        }
    }
}

impl WritableToSink for ServerKeyExchange {
    fn write(&self, buffer: &mut impl Sink<u8>, suite: Option<&CipherConfig>) -> Result<()> {
        match self {
            ServerKeyExchange::EcDiffieHellman(ecdh) => ecdh.write(buffer, suite),
        }
    }
}

#[derive(Debug, ReadableFromStream, WritableToSink)]
pub struct ServerKeyExchangeEcDiffieHellman {
    pub params: ServerECDHParams,
    pub signed_params: Signature,
}
