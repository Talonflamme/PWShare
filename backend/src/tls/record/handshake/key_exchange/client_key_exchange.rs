use crate::tls::record::alert::{Alert, Result};
use crate::tls::record::ciphers::cipher_suite::CipherConfig;
use crate::tls::record::ciphers::key_exchange_algorithm::KeyExchangeAlgorithm;
use crate::tls::record::handshake::key_exchange::rsa::EncryptedPreMasterSecret;
use crate::tls::record::key_exchange::ecdhe::ClientECDiffieHellmanPublic;
use crate::tls::{ReadableFromStream, Sink, WritableToSink};
use pwshare_macros::{ReadableFromStream, WritableToSink};

#[derive(Debug, ReadableFromStream, WritableToSink)]
pub struct ClientKeyExchange {
    pub exchange_keys: ExchangeKeys,
}

/// The field `exchange_keys` of `ClientKeyExchange`.
/// Depends on the KeyExchangeAlgorithm `cipher_suite.key_exchange`
#[derive(Debug)]
pub enum ExchangeKeys {
    Rsa(EncryptedPreMasterSecret),
    Ecdh(ClientECDiffieHellmanPublic),
}

impl WritableToSink for ExchangeKeys {
    fn write(&self, buffer: &mut impl Sink<u8>, suite: Option<&CipherConfig>) -> Result<()> {
        let kx = &suite
            .ok_or_else(|| Alert::internal_error("ExchangeKeys written when suite is null"))?
            .key_exchange;

        match self {
            ExchangeKeys::Rsa(rsa) => {
                if matches!(kx, KeyExchangeAlgorithm::Rsa) {
                    rsa.write(buffer, suite)?;
                    return Ok(());
                }
            }
            ExchangeKeys::Ecdh(ecdh) => {
                if matches!(kx, KeyExchangeAlgorithm::Ecdhe) {
                    ecdh.write(buffer, suite)?;
                    return Ok(());
                }
            }
        }

        Err(Alert::internal_error(format!(
            "Unexpected key exchange algorithm {:?} for {:?}",
            kx, self
        )))
    }
}

impl ReadableFromStream for ExchangeKeys {
    fn read(stream: &mut impl Iterator<Item = u8>, suite: Option<&CipherConfig>) -> Result<Self> {
        match suite.unwrap().key_exchange {
            KeyExchangeAlgorithm::Null => Err(Alert::internal_error(
                "Cannot read ExchangeKeys when Key Exchange is null",
            )),
            KeyExchangeAlgorithm::Rsa => {
                Ok(Self::Rsa(EncryptedPreMasterSecret::read(stream, suite)?))
            }
            KeyExchangeAlgorithm::Ecdhe => Ok(Self::Ecdh(ClientECDiffieHellmanPublic::read(
                stream, suite,
            )?)),
        }
    }
}
