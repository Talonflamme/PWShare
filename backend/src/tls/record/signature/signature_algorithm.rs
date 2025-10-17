use super::{rsa, HashAlgorithm, Signature, SignatureAndHashAlgorithm};
use crate::tls::connection::RSA_KEY;
use crate::tls::record::alert::{Alert, Result};
use crate::tls::record::ciphers::cipher_suite::CipherConfig;
use crate::tls::record::cryptographic_attributes::DigitallySigned;
use crate::tls::{ReadableFromStream, Sink, WritableToSink};
use pwshare_macros::{FromRepr, IntoRepr};

#[repr(u8)]
#[derive(FromRepr, Clone, Copy, Debug, IntoRepr)]
pub enum SignatureAlgorithm {
    Anonymous = 0,
    RSA = 1,
    DSA = 2,
    ECDSA = 3,
    Unknown = 255,
}

impl SignatureAlgorithm {
    pub fn sign(self, message: &[u8], hash: HashAlgorithm) -> Result<Signature> {
        let sig_and_hash = SignatureAndHashAlgorithm {
            hash,
            signature: self,
        };

        match &sig_and_hash.signature {
            SignatureAlgorithm::Anonymous => Ok(Signature::Anonymous()),
            SignatureAlgorithm::RSA => Ok(Signature::RSA(DigitallySigned {
                signature: rsa::sign(RSA_KEY.as_ref()?, message, &sig_and_hash.hash)?.into(),
                algorithm: sig_and_hash,
            })),
            SignatureAlgorithm::DSA => {
                Err(Alert::internal_error("DSA negotiated when not implemented"))
            }
            SignatureAlgorithm::ECDSA => Err(Alert::internal_error(
                "ECDSA negotiated when not implemented",
            )),
            SignatureAlgorithm::Unknown => Err(Alert::internal_error(
                "Reading Signature when signature_algorithm is unknown",
            )),
        }
    }
}

impl ReadableFromStream for SignatureAlgorithm {
    fn read(stream: &mut impl Iterator<Item = u8>, suite: Option<&CipherConfig>) -> Result<Self> {
        let u = u8::read(stream, suite)?;

        Ok(Self::try_from(u).unwrap_or(Self::Unknown))
    }
}

impl WritableToSink for SignatureAlgorithm {
    fn write(&self, buffer: &mut impl Sink<u8>, suite: Option<&CipherConfig>) -> Result<()> {
        if matches!(self, Self::Unknown) {
            Err(Alert::internal_error(
                "Cannot write unknown SignatureAlgorithm",
            )) // should not occur
        } else {
            let u: u8 = self.into();
            u.write(buffer, suite)
        }
    }
}
