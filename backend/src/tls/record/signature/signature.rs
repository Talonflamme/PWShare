use super::SignatureAlgorithm;
use crate::tls::record::alert::{Alert, Result};
use crate::tls::record::ciphers::cipher_suite::CipherConfig;
use crate::tls::record::cryptographic_attributes::DigitallySigned;
use crate::tls::{ReadableFromStream, Sink, WritableToSink};

#[derive(Debug)]
pub enum Signature {
    Anonymous(),
    RSA(DigitallySigned),
    DSA(DigitallySigned),
    ECDSA(DigitallySigned),
}

impl ReadableFromStream for Signature {
    fn read(stream: &mut impl Iterator<Item = u8>, suite: Option<&CipherConfig>) -> Result<Self> {
        let s = suite.ok_or(Alert::internal_error(
            "Reading Signature when no cipher suite is negotiated",
        ))?;

        match s.signature {
            SignatureAlgorithm::Anonymous => Ok(Self::Anonymous()),
            SignatureAlgorithm::RSA => Ok(Self::RSA(DigitallySigned::read(stream, suite)?)),
            SignatureAlgorithm::DSA => Ok(Self::DSA(DigitallySigned::read(stream, suite)?)),
            SignatureAlgorithm::ECDSA => Ok(Self::ECDSA(DigitallySigned::read(stream, suite)?)),
            SignatureAlgorithm::Unknown => Err(Alert::internal_error(
                "Unknown SignatureAlgorithm negotiated",
            )),
        }
    }
}

impl WritableToSink for Signature {
    fn write(&self, buffer: &mut impl Sink<u8>, suite: Option<&CipherConfig>) -> Result<()> {
        match self {
            Signature::Anonymous() => {}
            Signature::RSA(ds) => ds.write(buffer, suite)?,
            Signature::DSA(ds) => ds.write(buffer, suite)?,
            Signature::ECDSA(ds) => ds.write(buffer, suite)?,
        }

        Ok(())
    }
}
