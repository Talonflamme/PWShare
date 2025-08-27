use crate::tls::ReadableFromStream;
use pwshare_macros::FromRepr;

#[repr(u8)]
#[derive(FromRepr, Clone, Copy, Debug)]
pub enum SignatureAlgorithm {
    Anonymous = 0,
    RSA = 1,
    DSA = 2,
    ECDSA = 3,
    Unknown = 255,
}

impl ReadableFromStream for SignatureAlgorithm {
    fn read(stream: &mut impl Iterator<Item = u8>) -> std::io::Result<Self> {
        let u = u8::read(stream)?;

        Ok(Self::try_from(u).unwrap_or(Self::Unknown))
    }
}
