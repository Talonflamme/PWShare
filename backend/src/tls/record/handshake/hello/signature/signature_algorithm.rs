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

impl ReadableFromStream for SignatureAlgorithm {
    fn read(stream: &mut impl Iterator<Item = u8>) -> std::io::Result<Self> {
        let u = u8::read(stream)?;

        Ok(Self::try_from(u).unwrap_or(Self::Unknown))
    }
}


impl WritableToSink for SignatureAlgorithm {
    fn write(&self, buffer: &mut impl Sink<u8>) -> std::io::Result<()> {
        if matches!(self, Self::Unknown) {
            Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("Cannot write {:?}", self)
            ))
        } else {
            let u: u8 = self.into();
            u.write(buffer)
        }
    }
}
