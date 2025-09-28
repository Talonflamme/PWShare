use crate::tls::record::alert::{Alert, Result};
use crate::tls::{ReadableFromStream, Sink, WritableToSink};
use pwshare_macros::{FromRepr, IntoRepr};

#[repr(u8)]
#[derive(FromRepr, Clone, Copy, Debug, IntoRepr)]
pub enum HashAlgorithm {
    None = 0,
    Md5 = 1,
    Sha1 = 2,
    Sha224 = 3,
    Sha256 = 4,
    Sha384 = 5,
    Sha512 = 6,
    Unknown = 255,
}

impl ReadableFromStream for HashAlgorithm {
    fn read(stream: &mut impl Iterator<Item = u8>) -> Result<Self> {
        let u = u8::read(stream)?;

        Ok(Self::try_from(u).unwrap_or(Self::Unknown))
    }
}

impl WritableToSink for HashAlgorithm {
    fn write(&self, buffer: &mut impl Sink<u8>) -> Result<()> {
        if matches!(self, Self::Unknown) {
            Err(Alert::internal_error()) // cannot write Unknown, should never come here
        } else {
            let u: u8 = self.into();
            u.write(buffer)
        }
    }
}
