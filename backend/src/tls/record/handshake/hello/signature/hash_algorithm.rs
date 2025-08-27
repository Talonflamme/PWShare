use crate::tls::ReadableFromStream;
use pwshare_macros::FromRepr;

#[repr(u8)]
#[derive(FromRepr, Clone, Copy, Debug)]
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
    fn read(stream: &mut impl Iterator<Item = u8>) -> std::io::Result<Self> {
        let u = u8::read(stream)?;

        Ok(Self::try_from(u).unwrap_or(Self::Unknown))
    }
}
