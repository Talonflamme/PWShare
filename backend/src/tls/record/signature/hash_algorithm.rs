use crate::cryptography::hashing::{self, HashFunction};
use pwshare_macros::{ReadableFromStream, WritableToSink};

#[repr(u8)]
#[derive(Clone, Copy, Debug, ReadableFromStream, WritableToSink)]
#[fallback(Unknown)]
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

impl HashAlgorithm {
    pub fn hasher(self) -> Option<Box<dyn HashFunction>> {
        match self {
            HashAlgorithm::None => None,
            HashAlgorithm::Unknown => None,
            HashAlgorithm::Md5 => Some(Box::new(hashing::Md5)),
            HashAlgorithm::Sha1 => Some(Box::new(hashing::Sha1)),
            HashAlgorithm::Sha224 => Some(Box::new(hashing::Sha224)),
            HashAlgorithm::Sha256 => Some(Box::new(hashing::Sha256)),
            HashAlgorithm::Sha384 => Some(Box::new(hashing::Sha384)),
            HashAlgorithm::Sha512 => Some(Box::new(hashing::Sha512)),
        }
    }

    /// Return the ASN.1 DER object identifier of the hash algorithm.
    pub fn object_identifier(&self) -> Option<Vec<u32>> {
        match self {
            HashAlgorithm::None => None,
            HashAlgorithm::Unknown => None,
            HashAlgorithm::Md5 => Some(vec![1, 2, 840, 113549, 2, 5]),
            HashAlgorithm::Sha1 => Some(vec![1, 3, 14, 3, 2, 26]),
            HashAlgorithm::Sha224 => Some(vec![2, 16, 840, 1, 101, 3, 4, 2, 4]),
            HashAlgorithm::Sha256 => Some(vec![2, 16, 840, 1, 101, 3, 4, 2, 1]),
            HashAlgorithm::Sha384 => Some(vec![2, 16, 840, 1, 101, 3, 4, 2, 2]),
            HashAlgorithm::Sha512 => Some(vec![2, 16, 840, 1, 101, 3, 4, 2, 3]),
        }
    }
}
