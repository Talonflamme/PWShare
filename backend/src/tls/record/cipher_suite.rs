use pwshare_macros::{FromRepr, IntoRepr};
use crate::tls::{ReadableFromStream, Sink, WritableToSink};

#[repr(u16)]
#[derive(Debug, FromRepr, Clone, Copy, PartialEq, Eq, IntoRepr)]
pub enum CipherSuite {
    // initial, must not be used as it does not protect any data
    TlsNullWithNullNull = 0x0000,

    // Server must provide RSA certificate that can be used for key exchange
    TlsRsaWithNullMd5 = 0x0001,
    TlsRsaWithNullSha = 0x0002,
    TlsRsaWithNullSha256 = 0x003B,
    TlsRsaWithRc4128Md5 = 0x0004,
    TlsRsaWithRc4128Sha = 0x0005,
    TlsRsaWith3desEdeCbcSha = 0x000A,
    TlsRsaWithAes128CbcSha = 0x002f,
    TlsRsaWithAes256CbcSha = 0x0035,
    TlsRsaWithAes128CbcSha256 = 0x003c,
    TlsRsaWithAes256CbcSha256 = 0x003d,

    // Server-authenticated Diffie-Hellman
    TlsDhDssWith3desEdeCbcSha = 0x000D,
    TlsDhRsaWith3desEdeCbcSha = 0x0010,
    TlsDheDssWith3desEdeCbcSha = 0x0013,
    TlsDheRsaWith3desEdeCbcSha = 0x0016,
    TlsDhDssWithAes128CbcSha = 0x0030,
    TlsDhRsaWithAes128CbcSha = 0x0031,
    TlsDheDssWithAes128CbcSha = 0x0032,
    TlsDheRsaWithAes128CbcSha = 0x0033,
    TlsDhDssWithAes256CbcSha = 0x0036,
    TlsDhRsaWithAes256CbcSha = 0x0037,
    TlsDheDssWithAes256CbcSha = 0x0038,
    TlsDheRsaWithAes256CbcSha = 0x0039,
    TlsDhDssWithAes128CbcSha256 = 0x003E,
    TlsDhRsaWithAes128CbcSha256 = 0x003F,
    TlsDheDssWithAes128CbcSha256 = 0x0040,
    TlsDheRsaWithAes128CbcSha256 = 0x0067,
    TlsDhDssWithAes256CbcSha256 = 0x0068,
    TlsDhRsaWithAes256CbcSha256 = 0x0069,
    TlsDheDssWithAes256CbcSha256 = 0x006A,
    TlsDheRsaWithAes256CbcSha256 = 0x006B,

    // Anonymous Diffie-Hellman, must not be used unless explicitly requested by application layer
    TlsDhAnonWithRc4128Md5 = 0x0018,
    TlsDhAnonWith3desEdeCbcSha = 0x001B,
    TlsDhAnonWithAes128CbcSha = 0x0034,
    TlsDhAnonWithAes256CbcSha = 0x003A,
    TlsDhAnonWithAes128CbcSha256 = 0x006C,
    TlsDhAnonWithAes256CbcSha256 = 0x006D,

    Unknown = 0xFFFF
}

impl ReadableFromStream for CipherSuite {
    fn read(stream: &mut impl Iterator<Item=u8>) -> std::io::Result<Self> {
        let u = u16::read(stream)?;

        Ok(Self::try_from(u).unwrap_or(Self::Unknown))
    }
}

impl WritableToSink for CipherSuite {
    fn write(&self, buffer: &mut impl Sink<u8>) -> std::io::Result<()> {
        
        if matches!(self, CipherSuite::Unknown) {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("Cannot write {:?}", self)
            ));
        }
        
        let v: u16 = self.into();
        
        v.write(buffer)
    }
}

/// A list of Cipher Suites, that are supported by this server. They in order of preference
/// in descending order (most preferable first).
const SUPPORTED_CIPHER_SUITES: [CipherSuite; 4] = [
    CipherSuite::TlsRsaWithAes256CbcSha256,
    CipherSuite::TlsRsaWithAes256CbcSha,
    CipherSuite::TlsRsaWithAes128CbcSha256,
    CipherSuite::TlsRsaWithAes128CbcSha
];

#[derive(Debug)]
/// Error type for when the client and our server do not share any common `CipherSuite`s.
pub struct NoAcceptableMatch;

/// Our server enforces our own preference since we deal with sharing passwords. This function
/// selects the best `CipherSuite` that are present in `SUPPORTED_CIPHER_SUITES` and in the
/// `cipher_suites_from_client`.
pub fn select_cipher_suite(cipher_suites_from_client: &Vec<CipherSuite>) -> Result<CipherSuite, NoAcceptableMatch> {
    for cipher in SUPPORTED_CIPHER_SUITES.iter() {
        if cipher_suites_from_client.contains(cipher) {
            return Ok(*cipher);
        }
    }

    Err(NoAcceptableMatch)
}
