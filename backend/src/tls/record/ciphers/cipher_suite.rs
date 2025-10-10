use crate::tls::connection_state::mac::MACAlgorithm;
use crate::tls::connection_state::prf::PRFAlgorithm;
use crate::tls::connection_state::security_parameters::{
    BulkCipherAlgorithm, CipherType, SecurityParameters,
};
use crate::tls::record::alert::{Alert, Result};
use crate::tls::{ReadableFromStream, Sink, WritableToSink};
use pwshare_macros::{FromRepr, IntoRepr};

// TODO: add more (modern) ciphers

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

    Unknown = 0xFFFF,
}

impl ReadableFromStream for CipherSuite {
    fn read(stream: &mut impl Iterator<Item = u8>) -> Result<Self> {
        let u = u16::read(stream)?;

        Ok(Self::try_from(u).unwrap_or(Self::Unknown))
    }
}

impl WritableToSink for CipherSuite {
    fn write(&self, buffer: &mut impl Sink<u8>) -> Result<()> {
        if matches!(self, CipherSuite::Unknown) {
            return Err(Alert::internal_error("Unknown cipher suite cannot be written"));
        }

        let v: u16 = self.into();

        v.write(buffer)
    }
}

macro_rules! define_mac {
    ($params: ident,
    mac = Null) => {
        $params.mac_algorithm = Some(MACAlgorithm::Null);
        $params.mac_length = Some(0);
        $params.mac_key_length = Some(0);
    };

    ($params: ident,
    mac = HMacMd5) => {
        $params.mac_algorithm = Some(MACAlgorithm::HMacMd5);
        $params.mac_length = Some(16);
        $params.mac_key_length = Some(16);
    };

    ($params: ident,
    mac = HMacSha1) => {
        $params.mac_algorithm = Some(MACAlgorithm::HMacSha1);
        $params.mac_length = Some(20);
        $params.mac_key_length = Some(20);
    };

    ($params: ident,
    mac = HMacSha256) => {
        $params.mac_algorithm = Some(MACAlgorithm::HMacSha256);
        $params.mac_length = Some(32);
        $params.mac_key_length = Some(32);
    };

    ($params: ident,
    mac = HMacSha384) => {
        $params.mac_algorithm = Some(MACAlgorithm::HMacSha384);
        $params.mac_length = Some(48);
        $params.mac_key_length = Some(48);
    };

    ($params: ident,
    mac = HMacSha512) => {
        $params.mac_algorithm = Some(MACAlgorithm::HMacSha512);
        $params.mac_length = Some(64);
        $params.mac_key_length = Some(64);
    };
}

macro_rules! define_suite {
    (
        $params: ident,
        prf = $prf:path,
        cipher = Null,
        mac = $mac: ident
    ) => {
        $params.prf_algorithm = Some($prf);
        $params.bulk_cipher_algorithm = Some(BulkCipherAlgorithm::Null);
        $params.cipher_type = Some(CipherType::Stream);
        $params.enc_key_length = Some(0);
        $params.block_length = Some(0);
        $params.fixed_iv_length = Some(0);
        $params.record_iv_length = Some(0);
        define_mac!($params, mac = $mac);
    };

    (
        $params: ident,
        prf = $prf:path,
        cipher = Rc4 | keylen = $key_len:expr,
        mac = $mac: ident
    ) => {
        $params.prf_algorithm = Some($prf);
        $params.bulk_cipher_algorithm = Some(BulkCipherAlgorithm::Rc4);
        $params.cipher_type = Some(CipherType::Stream);
        $params.enc_key_length = Some($key_len);
        $params.block_length = Some(0);
        $params.fixed_iv_length = Some(0);
        $params.record_iv_length = Some(0);
        define_mac!($params, mac = $mac);
    };

    (
        $params: ident,
        prf = $prf:path,
        cipher = AesCbc | keylen = $key_len:expr,
        mac = $mac: ident
    ) => {
        $params.prf_algorithm = Some($prf);
        $params.bulk_cipher_algorithm = Some(BulkCipherAlgorithm::AesCbc);
        $params.cipher_type = Some(CipherType::Block);
        $params.enc_key_length = Some($key_len);
        $params.block_length = Some(16);
        $params.fixed_iv_length = Some(16);
        $params.record_iv_length = Some(16);
        define_mac!($params, mac = $mac);
    };

    (
        $params: ident,
        prf = $prf:path,
        cipher = TDes,
        mac = $mac: ident
    ) => {
        $params.prf_algorithm = Some($prf);
        $params.bulk_cipher_algorithm = Some(BulkCipherAlgorithm::TDes);
        $params.cipher_type = Some(CipherType::Block);
        $params.enc_key_length = Some(24);
        $params.block_length = Some(8);
        $params.fixed_iv_length = Some(8);
        $params.record_iv_length = Some(8);
        define_mac!($params, mac = $mac);
    };
}

impl CipherSuite {
    pub fn set_security_params(&self, params: &mut SecurityParameters) {
        match self {
            CipherSuite::Unknown => panic!("Cannot set security params on Unknown"),

            CipherSuite::TlsNullWithNullNull => {
                define_suite!(
                    params,
                    prf = PRFAlgorithm::TlsPrfSha256,
                    cipher = Null,
                    mac = Null
                );
            }

            CipherSuite::TlsRsaWithNullMd5 => {
                define_suite!(
                    params,
                    prf = PRFAlgorithm::TlsPrfSha256,
                    cipher = Null,
                    mac = HMacMd5
                );
            }

            CipherSuite::TlsRsaWithNullSha => {
                define_suite!(
                    params,
                    prf = PRFAlgorithm::TlsPrfSha256,
                    cipher = Null,
                    mac = HMacSha1
                );
            }

            CipherSuite::TlsRsaWithNullSha256 => {
                define_suite!(
                    params,
                    prf = PRFAlgorithm::TlsPrfSha256,
                    cipher = Null,
                    mac = HMacSha256
                );
            }

            CipherSuite::TlsRsaWithRc4128Md5 => {
                define_suite!(
                    params,
                    prf = PRFAlgorithm::TlsPrfSha256,
                    cipher = Rc4 | keylen = 16,
                    mac = HMacMd5
                );
            }

            CipherSuite::TlsRsaWithRc4128Sha => {
                define_suite!(
                    params,
                    prf = PRFAlgorithm::TlsPrfSha256,
                    cipher = Rc4 | keylen = 16,
                    mac = HMacSha1
                );
            }

            CipherSuite::TlsRsaWith3desEdeCbcSha => {
                define_suite!(
                    params,
                    prf = PRFAlgorithm::TlsPrfSha256,
                    cipher = TDes,
                    mac = HMacSha1
                );
            }

            CipherSuite::TlsRsaWithAes128CbcSha => {
                define_suite!(
                    params,
                    prf = PRFAlgorithm::TlsPrfSha256,
                    cipher = AesCbc | keylen = 16,
                    mac = HMacSha1
                );
            }

            CipherSuite::TlsRsaWithAes256CbcSha => {
                define_suite!(
                    params,
                    prf = PRFAlgorithm::TlsPrfSha256,
                    cipher = AesCbc | keylen = 32,
                    mac = HMacSha1
                );
            }

            CipherSuite::TlsRsaWithAes128CbcSha256 => {
                define_suite!(
                    params,
                    prf = PRFAlgorithm::TlsPrfSha256,
                    cipher = AesCbc | keylen = 16,
                    mac = HMacSha256
                );
            }

            CipherSuite::TlsRsaWithAes256CbcSha256 => {
                define_suite!(
                    params,
                    prf = PRFAlgorithm::TlsPrfSha256,
                    cipher = AesCbc | keylen = 32,
                    mac = HMacSha256
                );
            }

            // All the DHE/DH/Anon variants just change the key exchange,
            // not the symmetric algorithms. They map to the same values
            // as the corresponding RSA suites:
            CipherSuite::TlsDhDssWith3desEdeCbcSha
            | CipherSuite::TlsDhRsaWith3desEdeCbcSha
            | CipherSuite::TlsDheDssWith3desEdeCbcSha
            | CipherSuite::TlsDheRsaWith3desEdeCbcSha
            | CipherSuite::TlsDhAnonWith3desEdeCbcSha => {
                define_suite!(
                    params,
                    prf = PRFAlgorithm::TlsPrfSha256,
                    cipher = TDes,
                    mac = HMacSha1
                );
            }

            CipherSuite::TlsDhDssWithAes128CbcSha
            | CipherSuite::TlsDhRsaWithAes128CbcSha
            | CipherSuite::TlsDheDssWithAes128CbcSha
            | CipherSuite::TlsDheRsaWithAes128CbcSha
            | CipherSuite::TlsDhAnonWithAes128CbcSha => {
                define_suite!(
                    params,
                    prf = PRFAlgorithm::TlsPrfSha256,
                    cipher = AesCbc | keylen = 16,
                    mac = HMacSha1
                );
            }

            CipherSuite::TlsDhDssWithAes256CbcSha
            | CipherSuite::TlsDhRsaWithAes256CbcSha
            | CipherSuite::TlsDheDssWithAes256CbcSha
            | CipherSuite::TlsDheRsaWithAes256CbcSha
            | CipherSuite::TlsDhAnonWithAes256CbcSha => {
                define_suite!(
                    params,
                    prf = PRFAlgorithm::TlsPrfSha256,
                    cipher = AesCbc | keylen = 32,
                    mac = HMacSha1
                );
            }

            CipherSuite::TlsDhDssWithAes128CbcSha256
            | CipherSuite::TlsDhRsaWithAes128CbcSha256
            | CipherSuite::TlsDheDssWithAes128CbcSha256
            | CipherSuite::TlsDheRsaWithAes128CbcSha256
            | CipherSuite::TlsDhAnonWithAes128CbcSha256 => {
                define_suite!(
                    params,
                    prf = PRFAlgorithm::TlsPrfSha256,
                    cipher = AesCbc | keylen = 16,
                    mac = HMacSha256
                );
            }

            CipherSuite::TlsDhDssWithAes256CbcSha256
            | CipherSuite::TlsDhRsaWithAes256CbcSha256
            | CipherSuite::TlsDheDssWithAes256CbcSha256
            | CipherSuite::TlsDheRsaWithAes256CbcSha256
            | CipherSuite::TlsDhAnonWithAes256CbcSha256 => {
                define_suite!(
                    params,
                    prf = PRFAlgorithm::TlsPrfSha256,
                    cipher = AesCbc | keylen = 32,
                    mac = HMacSha256
                );
            }

            CipherSuite::TlsDhAnonWithRc4128Md5 => {
                define_suite!(
                    params,
                    prf = PRFAlgorithm::TlsPrfSha256,
                    cipher = Rc4 | keylen = 16,
                    mac = HMacMd5
                );
            }
        }
    }
}

/// A list of Cipher Suites, that are supported by this server. They in order of preference
/// in descending order (most preferable first).
const SUPPORTED_CIPHER_SUITES: [CipherSuite; 4] = [
    CipherSuite::TlsRsaWithAes256CbcSha256,
    CipherSuite::TlsRsaWithAes256CbcSha,
    CipherSuite::TlsRsaWithAes128CbcSha256,
    CipherSuite::TlsRsaWithAes128CbcSha,
];

/// Our server enforces our own preference since we deal with sharing passwords. This function
/// selects the best `CipherSuite` that are present in `SUPPORTED_CIPHER_SUITES` and in the
/// `cipher_suites_from_client`.
pub fn select_cipher_suite(cipher_suites_from_client: &Vec<CipherSuite>) -> Result<CipherSuite> {
    for cipher in SUPPORTED_CIPHER_SUITES.iter() {
        if cipher_suites_from_client.contains(cipher) {
            return Ok(*cipher);
        }
    }

    Err(Alert::insufficient_security())
}
