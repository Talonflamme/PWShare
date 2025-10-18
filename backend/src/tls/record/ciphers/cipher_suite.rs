use crate::tls::connection_state::mac::MACAlgorithm;
use crate::tls::connection_state::prf::PRFAlgorithm;
use crate::tls::connection_state::security_parameters::{BulkCipherAlgorithm, SecurityParameters};
use crate::tls::record::alert::{Alert, Result};
use crate::tls::record::ciphers::key_exchange_algorithm::KeyExchangeAlgorithm;
use crate::tls::record::hello::extensions::{Extension, ExtensionType, NamedCurveList};
use crate::tls::record::key_exchange::ecdhe::elliptic_curve::NamedCurve;
use crate::tls::record::signature::{HashAlgorithm, SignatureAlgorithm};
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

    TlsRsaWithAes128GcmSha256 = 0x009c,
    TlsRsaWithAes256GcmSha384 = 0x009d,

    TlsEcdheRsaWithAes128CbcSha256 = 0xc027,

    Unknown = 0xFFFF,
}

impl ReadableFromStream for CipherSuite {
    fn read(stream: &mut impl Iterator<Item = u8>, suite: Option<&CipherConfig>) -> Result<Self> {
        let u = u16::read(stream, suite)?;

        Ok(Self::try_from(u).unwrap_or(Self::Unknown))
    }
}

impl WritableToSink for CipherSuite {
    fn write(&self, buffer: &mut impl Sink<u8>, suite: Option<&CipherConfig>) -> Result<()> {
        if matches!(self, CipherSuite::Unknown) {
            return Err(Alert::internal_error(
                "Unknown cipher suite cannot be written",
            ));
        }

        let v: u16 = self.into();

        v.write(buffer, suite)
    }
}

#[derive(Debug, Clone, Copy)]
pub struct CipherConfig {
    pub key_exchange: KeyExchangeAlgorithm,
    pub signature: SignatureAlgorithm,
    pub cipher: BulkCipherAlgorithm,
    pub mac: MACAlgorithm,
    pub hash: HashAlgorithm,
    pub prf: PRFAlgorithm,
    /// size of key in bytes
    pub key_length: u8,
    /// The EllipticCurve that was chosen for the `KeyExchange`. Initially `None`, until
    /// the `ServerKeyExchange` message is sent. Only `Some`, when `.key_exchange` is `ECDHE`.
    pub ec_curve: Option<NamedCurve>,
}

impl CipherSuite {
    pub fn config(&self) -> Result<CipherConfig> {
        match self {
            CipherSuite::TlsNullWithNullNull => Ok(CipherConfig {
                key_exchange: KeyExchangeAlgorithm::Null,
                signature: SignatureAlgorithm::Anonymous,
                cipher: BulkCipherAlgorithm::Null,
                mac: MACAlgorithm::Null,
                hash: HashAlgorithm::None,
                prf: PRFAlgorithm::TlsPrfSha256,
                key_length: 0,
                ec_curve: None,
            }),
            CipherSuite::TlsRsaWithAes256CbcSha256 => Ok(CipherConfig {
                key_exchange: KeyExchangeAlgorithm::Rsa,
                signature: SignatureAlgorithm::RSA,
                cipher: BulkCipherAlgorithm::Aes256Cbc,
                mac: MACAlgorithm::HMacSha256,
                hash: HashAlgorithm::Sha256,
                prf: PRFAlgorithm::TlsPrfSha256,
                key_length: 32,
                ec_curve: None,
            }),
            CipherSuite::TlsRsaWithAes256CbcSha => Ok(CipherConfig {
                key_exchange: KeyExchangeAlgorithm::Rsa,
                signature: SignatureAlgorithm::RSA,
                cipher: BulkCipherAlgorithm::Aes256Cbc,
                mac: MACAlgorithm::HMacSha1,
                hash: HashAlgorithm::Sha1,
                prf: PRFAlgorithm::TlsPrfSha256,
                key_length: 32,
                ec_curve: None,
            }),
            CipherSuite::TlsRsaWithAes128CbcSha256 => Ok(CipherConfig {
                key_exchange: KeyExchangeAlgorithm::Rsa,
                signature: SignatureAlgorithm::RSA,
                cipher: BulkCipherAlgorithm::Aes128Cbc,
                mac: MACAlgorithm::HMacSha256,
                hash: HashAlgorithm::Sha256,
                prf: PRFAlgorithm::TlsPrfSha256,
                key_length: 16,
                ec_curve: None,
            }),
            CipherSuite::TlsRsaWithAes128CbcSha => Ok(CipherConfig {
                key_exchange: KeyExchangeAlgorithm::Rsa,
                signature: SignatureAlgorithm::RSA,
                cipher: BulkCipherAlgorithm::Aes128Cbc,
                mac: MACAlgorithm::HMacSha1,
                hash: HashAlgorithm::Sha1,
                prf: PRFAlgorithm::TlsPrfSha256,
                key_length: 16,
                ec_curve: None,
            }),
            CipherSuite::TlsRsaWithAes128GcmSha256 => Ok(CipherConfig {
                key_exchange: KeyExchangeAlgorithm::Rsa,
                signature: SignatureAlgorithm::RSA,
                cipher: BulkCipherAlgorithm::Aes128Gcm,
                mac: MACAlgorithm::HMacSha256,
                hash: HashAlgorithm::Sha256,
                prf: PRFAlgorithm::TlsPrfSha256,
                key_length: 16,
                ec_curve: None,
            }),
            CipherSuite::TlsRsaWithAes256GcmSha384 => Ok(CipherConfig {
                key_exchange: KeyExchangeAlgorithm::Rsa,
                signature: SignatureAlgorithm::RSA,
                cipher: BulkCipherAlgorithm::Aes256Gcm,
                mac: MACAlgorithm::HMacSha384,
                hash: HashAlgorithm::Sha384,
                prf: PRFAlgorithm::TlsPrfSha384,
                key_length: 32,
                ec_curve: None,
            }),
            CipherSuite::TlsEcdheRsaWithAes128CbcSha256 => Ok(CipherConfig {
                key_exchange: KeyExchangeAlgorithm::Ecdhe,
                signature: SignatureAlgorithm::RSA,
                cipher: BulkCipherAlgorithm::Aes128Cbc,
                mac: MACAlgorithm::HMacSha256,
                hash: HashAlgorithm::Sha256,
                prf: PRFAlgorithm::TlsPrfSha256,
                key_length: 16,
                ec_curve: None,
            }),
            _ => Err(Alert::internal_error("Unsupported cipher was negotiated")), // should not occur
        }
    }

    pub fn set_security_params(&self, params: &mut SecurityParameters) -> Result<()> {
        let config = self.config()?;

        params.prf_algorithm = Some(config.prf);
        params.enc_key_length = Some(config.key_length);
        config.cipher.set_params(params);
        config.mac.set_params(params);

        Ok(())
    }
}

/// A list of Cipher Suites, that are supported by this server. They in order of preference
/// in descending order (most preferable first).
pub const SUPPORTED_CIPHER_SUITES: [CipherSuite; 7] = [
    CipherSuite::TlsEcdheRsaWithAes128CbcSha256,
    CipherSuite::TlsRsaWithAes256GcmSha384,
    CipherSuite::TlsRsaWithAes128GcmSha256,
    CipherSuite::TlsRsaWithAes256CbcSha256,
    CipherSuite::TlsRsaWithAes256CbcSha,
    CipherSuite::TlsRsaWithAes128CbcSha256,
    CipherSuite::TlsRsaWithAes128CbcSha,
];

/// A list of `NamedCurve`s that this Server supports. They are in order of preference (most
/// preferable first).
pub const SUPPORTED_EC_CURVES: [NamedCurve; 5] = [
    NamedCurve::X25519,
    NamedCurve::X448,
    NamedCurve::SECP256R1,
    NamedCurve::SECP384R1,
    NamedCurve::SECP521R1,
];

/// Returns a reference to the `NamedCurveList` of the `Supported Groups Extension`.
/// Returns an `Err` when decoding the extension fails. If this extension is not present,
/// an `Ok(None)` will be returned, as the parsing did not fail, but there simply was no
/// such extension in `extensions`.
fn get_client_supported_named_curves(extensions: &[Extension]) -> Result<Option<&NamedCurveList>> {
    for ex in extensions.iter() {
        if let ExtensionType::SupportedGroups(sg) = &ex.extension_type {
            if sg.len() != 1 {
                return Err(Alert::decode_error());
            }

            return Ok(Some(&sg[0]));
        }
    }

    Ok(None)
}

/// Select a NamedCurve that is supported by both the Client (in `client_extensions`) and
/// the server (in `SUPPORTED_EC_CURVES`). If no common curve is found, an `Alert::handshake_fail()`
/// is returned. If no `Supported Groups Extension` is sent by the client, the most preferable
/// curve of this server is returned (usually `X25519`).
pub fn select_ec_curve(client_extensions: &[Extension]) -> Result<NamedCurve> {
    let curves = get_client_supported_named_curves(client_extensions)?;

    if let Some(sg) = curves {
        SUPPORTED_EC_CURVES
            .iter()
            .find(|&curve| sg.contains(curve))
            .map(|curve| Ok(*curve))
            .unwrap_or_else(|| Err(Alert::handshake_failure()))
    } else {
        Ok(SUPPORTED_EC_CURVES[0])
    }
}

/// Our server enforces our own preference since we deal with sharing passwords. This function
/// selects the best `CipherSuite` that are present in `SUPPORTED_CIPHER_SUITES` and in the
/// `cipher_suites_from_client`.
pub fn select_cipher_suite(
    cipher_suites_from_client: &Vec<CipherSuite>,
    extensions: &Vec<Extension>,
) -> Result<CipherSuite> {
    let client_ec_curves = get_client_supported_named_curves(extensions)?;
    let can_use_ecdhe: bool;

    // if SupportedGroups was sent, then we need to make sure we have supported curves to use ECDH
    if let Some(sg) = client_ec_curves {
        can_use_ecdhe = sg.iter().any(|nc| !matches!(nc, NamedCurve::Unknown));
    } else {
        can_use_ecdhe = true; // no extension was sent, we assume that basic curves are used
    }

    for cipher in SUPPORTED_CIPHER_SUITES.iter() {
        if !cipher_suites_from_client.contains(cipher) {
            continue;
        }

        if !can_use_ecdhe && matches!(cipher.config()?.key_exchange, KeyExchangeAlgorithm::Ecdhe) {
            continue; // no matching curve
        }

        return Ok(*cipher);
    }

    Err(Alert::handshake_failure())
}
