use crate::cryptography::elliptic_curves::curve::{ECPoint, EllipticCurve, EllipticCurveConstants};
use crate::tls::record::alert::{Alert, Result};
use crate::tls::record::ciphers::cipher_suite::CipherConfig;
use crate::tls::record::variable_length_vec::VariableLengthVec;
use crate::tls::{ReadableFromStream, Sink, WritableToSink};
use num_bigint::BigUint;
use pwshare_macros::{ReadableFromStream, WritableToSink};

#[repr(u8)]
#[derive(Debug, Clone, Copy, Eq, PartialEq, ReadableFromStream, WritableToSink)]
pub enum ECCurveType {
    // The values `explicit_prime = 1` and `explicit_char2 = 2` are deprecated by RFC 8422. Since
    // we only implement the Server, we can safely not implement and support these types.
    /// Indicates that a named curve is used. This option SHOULD be used when applicable.
    NamedCurve = 3,
}

#[derive(Debug, ReadableFromStream, WritableToSink)]
pub struct ECCurve {
    /// `a` parameter of the Elliptic Curve (EC) with `{(x, y) | y² = x³ + ax + b}`
    pub a: VariableLengthVec<u8, 1, 255>,
    /// `b` parameter of the Elliptic Curve (EC) with `{(x, y) | y² = x³ + ax + b}`
    pub b: VariableLengthVec<u8, 1, 255>,
}

#[repr(u8)]
#[derive(Debug, ReadableFromStream, WritableToSink, Copy, Clone, Eq, PartialEq)]
#[fallback(Unknown)]
pub enum PointConversionForm {
    Uncompressed = 4,
    Unknown,
}

#[derive(Debug)]
pub struct UncompressedPointRepresentation {
    pub form: PointConversionForm,
    pub x: BigUint,
    pub y: BigUint,
}

impl WritableToSink for UncompressedPointRepresentation {
    fn write(&self, buffer: &mut impl Sink<u8>, suite: Option<&CipherConfig>) -> Result<()> {
        todo!()
    }
}

impl ReadableFromStream for UncompressedPointRepresentation {
    fn read(stream: &mut impl Iterator<Item = u8>, suite: Option<&CipherConfig>) -> Result<Self> {
        todo!()
    }
}

#[repr(u16)]
#[derive(Debug, ReadableFromStream, WritableToSink, Clone, Copy, PartialEq, Eq)]
#[fallback(Unknown)]
pub enum NamedCurve {
    SECP256R1 = 23,
    SECP384R1 = 24,
    SECP521R1 = 25,
    X25519 = 29,
    X448 = 30,
    Unknown,
}

impl NamedCurve {
    pub fn curve(self) -> Result<EllipticCurve> {
        match self {
            NamedCurve::SECP384R1 => todo!(),
            NamedCurve::SECP521R1 => todo!(),
            NamedCurve::SECP256R1 => todo!(),
            NamedCurve::X25519 => Ok(EllipticCurve {
                coordinate_length: 32, // 32 bytes
                p: BigUint::new(vec![
                    0xffffffed, 0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff,
                    0xffffffff, 0x7fffffff,
                ]), // 2^255 - 19
                constants: EllipticCurveConstants::Montgomery {
                    A: BigUint::from(486662_u32),
                },
                n: BigUint::new(vec![
                    0x5cf5d3ed, 0x5812631a, 0xa2f79cd6, 0x14def9de, 0x0, 0x0, 0x0, 0x10000000,
                ]), // 2^252 + 0x14def9dea2f79cd65812631a5cf5d3ed
                G: ECPoint {
                    x: BigUint::from(9_u32),
                    y: BigUint::ZERO, // unused in Montgomery form
                },
            }),
            NamedCurve::X448 => todo!(),
            NamedCurve::Unknown => Err(Alert::internal_error("Called .curve() on Unknown")),
        }
    }
}

#[derive(Debug, ReadableFromStream, WritableToSink)]
pub struct ECParameters {
    pub curve_type: ECCurveType,
    pub named_curve: NamedCurve,
}

#[derive(Debug, ReadableFromStream, WritableToSink)]
pub struct ServerECDHParams {
    pub curve_params: ECParameters,
    pub public: UncompressedPointRepresentation,
}
