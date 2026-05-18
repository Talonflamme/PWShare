use crate::cryptography::elliptic_curves::curve::{EllipticCurve, EllipticCurveConstants, Point};
use crate::cryptography::elliptic_curves::ECDHPublicKey;
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

#[repr(u8)]
#[derive(Debug, ReadableFromStream, WritableToSink, Copy, Clone, Eq, PartialEq)]
#[fallback(Unknown)]
enum PointConversionForm {
    Uncompressed = 4,
    Unknown,
}

#[derive(Debug, WritableToSink, ReadableFromStream)]
pub struct ECPoint {
    pub point: VariableLengthVec<u8, 1, 255>,
}

impl ECPoint {
    fn from_curve_and_point(point: Point, curve: NamedCurve) -> Result<Self> {
        match curve {
            // Weierstrass curves are encoded with the UncompressedPointRepresentation struct
            // the points are implicitly sized based on the curve. The amount of bytes used
            // for encoding is the same as the bytes used for 'p' of the curve. This format
            // uses big-endian.
            NamedCurve::SECP256R1 | NamedCurve::SECP384R1 | NamedCurve::SECP521R1 => {
                let mut vec = Vec::new();
                UncompressedPointRepresentation {
                    form: PointConversionForm::Uncompressed,
                    x: point.x,
                    y: point.y,
                }
                .write(&mut vec, &curve)?;
                Ok(Self { point: vec.into() })
            }
            // Montgomery Curves only encode the X coordinate (sometimes 'u') because only it is
            // used as a public key (since Montgomery ladder only requires the x)
            // X25519 uses 32 bytes
            // X448 uses 56 bytes
            // Encoding is in little-endian
            NamedCurve::X25519 => {
                let mut slice = [0u8; 32];
                let x = point.x.to_bytes_le();
                slice[..x.len()].copy_from_slice(&x);
                Ok(Self {
                    point: slice.to_vec().into(),
                })
            }
            NamedCurve::X448 => {
                let mut slice = [0u8; 56];
                let x = point.x.to_bytes_le();
                slice[..x.len()].copy_from_slice(&x);
                Ok(Self {
                    point: slice.to_vec().into(),
                })
            }
            NamedCurve::Unknown => Err(Alert::internal_error("Unknown curve")),
        }
    }
}

#[derive(Debug)]
struct UncompressedPointRepresentation {
    pub form: PointConversionForm,
    pub x: BigUint,
    pub y: BigUint,
}

impl UncompressedPointRepresentation {
    fn write(&self, buffer: &mut impl Sink<u8>, named_curve: &NamedCurve) -> Result<()> {
        let curve = named_curve.curve()?;

        let bytes = curve.p.bits().div_ceil(8) as usize;

        self.form.write(buffer, None)?;

        let x = self.x.to_bytes_be();

        // zero pad to left
        buffer.append(vec![0u8; bytes - x.len()]);
        buffer.append(x);

        let y = self.y.to_bytes_be();

        // zero pad to left again
        buffer.append(vec![0u8; bytes - y.len()]);
        buffer.append(y);

        Ok(())
    }

    fn read(stream: &mut impl Iterator<Item = u8>, named_curve: &NamedCurve) -> Result<Self> {
        let curve = named_curve.curve()?;

        let bytes = curve.p.bits().div_ceil(8) as usize;

        let form = PointConversionForm::read(stream, None)?;

        if !matches!(form, PointConversionForm::Uncompressed) {
            return Err(Alert::internal_error(
                "Point Conversion Form other than 'Uncompressed' was negotiated",
            )); // Should not come this far
        }

        let x: Vec<u8> = stream.take(bytes).collect();

        if x.len() != bytes {
            return Err(Alert::decode_error());
        }

        let y: Vec<u8> = stream.take(bytes).collect();

        if y.len() != bytes {
            return Err(Alert::decode_error());
        }

        Ok(Self {
            form,
            x: BigUint::from_bytes_be(&x),
            y: BigUint::from_bytes_be(&y),
        })
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
                G: Point {
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
    pub public: ECPoint,
}

impl ServerECDHParams {
    pub fn from_curve_and_key(named_curve: NamedCurve, public_key: &ECDHPublicKey) -> Result<Self> {
        Ok(Self {
            curve_params: ECParameters {
                curve_type: ECCurveType::NamedCurve,
                named_curve,
            },
            public: ECPoint::from_curve_and_point(public_key.key.clone(), named_curve)?,
        })
    }
}
