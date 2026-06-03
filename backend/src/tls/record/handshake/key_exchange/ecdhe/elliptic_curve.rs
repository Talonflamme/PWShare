use crate::cryptography::elliptic_curves::curve::{EllipticCurve, EllipticCurveConstants, Point};
use crate::cryptography::elliptic_curves::ECDHPublicKey;
use crate::tls::record::alert::{Alert, Result};
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
                Ok(Self {
                    point: vec.try_into().unwrap(),
                })
            }
            // Montgomery Curves only encode the X coordinate (sometimes 'u') because only it is
            // used as a public key (since Montgomery ladder only requires the x)
            // X25519 uses 32 bytes
            // X448 uses 56 bytes
            // Encoding is in little-endian
            NamedCurve::X25519 | NamedCurve::X448 => Ok(Self {
                point: Self::encode_x_coordinate(point.x, curve)?
                    .try_into()
                    .unwrap(),
            }),
            NamedCurve::Unknown => Err(Alert::internal_error("Unknown curve")),
        }
    }

    // TODO: maybe even use one coordinate (BigUint) instead of Point
    pub fn to_point(self, curve: NamedCurve) -> Result<Point> {
        match curve {
            // Weierstrass curves are encoded with the UncompressedPointRepresentation struct
            // the points are implicitly sized based on the curve. The amount of bytes used
            // for encoding is the same as the bytes used for 'p' of the curve. This format
            // uses big-endian.
            NamedCurve::SECP256R1 | NamedCurve::SECP384R1 | NamedCurve::SECP521R1 => {
                let mut stream = Into::<Vec<u8>>::into(self.point).into_iter();
                let upr = UncompressedPointRepresentation::read(&mut stream, &curve)?;
                Ok(Point { x: upr.x, y: upr.y })
            }
            // Montgomery Curves only encode the X coordinate (sometimes 'u') because only it is
            // used as a public key (since Montgomery ladder only requires the x)
            // X25519 uses 32 bytes
            // X448 uses 56 bytes
            // Encoding is in little-endian
            NamedCurve::X25519 | NamedCurve::X448 => {
                if self.point.len() != curve.curve()?.coordinate_length {
                    Err(Alert::decode_error())
                } else {
                    Ok(Point {
                        x: BigUint::from_bytes_le(&self.point),
                        y: BigUint::ZERO, // irrelevant
                    })
                }
            }
            NamedCurve::Unknown => Err(Alert::internal_error("Unknown curve")),
        }
    }

    /// Encodes the x coordinate of a point depending on which curve is used.
    /// For Weirstrass curves, this happens to be big-endian.
    /// For Montgomery curves, this happens to be little-endian.
    pub fn encode_x_coordinate(x: BigUint, curve: NamedCurve) -> Result<Vec<u8>> {
        let size = curve.curve()?.coordinate_length;

        let mut result = vec![0u8; size];
        let bytes = match curve {
            NamedCurve::SECP256R1 | NamedCurve::SECP384R1 | NamedCurve::SECP521R1 => {
                x.to_bytes_be()
            }
            NamedCurve::X25519 | NamedCurve::X448 => x.to_bytes_le(),
            NamedCurve::Unknown => unreachable!(),
        };

        result[size - bytes.len()..].copy_from_slice(&bytes);
        Ok(result)
    }

    /// When `named_curve` is a Weirstrass curve, checks if the given points sits on the curve.
    /// Throws an error if it does not, else returns a simple `Ok(())`.
    /// If `named_curve` is not a Weirstrass curve, checks nothing and simply returns `Ok(())`
    pub fn verify_weirstrass(point: Point, named_curve: NamedCurve) -> Result<()> {
        match named_curve {
            NamedCurve::SECP256R1 | NamedCurve::SECP384R1 | NamedCurve::SECP521R1 => {
                let curve = named_curve.curve()?;
                if !curve.is_on_curve(point) {
                    Err(Alert::illegal_parameter())
                } else {
                    Ok(())
                }
            }
            NamedCurve::X25519 | NamedCurve::X448 => Ok(()),
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
            NamedCurve::X448 => Ok(EllipticCurve {
                coordinate_length: 56,
                p: BigUint::new(vec![
                    0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff,
                    0xffffffff, 0xfffffffe, 0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff,
                    0xffffffff, 0xffffffff,
                ]), // 2^448 - 2^224 - 1
                constants: EllipticCurveConstants::Montgomery {
                    A: BigUint::from(156326_u32),
                },
                n: BigUint::new(vec![
                    0xab5844f3, 0x2378c292, 0x8dc58f55, 0x216cc272, 0xaed63690, 0xc44edb49,
                    0x7cca23e9, 0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff,
                    0xffffffff, 0x3fffffff,
                ]), // 2^446 - 0x8335dc163bb124b65129c96fde933d8d723a70aadc873d6d54a7bb0d
                G: Point {
                    x: BigUint::from(5_u32),
                    y: BigUint::ZERO,
                },
            }),
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
