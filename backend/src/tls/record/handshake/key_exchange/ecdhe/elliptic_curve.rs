use crate::cryptography::elliptic_curves::curve::{EllipticCurve, EllipticCurveConstants, Point};
use crate::cryptography::elliptic_curves::ECDHPublicKey;
use crate::tls::record::alert::{Alert, AlertResult};
use crate::tls::record::variable_length_vec::VariableLengthVec;
use crate::tls::{ReadableFromStream, Sink, WritableToSink};
use crypto_bigint::{BoxedUint, Encoding};
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
    fn from_curve_and_point(point: Point, curve: NamedCurve) -> AlertResult<Self> {
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

    pub fn to_point(self, curve: NamedCurve) -> AlertResult<Point> {
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
                let length = curve.curve()?.coordinate_length;
                if self.point.len() != length {
                    Err(Alert::decode_error())
                } else {
                    Ok(Point {
                        x: BoxedUint::from_le_slice(&self.point, length as u32 * 8).unwrap(),
                        y: BoxedUint::zero_with_precision(length as u32 * 8), // irrelevant
                    })
                }
            }
            NamedCurve::Unknown => Err(Alert::internal_error("Unknown curve")),
        }
    }

    /// Encodes the x coordinate of a point depending on which curve is used.
    /// For Weierstrass curves, this happens to be big-endian.
    /// For Montgomery curves, this happens to be little-endian.
    pub fn encode_x_coordinate(x: BoxedUint, curve: NamedCurve) -> AlertResult<Vec<u8>> {
        let size = curve.curve()?.coordinate_length;

        let bytes = match curve {
            NamedCurve::SECP256R1 | NamedCurve::SECP384R1 => x.to_be_bytes(),
            NamedCurve::SECP521R1 => {
                let bytes = x.to_be_bytes(); // 72 bytes, since 66 does not fit perfectly into u64s
                bytes[bytes.len() - size..].into()
            }
            NamedCurve::X25519 | NamedCurve::X448 => x.to_le_bytes(),
            NamedCurve::Unknown => unreachable!(),
        };

        if bytes.len() != size {
            Err(Alert::internal_error(format!(
                "parameter x has unexpected amount of bytes: {} ({} expected)",
                bytes.len(),
                size
            )))
        } else {
            Ok(bytes.into())
        }
    }

    /// When `named_curve` is a Weierstrass curve, checks if the given points sits on the curve.
    /// Throws an error if it does not, else returns a simple `Ok(())`.
    /// If `named_curve` is not a Weierstrass curve, checks nothing and simply returns `Ok(())`
    pub fn verify_weierstrass(point: Point, named_curve: NamedCurve) -> AlertResult<()> {
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
    pub x: BoxedUint,
    pub y: BoxedUint,
}

impl UncompressedPointRepresentation {
    fn write(&self, buffer: &mut impl Sink<u8>, named_curve: &NamedCurve) -> AlertResult<()> {
        let curve = named_curve.curve()?;

        let bytes = curve.coordinate_length;

        self.form.write(buffer, None)?;

        let x = self.x.to_be_bytes();

        buffer.extend_from_slice(&x[x.len() - bytes..]);

        let y = self.y.to_be_bytes();
        buffer.extend_from_slice(&y[x.len() - bytes..]);

        Ok(())
    }

    fn read(stream: &mut impl Iterator<Item = u8>, named_curve: &NamedCurve) -> AlertResult<Self> {
        let curve = named_curve.curve()?;

        let bytes = curve.p.bits().div_ceil(8) as usize;

        let form = PointConversionForm::read(stream, None)?;

        if !matches!(form, PointConversionForm::Uncompressed) {
            return Err(Alert::internal_error(
                "Point Conversion Form other than 'Uncompressed' was negotiated",
            )); // Should not come this far
        }

        let x: Box<[u8]> = stream.take(bytes).collect();

        if x.len() != bytes {
            return Err(Alert::decode_error());
        }

        let y: Box<[u8]> = stream.take(bytes).collect();

        if y.len() != bytes {
            return Err(Alert::decode_error());
        }

        Ok(Self {
            form,
            x: BoxedUint::from_be_bytes(x),
            y: BoxedUint::from_be_bytes(y),
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
    pub fn curve(self) -> AlertResult<EllipticCurve> {
        match self {
            NamedCurve::SECP256R1 => Ok(EllipticCurve {
                coordinate_length: 32,
                p: BoxedUint::from_words([0xffffffffffffffff, 0xffffffff, 0x0, 0xffffffff00000001])
                    .into_odd()
                    .unwrap(),
                constants: EllipticCurveConstants::Weierstrass {
                    a: BoxedUint::from_words([
                        0xfffffffffffffffc,
                        0xffffffff,
                        0x0,
                        0xffffffff00000001,
                    ]),
                    b: BoxedUint::from_words([
                        0x3bce3c3e27d2604b,
                        0x651d06b0cc53b0f6,
                        0xb3ebbd55769886bc,
                        0x5ac635d8aa3a93e7,
                    ]),
                },
                G: Point {
                    x: BoxedUint::from_words([
                        0xf4a13945d898c296,
                        0x77037d812deb33a0,
                        0xf8bce6e563a440f2,
                        0x6b17d1f2e12c4247,
                    ]),
                    y: BoxedUint::from_words([
                        0xcbb6406837bf51f5,
                        0x2bce33576b315ece,
                        0x8ee7eb4a7c0f9e16,
                        0x4fe342e2fe1a7f9b,
                    ]),
                },
                n: BoxedUint::from_words([
                    0xf3b9cac2fc632551,
                    0xbce6faada7179e84,
                    0xffffffffffffffff,
                    0xffffffff00000000,
                ])
                .into_odd()
                .unwrap(),
            }),
            NamedCurve::SECP384R1 => Ok(EllipticCurve {
                coordinate_length: 48,
                p: BoxedUint::from_words([
                    0x00000000ffffffff,
                    0xffffffff00000000,
                    0xfffffffffffffffe,
                    0xffffffffffffffff,
                    0xffffffffffffffff,
                    0xffffffffffffffff,
                ])
                .into_odd()
                .unwrap(),
                constants: EllipticCurveConstants::Weierstrass {
                    a: BoxedUint::from_words([
                        0x00000000fffffffc,
                        0xffffffff00000000,
                        0xfffffffffffffffe,
                        0xffffffffffffffff,
                        0xffffffffffffffff,
                        0xffffffffffffffff,
                    ]),
                    b: BoxedUint::from_words([
                        0x2a85c8edd3ec2aef,
                        0xc656398d8a2ed19d,
                        0x0314088f5013875a,
                        0x181d9c6efe814112,
                        0x988e056be3f82d19,
                        0xb3312fa7e23ee7e4,
                    ]),
                },
                G: Point {
                    x: BoxedUint::from_words([
                        0x3a545e3872760ab7,
                        0x5502f25dbf55296c,
                        0x59f741e082542a38,
                        0x6e1d3b628ba79b98,
                        0x8eb1c71ef320ad74,
                        0xaa87ca22be8b0537,
                    ]),
                    y: BoxedUint::from_words([
                        0x7a431d7c90ea0e5f,
                        0x0a60b1ce1d7e819d,
                        0xe9da3113b5f0b8c0,
                        0xf8f41dbd289a147c,
                        0x5d9e98bf9292dc29,
                        0x3617de4a96262c6f,
                    ]),
                },
                n: BoxedUint::from_words([
                    0xecec196accc52973,
                    0x581a0db248b0a77a,
                    0xc7634d81f4372ddf,
                    0xffffffffffffffff,
                    0xffffffffffffffff,
                    0xffffffffffffffff,
                ])
                .into_odd()
                .unwrap(),
            }),
            NamedCurve::SECP521R1 => Ok(EllipticCurve {
                coordinate_length: 66,
                p: BoxedUint::from_words([
                    0xffffffffffffffff,
                    0xffffffffffffffff,
                    0xffffffffffffffff,
                    0xffffffffffffffff,
                    0xffffffffffffffff,
                    0xffffffffffffffff,
                    0xffffffffffffffff,
                    0xffffffffffffffff,
                    0x1ff,
                ])
                .into_odd()
                .unwrap(),
                constants: EllipticCurveConstants::Weierstrass {
                    a: BoxedUint::from_words([
                        0xfffffffffffffffc,
                        0xffffffffffffffff,
                        0xffffffffffffffff,
                        0xffffffffffffffff,
                        0xffffffffffffffff,
                        0xffffffffffffffff,
                        0xffffffffffffffff,
                        0xffffffffffffffff,
                        0x1ff,
                    ]),
                    b: BoxedUint::from_words([
                        0xef451fd46b503f00,
                        0x3573df883d2c34f1,
                        0x1652c0bd3bb1bf07,
                        0x56193951ec7e937b,
                        0xb8b489918ef109e1,
                        0xa2da725b99b315f3,
                        0x929a21a0b68540ee,
                        0x953eb9618e1c9a1f,
                        0x51,
                    ]),
                },
                G: Point {
                    x: BoxedUint::from_words([
                        0xf97e7e31c2e5bd66,
                        0x3348b3c1856a429b,
                        0xfe1dc127a2ffa8de,
                        0xa14b5e77efe75928,
                        0xf828af606b4d3dba,
                        0x9c648139053fb521,
                        0x9e3ecb662395b442,
                        0x858e06b70404e9cd,
                        0xc6,
                    ]),
                    y: BoxedUint::from_words([
                        0x88be94769fd16650,
                        0x353c7086a272c240,
                        0xc550b9013fad0761,
                        0x97ee72995ef42640,
                        0x17afbd17273e662c,
                        0x98f54449579b4468,
                        0x5c8a5fb42c7d1bd9,
                        0x39296a789a3bc004,
                        0x118,
                    ]),
                },
                n: BoxedUint::from_words([
                    0xbb6fb71e91386409,
                    0x3bb5c9b8899c47ae,
                    0x7fcc0148f709a5d0,
                    0x51868783bf2f966b,
                    0xfffffffffffffffa,
                    0xffffffffffffffff,
                    0xffffffffffffffff,
                    0xffffffffffffffff,
                    0x1ff,
                ])
                .into_odd()
                .unwrap(),
            }),
            NamedCurve::X25519 => Ok(EllipticCurve {
                coordinate_length: 32, // 32 bytes
                p: BoxedUint::from_words([
                    0xffffffffffffffed,
                    0xffffffffffffffff,
                    0xffffffffffffffff,
                    0x7fffffffffffffff,
                ])
                .into_odd()
                .unwrap(), // 2^255 - 19
                constants: EllipticCurveConstants::Montgomery {
                    A: BoxedUint::from_words_with_precision([486662], 32 * 8),
                    A_minus2_over4: BoxedUint::from_words_with_precision([121665], 32 * 8), // 121665 = (486662 - 2) / 4
                },
                n: BoxedUint::from_words([
                    0x5812631a5cf5d3ed,
                    0x14def9dea2f79cd6,
                    0x0000000000000000,
                    0x1000000000000000,
                ])
                .into_odd()
                .unwrap(), // 2^252 + 0x14def9dea2f79cd65812631a5cf5d3ed
                G: Point {
                    x: BoxedUint::from_words_with_precision([9], 32 * 8),
                    y: BoxedUint::zero_with_precision(32 * 8), // unused in Montgomery form
                },
            }),
            NamedCurve::X448 => Ok(EllipticCurve {
                coordinate_length: 56,
                p: BoxedUint::from_words([
                    0xffffffffffffffff,
                    0xffffffffffffffff,
                    0xffffffffffffffff,
                    0xfffffffeffffffff,
                    0xffffffffffffffff,
                    0xffffffffffffffff,
                    0xffffffffffffffff,
                ])
                .into_odd()
                .unwrap(), // 2^448 - 2^224 - 1
                constants: EllipticCurveConstants::Montgomery {
                    A: BoxedUint::from_words_with_precision([156326], 56 * 8),
                    A_minus2_over4: BoxedUint::from_words_with_precision([39081], 56 * 8), // 39081 = (156326 - 2) / 4
                },
                n: BoxedUint::from_words([
                    0x2378c292ab5844f3,
                    0x216cc2728dc58f55,
                    0xc44edb49aed63690,
                    0xffffffff7cca23e9,
                    0xffffffffffffffff,
                    0xffffffffffffffff,
                    0x3fffffffffffffff,
                ])
                .into_odd()
                .unwrap(), // 2^446 - 0x8335dc163bb124b65129c96fde933d8d723a70aadc873d6d54a7bb0d
                G: Point {
                    x: BoxedUint::from_words_with_precision([5], 56 * 8),
                    y: BoxedUint::zero_with_precision(56 * 8),
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
    pub fn from_curve_and_key(
        named_curve: NamedCurve,
        public_key: &ECDHPublicKey,
    ) -> AlertResult<Self> {
        Ok(Self {
            curve_params: ECParameters {
                curve_type: ECCurveType::NamedCurve,
                named_curve,
            },
            public: ECPoint::from_curve_and_point(public_key.key.clone(), named_curve)?,
        })
    }
}
