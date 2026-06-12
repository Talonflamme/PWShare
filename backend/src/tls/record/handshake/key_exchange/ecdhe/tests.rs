use crate::cryptography::elliptic_curves::curve::*;
use crate::tls::record::key_exchange::ecdhe::elliptic_curve::NamedCurve;
use crate::util::{bytes_from_hex, UintDisplay};
use crypto_bigint::{BoxedUint, One, RandomMod};
use ct_test_framework::{BenchBuilder, Bencher};
use pwshare_macros::ct_test;

#[inline]
fn uint(constant: u64, bits: u32) -> BoxedUint {
    BoxedUint::from_words_with_precision([constant], bits)
}

#[test]
fn test_x25519_params() {
    let curve = NamedCurve::X25519.curve().unwrap();

    assert_eq!(curve.coordinate_length, 32);

    // 256 bits precision for X25519 (32 bytes)
    let p_expected = uint(1, 256).shl(255).wrapping_sub(uint(19, 256));
    assert_eq!(curve.p.as_ref(), &p_expected);

    let n_expected = uint(1, 256).shl(252).wrapping_add(
        BoxedUint::from_str_radix_with_precision_vartime(
            "14def9dea2f79cd65812631a5cf5d3ed",
            16,
            256,
        )
        .unwrap(),
    );

    assert_eq!(curve.n.as_ref(), &n_expected);
    assert_eq!(curve.G.x, uint(9, 256));

    if let EllipticCurveConstants::Montgomery { A, A_minus2_over4 } = &curve.constants {
        assert_eq!(A, &uint(486662, 256));
        assert_eq!(
            A.wrapping_sub(uint(2, 256))
                .checked_div(&uint(4, 256))
                .unwrap(),
            *A_minus2_over4
        );
    } else {
        panic!("X25519 should be in Montgomery form");
    }
}

#[test]
fn test_x448_params() {
    let curve = NamedCurve::X448.curve().unwrap();

    // 448 bits precision for X448 (56 bytes)
    assert_eq!(curve.coordinate_length, 56);

    let p_expected = BoxedUint::zero_with_precision(448) // acts as 2^448 with wrapping sub
        .wrapping_sub(uint(1, 448).shl(224))
        .wrapping_sub(uint(1, 448));
    assert_eq!(curve.p.as_ref(), &p_expected);

    let n_expected = uint(1, 448).shl(446).wrapping_sub(
        BoxedUint::from_str_radix_with_precision_vartime(
            "8335dc163bb124b65129c96fde933d8d723a70aadc873d6d54a7bb0d",
            16,
            448,
        )
        .unwrap(),
    );
    assert_eq!(curve.n.as_ref(), &n_expected);
    assert_eq!(curve.G.x, uint(5, 448));

    if let EllipticCurveConstants::Montgomery { A, A_minus2_over4 } = &curve.constants {
        assert_eq!(A, &uint(0x262a6, 448));
        assert_eq!(
            A.wrapping_sub(uint(2, 448))
                .checked_div(&uint(4, 448))
                .unwrap(),
            *A_minus2_over4
        );
    } else {
        panic!("X448 should be in Montgomery form");
    }
}

#[test]
fn test_secp256r1_params() {
    let curve = NamedCurve::SECP256R1.curve().unwrap();

    // 256-bits, 32 bytes
    assert_eq!(curve.coordinate_length, 32);

    assert_eq!(
        curve.p.hex(),
        "ffffffff00000001000000000000000000000000ffffffffffffffffffffffff"
    );
    assert_eq!(
        curve.n.hex(),
        "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551"
    );
    assert_eq!(
        curve.G.x.hex(),
        "6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296"
    );
    assert_eq!(
        curve.G.y.hex(),
        "4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5"
    );

    if let EllipticCurveConstants::Weierstrass { a, b } = &curve.constants {
        assert_eq!(
            a.hex(),
            "ffffffff00000001000000000000000000000000fffffffffffffffffffffffc"
        );
        assert_eq!(
            b.hex(),
            "5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b"
        );
    } else {
        panic!("SECP256R1 should be in Weierstrass form");
    }
}

#[test]
fn test_secp384r1_params() {
    let curve = NamedCurve::SECP384R1.curve().unwrap();

    // 384-bit, 48 bytes
    assert_eq!(curve.coordinate_length, 48);

    assert_eq!(curve.p.hex(), "fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffff0000000000000000ffffffff");
    assert_eq!(curve.n.hex(), "ffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf581a0db248b0a77aecec196accc52973");
    assert_eq!(curve.G.x.hex(), "aa87ca22be8b05378eb1c71ef320ad746e1d3b628ba79b9859f741e082542a385502f25dbf55296c3a545e3872760ab7");
    assert_eq!(curve.G.y.hex(), "3617de4a96262c6f5d9e98bf9292dc29f8f41dbd289a147ce9da3113b5f0b8c00a60b1ce1d7e819d7a431d7c90ea0e5f");

    if let EllipticCurveConstants::Weierstrass { a, b } = &curve.constants {
        assert_eq!(a.hex(), "fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffff0000000000000000fffffffc");
        assert_eq!(b.hex(), "b3312fa7e23ee7e4988e056be3f82d19181d9c6efe8141120314088f5013875ac656398d8a2ed19d2a85c8edd3ec2aef");
    } else {
        panic!("SECP384R1 should be in Weierstrass form");
    }
}

#[test]
fn test_secp521r1_params() {
    let curve = NamedCurve::SECP521R1.curve().unwrap();

    // 521-bit, 66 bytes
    assert_eq!(curve.coordinate_length, 66);

    assert_eq!(curve.p.hex(), "1ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
    assert_eq!(curve.n.hex(), "1fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffa51868783bf2f966b7fcc0148f709a5d03bb5c9b8899c47aebb6fb71e91386409");
    assert_eq!(curve.G.x.hex(), "c6858e06b70404e9cd9e3ecb662395b4429c648139053fb521f828af606b4d3dbaa14b5e77efe75928fe1dc127a2ffa8de3348b3c1856a429bf97e7e31c2e5bd66");
    assert_eq!(curve.G.y.hex(), "11839296a789a3bc0045c8a5fb42c7d1bd998f54449579b446817afbd17273e662c97ee72995ef42640c550b9013fad0761353c7086a272c24088be94769fd16650");

    if let EllipticCurveConstants::Weierstrass { a, b } = &curve.constants {
        assert_eq!(a.hex(), "1fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffc");
        assert_eq!(b.hex(), "51953eb9618e1c9a1f929a21a0b68540eea2da725b99b315f3b8b489918ef109e156193951ec7e937b1652c0bd3bb1bf073573df883d2c34f1ef451fd46b503f00");
    } else {
        panic!("SECP521R1 should be in Weierstrass form");
    }
}

#[test]
fn test_x25519_scalar_multiply() {
    let curve = NamedCurve::X25519.curve().unwrap();

    let scalar = BoxedUint::from_str_radix_with_precision_vartime(
        "31029842492115040904895560451863089656472772604678260265531221036453811406496",
        10,
        256,
    )
    .unwrap();

    let u = BoxedUint::from_str_radix_with_precision_vartime(
        "34426434033919594451155107781188821651316167215306631574996226621102155684838",
        10,
        256,
    )
    .unwrap();

    let point = Point {
        x: u,
        y: uint(0, 256),
    };

    let output = curve.scalar_multiply(&scalar, point).x;

    let expected_bytes =
        bytes_from_hex("c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552");
    // crypto-bigint's from_le_slice parses directly matching your native precision bits
    let expected_output = BoxedUint::from_le_slice(&expected_bytes, 256).unwrap();

    assert_eq!(output, expected_output);
}

#[test]
fn test_secp256r1_scalar_multiply() {
    let curve = NamedCurve::SECP256R1.curve().unwrap();

    let scalar = BoxedUint::from_str_radix_with_precision_vartime(
        "a0bf9fce83ee15eba6b984cb12530c4e57d7642d65bca02b92d6d1fa097552b",
        16,
        256,
    )
    .unwrap();

    let point = Point {
        x: BoxedUint::from_str_radix_with_precision_vartime(
            "3c765b26361b7d686f0ea44edc283a6ab54d874ad64c67c312e4bd48db737392",
            16,
            256,
        )
        .unwrap(),
        y: BoxedUint::from_str_radix_with_precision_vartime(
            "c42a4820da897f66821880301719725ec507e2b746505820263ac8c6a4847476",
            16,
            256,
        )
        .unwrap(),
    };

    let output = curve.scalar_multiply(&scalar, point);

    let expected_output = Point {
        x: BoxedUint::from_str_radix_with_precision_vartime(
            "291ccd6c75909645e336aa17cb9533a55bcf5f1185dd5c33c4eee1681774cb35",
            16,
            256,
        )
        .unwrap(),
        y: BoxedUint::from_str_radix_with_precision_vartime(
            "377c86bbe300a2378143da3267fa3f30c150b4ab4d6bf1564a6f5c2fc0f7796e",
            16,
            256,
        )
        .unwrap(),
    };

    assert_eq!(output, expected_output);
}

#[ct_test]
fn test_ct_scalar_multiply_montgomery() {
    let bencher = BenchBuilder::builder()
        .name("Scalar Multiply Montgomery")
        .build()
        .unwrap();

    let curve = NamedCurve::X25519.curve().unwrap();

    let runner = Bencher::generator(
        |scalar| curve.scalar_multiply(&scalar, curve.G.clone()),
        |rng| BoxedUint::random_mod_vartime(rng, curve.n.as_nz_ref()),
        BoxedUint::one_like(&curve.p),
        1_000_000,
    );

    let result = bencher.bench(runner);
    println!("{}", result);

    assert!(result.conclusion().is_probably_ct(), "Not constant time likely");
}
