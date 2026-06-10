use crate::cryptography::elliptic_curves::curve::*;
use crate::tls::record::key_exchange::ecdhe::elliptic_curve::NamedCurve;
use crate::util::bytes_from_hex;
use crypto_bigint::BoxedUint;

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
