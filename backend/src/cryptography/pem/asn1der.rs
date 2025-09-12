use crate::cryptography::rsa::{PrivateKey, PublicKey};
use num_bigint::BigUint;
use num_traits::One;

fn encode_length(length: usize, result: &mut Vec<u8>) {
    if length <= 127 {
        // short form, length encoded directly
        result.push(length as u8);
    } else {
        // long form
        // how many bytes are required to encode the length?
        let num_length_bytes = ((usize::BITS - length.leading_zeros() + 7) / 8) as usize;

        assert!(num_length_bytes <= 126, "Object too large"); // 127 is reserved for future extensions

        // first encode how many bytes are needed to encode length
        result.push(0x80 | (num_length_bytes as u8));

        // encode length as big-endian bytes
        let bytes = length.to_be_bytes();

        result.extend_from_slice(&bytes[bytes.len() - num_length_bytes..]);
    }
}

fn encode_integer(integer: i64) -> Vec<u8> {
    let mut result = Vec::new();

    result.push(0x02); // Tag: integer

    let bytes = integer.to_be_bytes();
    // how many bytes can be removed
    let mut skip = 0;

    if integer >= 0 {
        // byte is 00 and the MSB of next byte is 0, can be skipped
        while skip + 1 < bytes.len() && bytes[skip] == 0x00 && (bytes[skip + 1] & 0x80 == 0) {
            skip += 1;
        }
    } else {
        // byte is FF and the MSB of next byte is 1, can be skipped
        while skip + 1 < bytes.len() && bytes[skip] == 0xff && (bytes[skip + 1] & 0x80 != 0) {
            skip += 1;
        }
    }

    encode_length(bytes.len() - skip, &mut result);
    result.extend_from_slice(&bytes[skip..]);

    result
}

fn encode_null() -> Vec<u8> {
    vec![0x05, 0x00]
}

fn decode_null(iter: &mut impl Iterator<Item = u8>) -> Result<(), &'static str> {
    let tag = iter.next().ok_or("EOF, 0x05 expected")?;

    if tag != 0x05 {
        return Err("0x05 expected");
    }

    let null_byte = iter.next().ok_or("EOF, 0x00 expected")?;

    if null_byte != 0x00 {
        return Err("0x00 expected");
    }

    Ok(())
}

fn encode_big_integer(integer: &BigUint) -> Vec<u8> {
    let mut result = Vec::new();

    // Tag
    result.push(0x02); // Tag: Integer

    // how many bytes can be skipped?
    let mut skip: usize = 0;

    let bytes = integer.to_bytes_be();

    // byte is 00 and next byte's MSB is also 0
    while skip + 1 < bytes.len() && bytes[skip] == 0x00 && (bytes[skip + 1] & 0x80 == 0) {
        skip += 1;
    }

    // Length
    encode_length(bytes.len() - skip, &mut result);

    // value
    result.extend_from_slice(&bytes[skip..]);

    result
}

fn encode_sequence(mut sequence: Vec<u8>) -> Vec<u8> {
    let mut result = Vec::new();

    // Tag
    result.push(0x30); // Tag: Sequence

    encode_length(sequence.len(), &mut result);

    result.append(&mut sequence);

    result
}

fn encode_octet_string(mut string: Vec<u8>) -> Vec<u8> {
    let mut result = Vec::new();

    result.push(0x04); // Tag: Octet String

    encode_length(string.len(), &mut result);
    result.append(&mut string);

    result
}

fn encode_bit_string(mut string: Vec<u8>) -> Vec<u8> {
    let mut result = Vec::new();

    result.push(0x03); // Tag: Bit String
    encode_length(string.len() + 1, &mut result);

    result.push(0); // How many bits unused? Since we use bytes, 0
    result.append(&mut string);

    result
}

fn encode_object_identifier(components: &[u32]) -> Vec<u8> {
    let mut result = Vec::new();

    result.push(0x06); // Tag: Object Identifier

    assert!(
        components.len() >= 2,
        "Object identifiers must be at least two components long"
    );

    assert!(components[0] <= 2, "First component must be in 0..=2");

    // first two components are combined with 40*X+Y, then we chain every component after that
    let components = std::iter::once(components[0] * 40 + components[1])
        .chain(components.iter().skip(2).copied());

    for component in components {
        let bits = u32::BITS - component.leading_zeros();
        let number_7_bit_groups = (bits + 6) / 7; // = ceil(bits / 7.0)

        for i in (0..number_7_bit_groups).rev() {
            let byte = ((component >> (i * 7)) & 0x7f) as u8;
            if i == 0 {
                result.push(byte);
            } else {
                result.push(byte | 0x80); // continuation
            }
        }
    }

    // insert length
    let length = result.len() - 1; // without tag
    let mut length_vec = Vec::new();
    encode_length(length, &mut length_vec);
    result.splice(1..1, length_vec); // insert length_vec at index 1

    result
}

fn decode_object_identifier(iter: &mut impl Iterator<Item = u8>) -> Result<Vec<u32>, &'static str> {
    let tag = iter.next().ok_or("Expected 0x06, got none")?;

    if tag != 0x06 {
        return Err("Expected 0x06");
    }

    let length = decode_length(iter)?;

    let bytes = iter.take(length);
    let mut count = 0;
    let mut current: u32 = 0;
    let mut result = Vec::new();

    for byte in bytes {
        current = current << 7 | ((byte & 0x7f) as u32);

        if byte & 0x80 == 0 {
            // no continuation
            result.push(current);
            current = 0;
        }

        count += 1;
    }

    if count != length {
        return Err("Unexpected EOF");
    }

    if result[0] / 40 <= 1 {
        // first component is transformed, remember X*40 + Y
        // we insert Y into [1]
        result.insert(1, result[0] % 40);
        // and then X into [0]
        result[0] = result[0] / 40;
    } else {
        result.insert(1, result[0] - 80);
        result[0] = 2;
    }

    Ok(result)
}

fn decode_length(iter: &mut impl Iterator<Item = u8>) -> Result<usize, &'static str> {
    let byte = iter.next().ok_or("EOF, byte expected")?;
    if byte <= 127 {
        // short form, length is directly encoded
        Ok(byte as usize)
    } else {
        let amount_of_bytes = (byte & 0x7f) as usize;

        if amount_of_bytes > (usize::BITS / 8) as usize {
            return Err("Length too large to fit into usize");
        }

        let length_bytes: Vec<u8> = iter.take(amount_of_bytes).collect();

        if length_bytes.len() < amount_of_bytes {
            Err("EOF, length bytes expected")
        } else {
            Ok(length_bytes
                .into_iter()
                .fold(0_usize, |acc, cur| (acc << 8) | (cur as usize)))
        }
    }
}

fn decode_integer(iter: &mut impl Iterator<Item = u8>) -> Result<i64, &'static str> {
    let tag = iter.next().ok_or("0x02 expected, none found")?;

    if tag != 0x02 {
        // integer
        return Err("0x02 expected");
    }

    let length = decode_length(iter)?;

    if length > 8 {
        return Err("Length too long, maybe call decode_big_integer");
    }

    if length == 0 {
        return Err("Length of integer must not be 0");
    }

    let bytes: Vec<u8> = iter.take(length).collect();

    let mut result = if bytes[0] & 0x80 == 0 {
        [0; 8] // positive
    } else {
        [0xff; 8] // negative
    };

    result[8 - length..].copy_from_slice(&bytes);

    Ok(i64::from_be_bytes(result))
}

fn decode_big_integer(iter: &mut impl Iterator<Item = u8>) -> Result<BigUint, &'static str> {
    let tag = iter.next().ok_or("0x02 expected, none found")?;

    if tag != 0x02 {
        return Err("0x02 expected");
    }

    let length = decode_length(iter)?;
    let bytes: Vec<u8> = iter.take(length).collect();

    if bytes[0] & 0x80 != 0 {
        // negative
        return Err("Negative number");
    }

    Ok(BigUint::from_bytes_be(&bytes))
}

fn decode_sequence(iter: &mut impl Iterator<Item = u8>) -> Result<Vec<u8>, &'static str> {
    let tag = iter.next().ok_or("0x30 expected, none found")?;

    if tag != 0x30 {
        return Err("0x30 expected");
    }

    let length = decode_length(iter)?;
    let result: Vec<u8> = iter.take(length).collect();

    if result.len() != length {
        Err("EOF, value bytes expected")
    } else {
        Ok(result)
    }
}

fn decode_octet_string(iter: &mut impl Iterator<Item = u8>) -> Result<Vec<u8>, &'static str> {
    let tag = iter.next().ok_or("0x04 expected, none found")?;

    if tag != 0x04 {
        return Err("0x04 expected");
    }

    let length = decode_length(iter)?;
    let result: Vec<u8> = iter.take(length).collect();

    if result.len() != length {
        Err("EOF")
    } else {
        Ok(result)
    }
}

fn decode_bit_string(iter: &mut impl Iterator<Item = u8>) -> Result<Vec<u8>, &'static str> {
    let tag = iter.next().ok_or("0x03 expected, none found")?;

    if tag != 0x03 {
        return Err("0x03 expected");
    }

    let length = decode_length(iter)?;
    let unused = iter.next().ok_or("EOF")?;

    if unused >= 8 {
        return Err("Too many unused bits");
    }

    let mut result: Vec<u8> = iter.take(length - 1).collect();

    if result.len() + 1 != length {
        return Err("EOF");
    }

    result[length - 2] &= 0xff << unused; // unset unused bits (right side)

    Ok(result)
}

pub trait ToASN1DER {
    fn to_asn1_der(&self) -> Vec<u8>;
}

fn asn1_rsa_algorithm_identifier() -> Vec<u8> {
    let mut algorithm = encode_object_identifier(&[1, 2, 840, 113549, 1, 1, 1]);
    let mut null = encode_null();

    algorithm.append(&mut null);

    encode_sequence(algorithm)
}

fn decode_rsa_algorithm_identifier(
    iter: &mut impl Iterator<Item = u8>,
) -> Result<(), &'static str> {
    let sequence = decode_sequence(iter)?;

    let mut iter = sequence.into_iter();

    // algorithm
    let alg = decode_object_identifier(&mut iter)?;

    if alg != vec![1, 2, 840, 113549, 1, 1, 1] {
        return Err("Unexpected algorithm identifier");
    }

    // args should be null
    decode_null(&mut iter)?;

    if iter.next().is_some() {
        return Err("Algorithm Identifier sequence has too many bytes");
    }

    Ok(())
}

impl PublicKey {
    fn asn1_rsa_public_key(&self) -> Vec<u8> {
        let mut sequence = Vec::new();

        // modulus - n
        sequence.append(&mut encode_big_integer(&self.n));

        // public exponent - e
        sequence.append(&mut encode_big_integer(&self.e));

        encode_bit_string(encode_sequence(sequence))
    }
}

impl PublicKey {
    fn decode_rsa_public_key(iter: &mut impl Iterator<Item = u8>) -> Result<Self, &'static str> {
        let bit_string = decode_bit_string(iter)?;

        if iter.next().is_some() {
            return Err("Expected EOF");
        }

        let mut iter = bit_string.into_iter();

        let sequence = decode_sequence(&mut iter)?;

        if iter.next().is_some() {
            return Err("Expected EOF");
        }

        let mut iter = sequence.into_iter();

        let n = decode_big_integer(&mut iter)?;
        let e = decode_big_integer(&mut iter)?;

        if iter.next().is_some() {
            return Err("Expected EOF");
        }

        Ok(Self::new(n, e))
    }
}

impl ToASN1DER for PublicKey {
    fn to_asn1_der(&self) -> Vec<u8> {
        let mut algorithm_identifier = asn1_rsa_algorithm_identifier();
        let mut public_key = self.asn1_rsa_public_key();

        let mut sequence = Vec::new();
        sequence.append(&mut algorithm_identifier);
        sequence.append(&mut public_key);

        encode_sequence(sequence)
    }
}

impl PrivateKey {
    fn asn1_version() -> Vec<u8> {
        encode_integer(0)
    }

    fn asn1_rsa_private_key(&self) -> Vec<u8> {
        let mut sequence = Vec::new();

        // version
        sequence.append(&mut encode_integer(0));

        // modulus - n
        sequence.append(&mut encode_big_integer(&self.n));

        // public exponent - e
        sequence.append(&mut encode_big_integer(&self.e));

        // private exponent - d
        sequence.append(&mut encode_big_integer(&self.d));

        // prime 1 - p
        sequence.append(&mut encode_big_integer(&self.p));

        // prime 2 - q
        sequence.append(&mut encode_big_integer(&self.q));

        // exponent 1 - d mod (p - 1)
        sequence.append(&mut encode_big_integer(
            &(&self.d % (&self.p - &BigUint::one())),
        ));

        // exponent 2 - d mod (q - 1)
        sequence.append(&mut encode_big_integer(
            &(&self.d % (&self.q - BigUint::one())),
        ));

        // coefficient - (inverse of q) mod p
        sequence.append(&mut encode_big_integer(&self.q.modinv(&self.p).unwrap()));

        encode_octet_string(encode_sequence(sequence))
    }
}

impl ToASN1DER for PrivateKey {
    fn to_asn1_der(&self) -> Vec<u8> {
        let mut version = Self::asn1_version();
        let mut algorithm_identifier = asn1_rsa_algorithm_identifier();
        let mut private_key = self.asn1_rsa_private_key();

        let mut sequence = Vec::new();
        sequence.append(&mut version);
        sequence.append(&mut algorithm_identifier);
        sequence.append(&mut private_key);

        encode_sequence(sequence)
    }
}

pub trait FromASN1DER: Sized {
    fn from_asn1_der(bytes: impl IntoIterator<Item = u8>) -> Result<Self, &'static str>;
}

impl FromASN1DER for PublicKey {
    fn from_asn1_der(bytes: impl IntoIterator<Item = u8>) -> Result<Self, &'static str> {
        let mut iter = bytes.into_iter();

        let sequence = decode_sequence(&mut iter)?;

        if iter.next().is_some() {
            return Err("Expected EOF");
        }

        let mut iter = sequence.into_iter();
        decode_rsa_algorithm_identifier(&mut iter)?;
        Self::decode_rsa_public_key(&mut iter)
    }
}

impl PrivateKey {
    fn decode_version(
        iter: &mut impl Iterator<Item = u8>,
        expected: i64,
    ) -> Result<(), &'static str> {
        let int = decode_integer(iter)?;

        if int != expected {
            return Err("Version unexpected");
        }

        Ok(())
    }

    fn decode_rsa_private_key(iter: &mut impl Iterator<Item = u8>) -> Result<Self, &'static str> {
        let octet = decode_octet_string(iter)?;

        let mut iter = octet.into_iter();

        let sequence = decode_sequence(&mut iter)?;

        if iter.next().is_some() {
            return Err("Expected EOF");
        }

        let mut iter = sequence.into_iter();

        // version
        Self::decode_version(&mut iter, 0)?;

        // modulus - n
        let n = decode_big_integer(&mut iter)?;

        // public exponent - e
        let e = decode_big_integer(&mut iter)?;

        // private exponent - d
        let d = decode_big_integer(&mut iter)?;

        // prime 1 - p
        let p = decode_big_integer(&mut iter)?;
        // prime 2 - q
        let q = decode_big_integer(&mut iter)?;

        // exponent 1 - d mod (p - 1)
        let exp1 = decode_big_integer(&mut iter)?;

        if (&d % (&p - BigUint::one())) != exp1 {
            return Err("Exponent 1 does not match `d mod (p - 1)`");
        }

        // exponent 2 - d mod (q - 1)
        let exp2 = decode_big_integer(&mut iter)?;

        if (&d % (&q - BigUint::one())) != exp2 {
            return Err("Exponent 2 does not match `d mod (q - 1)`");
        }

        // coefficient - (inverse of q) mod p
        let coeff = decode_big_integer(&mut iter)?;

        if q.modinv(&p).unwrap() != coeff {
            return Err("Coefficient does not match `(inv q) mod p`");
        }

        if iter.next().is_some() {
            return Err("Expected EOF");
        }

        Ok(Self::new(n, d, e, p, q))
    }
}

impl FromASN1DER for PrivateKey {
    fn from_asn1_der(bytes: impl IntoIterator<Item = u8>) -> Result<Self, &'static str> {
        let mut iter = bytes.into_iter();

        // private key info
        let sequence = decode_sequence(&mut iter)?;

        if iter.next().is_some() {
            return Err("More bytes after PrivateKeyInfo");
        }

        let mut iter = sequence.into_iter();

        Self::decode_version(&mut iter, 0)?;
        decode_rsa_algorithm_identifier(&mut iter)?;
        Self::decode_rsa_private_key(&mut iter)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use num_traits::Num;

    #[test]
    fn test_integer() {
        assert_eq!(encode_integer(1), vec![2, 1, 1]);
        assert_eq!(encode_integer(-1), vec![2, 1, 0xff]);
        assert_eq!(encode_integer(0), vec![2, 1, 0]);
        assert_eq!(encode_integer(-0), vec![2, 1, 0]);
        assert_eq!(encode_integer(127), vec![2, 1, 0x7f]);
        assert_eq!(encode_integer(128), vec![2, 2, 0x00, 0x80]);
        assert_eq!(encode_integer(-127), vec![2, 1, 0x81]);
        assert_eq!(encode_integer(-128), vec![2, 1, 0x80]);
        assert_eq!(encode_integer(-129), vec![2, 2, 0xff, 0x7f]);
        assert_eq!(encode_integer(32767), vec![2, 2, 0x7f, 0xff]);
        assert_eq!(encode_integer(32768), vec![2, 3, 0x00, 0x80, 0x00]);
        assert_eq!(encode_integer(32769), vec![2, 3, 0x00, 0x80, 0x01]);
        assert_eq!(encode_integer(-32767), vec![2, 2, 0x80, 0x01]);
        assert_eq!(encode_integer(-32768), vec![2, 2, 0x80, 0x00]);
        assert_eq!(encode_integer(-32769), vec![2, 3, 0xff, 0x7f, 0xff]);
    }

    #[test]
    fn test_long_integer() {
        assert_eq!(
            encode_big_integer(
                &BigUint::from_str_radix("000102030405060708090a0b0c0d0e0f", 16).unwrap()
            ),
            vec![
                0x02, 0x0f, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c,
                0x0d, 0x0e, 0x0f
            ]
        );
    }

    #[test]
    fn test_null() {
        assert_eq!(encode_null(), vec![0x05, 0x00]);
    }

    #[test]
    fn test_oid() {
        assert_eq!(
            encode_object_identifier(&[1, 2, 840, 113549, 1, 1, 11]),
            vec![0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0b]
        );

        assert_eq!(
            encode_object_identifier(&[1, 2, 840, 113549]),
            vec![0x06, 0x06, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D]
        );

        assert_eq!(
            encode_object_identifier(&[1, 2, 3]),
            vec![0x06, 0x02, 0x2a, 0x03]
        );

        assert_eq!(
            encode_object_identifier(&[2, 1482, 3]),
            vec![0x06, 0x03, 0x8c, 0x1a, 0x03]
        );

        assert_eq!(
            encode_object_identifier(&[2, 999, 3]),
            vec![0x06, 0x03, 0x88, 0x37, 0x03]
        );

        assert_eq!(
            encode_object_identifier(&[1, 39, 3]),
            vec![0x06, 0x02, 0x4f, 0x03]
        );

        assert_eq!(
            encode_object_identifier(&[1, 2, 300000]),
            vec![0x06, 0x04, 0x2a, 0x92, 0xa7, 0x60]
        );

        assert_eq!(
            encode_object_identifier(&[1, 2, 840, 113554, 1, 2, 1, 1]),
            vec![0x06, 0x0a, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x12, 0x01, 0x02, 0x01, 0x01]
        );
    }

    #[test]
    fn test_integer_decode() {
        assert_eq!(decode_integer(&mut vec![2, 1, 1].into_iter()).unwrap(), 1);
        assert_eq!(
            decode_integer(&mut vec![2, 1, 0xff].into_iter()).unwrap(),
            -1
        );
        assert_eq!(decode_integer(&mut vec![2, 1, 0].into_iter()).unwrap(), 0);
        assert_eq!(decode_integer(&mut vec![2, 1, 0].into_iter()).unwrap(), -0);
        assert_eq!(
            decode_integer(&mut vec![2, 1, 0x7f].into_iter()).unwrap(),
            127
        );
        assert_eq!(
            decode_integer(&mut vec![2, 2, 0x00, 0x80].into_iter()).unwrap(),
            128
        );
        assert_eq!(
            decode_integer(&mut vec![2, 1, 0x81].into_iter()).unwrap(),
            -127
        );
        assert_eq!(
            decode_integer(&mut vec![2, 1, 0x80].into_iter()).unwrap(),
            -128
        );
        assert_eq!(
            decode_integer(&mut vec![2, 2, 0xff, 0x7f].into_iter()).unwrap(),
            -129
        );
        assert_eq!(
            decode_integer(&mut vec![2, 2, 0x7f, 0xff].into_iter()).unwrap(),
            32767
        );
        assert_eq!(
            decode_integer(&mut vec![2, 3, 0x00, 0x80, 0x00].into_iter()).unwrap(),
            32768
        );
        assert_eq!(
            decode_integer(&mut vec![2, 3, 0x00, 0x80, 0x01].into_iter()).unwrap(),
            32769
        );
        assert_eq!(
            decode_integer(&mut vec![2, 2, 0x80, 0x01].into_iter()).unwrap(),
            -32767
        );
        assert_eq!(
            decode_integer(&mut vec![2, 2, 0x80, 0x00].into_iter()).unwrap(),
            -32768
        );
        assert_eq!(
            decode_integer(&mut vec![2, 3, 0xff, 0x7f, 0xff].into_iter()).unwrap(),
            -32769
        );
    }

    #[test]
    fn test_long_integer_decode() {
        assert_eq!(
            decode_big_integer(
                &mut vec![
                    0x02, 0x0f, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b,
                    0x0c, 0x0d, 0x0e, 0x0f
                ]
                .into_iter()
            )
            .unwrap(),
            BigUint::from_str_radix("000102030405060708090a0b0c0d0e0f", 16).unwrap()
        );
    }

    #[test]
    fn test_null_decode() {
        assert_eq!(decode_null(&mut vec![0x05, 0x00].into_iter()).unwrap(), ());
    }

    #[test]
    fn test_oid_decode() {
        assert_eq!(
            decode_object_identifier(
                &mut vec![0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0b]
                    .into_iter()
            )
            .unwrap(),
            vec![1, 2, 840, 113549, 1, 1, 11]
        );

        assert_eq!(
            decode_object_identifier(
                &mut vec![0x06, 0x06, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D].into_iter()
            )
            .unwrap(),
            vec![1, 2, 840, 113549]
        );

        assert_eq!(
            decode_object_identifier(&mut vec![0x06, 0x02, 0x2a, 0x03].into_iter()).unwrap(),
            vec![1, 2, 3]
        );

        assert_eq!(
            decode_object_identifier(&mut vec![0x06, 0x03, 0x8c, 0x1a, 0x03].into_iter()).unwrap(),
            vec![2, 1482, 3]
        );

        assert_eq!(
            decode_object_identifier(&mut vec![0x06, 0x03, 0x88, 0x37, 0x03].into_iter()).unwrap(),
            vec![2, 999, 3]
        );

        assert_eq!(
            decode_object_identifier(&mut vec![0x06, 0x02, 0x4f, 0x03].into_iter()).unwrap(),
            vec![1, 39, 3]
        );

        assert_eq!(
            decode_object_identifier(&mut vec![0x06, 0x04, 0x2a, 0x92, 0xa7, 0x60].into_iter())
                .unwrap(),
            vec![1, 2, 300000]
        );

        assert_eq!(
            decode_object_identifier(
                &mut vec![0x06, 0x0a, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x12, 0x01, 0x02, 0x01, 0x01]
                    .into_iter()
            )
            .unwrap(),
            vec![1, 2, 840, 113554, 1, 2, 1, 1]
        );
    }
}
