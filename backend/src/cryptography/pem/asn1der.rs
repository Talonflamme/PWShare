use crate::cryptography::rsa::{PrivateKey, PublicKey};
use crypto_bigint::{Encoding, Limb, Uint, Word};

fn encode_length(length: usize, result: &mut Vec<u8>) {
    if length <= 127 {
        // short form, length encoded directly
        result.push(length as u8);
    } else {
        // long form
        let num_length_bytes = ((length as f64).log2() / 8.0).ceil() as usize; // ceil(log256(length))

        assert!(num_length_bytes <= 126, "Object too large"); // 127 is reserved for future extensions

        // first encode how many bytes are needed to encode length
        result.push(0x80 | (num_length_bytes as u8));

        // encode length as big-endian bytes
        let bytes = length.to_be_bytes();

        result.extend_from_slice(&bytes[bytes.len() - num_length_bytes..]);
    }
}

fn encode_integer<const L: usize>(integer: Uint<L>) -> Vec<u8>
where
    Uint<L>: Encoding,
    <Uint<L> as Encoding>::Repr: AsRef<[u8]>,
{
    let length = Uint::<L>::BYTES;

    let mut result = Vec::new();

    // Tag
    result.push(0x02); // Tag: Integer

    // Length
    encode_length(length, &mut result);

    // value
    let bytes = integer.to_be_bytes();
    result.extend_from_slice(bytes.as_ref());

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

fn read_uint<const L: usize>(iter: impl Iterator<Item = u8>) -> Result<Uint<L>, &'static str> {
    let mut res = [Limb::ZERO; L];
    let mut buf = [0u8; Limb::BYTES];
    let mut i = 0;

    for byte in iter {
        let j = i % Limb::BYTES;
        buf[j] = byte;

        if j == Limb::BYTES - 1 {
            let limb_index = i / Limb::BYTES;
            // limbs seem to be little endian, so we need to reverse the index here
            res[L - limb_index - 1] = Limb(Word::from_be_bytes(buf));
        }

        i += 1;
    }

    if i != Uint::<L>::BYTES {
        Err("Unexpected EOF")
    } else {
        Ok(Uint::new(res))
    }
}

fn decode_integer<const L: usize>(
    iter: &mut impl Iterator<Item = u8>,
) -> Result<Uint<L>, &'static str> {
    let tag = iter.next().ok_or("0x02 expected, none found")?;

    if tag != 0x02 {
        return Err("0x02 expected");
    }

    let length = decode_length(iter)?;

    if length != Uint::<L>::BYTES {
        return Err("unexpected length for L");
    }

    read_uint(iter.take(length))
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

pub trait ToASN1DER {
    fn to_asn1_der(&self) -> Vec<u8>;
}

impl<const L: usize> ToASN1DER for PublicKey<L>
where
    Uint<L>: Encoding,
    <Uint<L> as Encoding>::Repr: AsRef<[u8]>,
{
    fn to_asn1_der(&self) -> Vec<u8> {
        let mut n = encode_integer(self.n);
        let mut e = encode_integer(self.e);

        n.append(&mut e);

        let sequence = encode_sequence(n);
        sequence
    }
}

impl<const L: usize> ToASN1DER for PrivateKey<L>
where
    Uint<L>: Encoding,
    <Uint<L> as Encoding>::Repr: AsRef<[u8]>,
{
    fn to_asn1_der(&self) -> Vec<u8> {
        let mut n = encode_integer(self.n);
        let mut d = encode_integer(self.d);

        n.append(&mut d);

        let sequence = encode_sequence(n);
        sequence
    }
}

pub trait FromASN1DER: Sized {
    fn from_asn1_der(bytes: impl IntoIterator<Item = u8>) -> Result<Self, &'static str>;
}

impl<const L: usize> FromASN1DER for PublicKey<L> {
    fn from_asn1_der(bytes: impl IntoIterator<Item = u8>) -> Result<Self, &'static str> {
        let mut iter = bytes.into_iter();

        let mut sequence = decode_sequence(&mut iter)?.into_iter();

        let n = decode_integer::<L>(&mut sequence)?;
        let e = decode_integer::<L>(&mut sequence)?;

        if !sequence.next().is_none() {
            Err("Sequence contains more than just 2 integers")
        } else if !iter.next().is_none() {
            Err("Bytes encode for more than just a sequence")
        } else {
            Ok(PublicKey::new(n, e))
        }
    }
}

impl<const L: usize> FromASN1DER for PrivateKey<L> {
    fn from_asn1_der(bytes: impl IntoIterator<Item = u8>) -> Result<Self, &'static str> {
        let mut iter = bytes.into_iter();

        let mut sequence = decode_sequence(&mut iter)?.into_iter();

        let n = decode_integer::<L>(&mut sequence)?;
        let d = decode_integer::<L>(&mut sequence)?;

        if !sequence.next().is_none() {
            Err("Sequence contains more than just 2 integers")
        } else if !iter.next().is_none() {
            Err("Bytes encode for more than just a sequence")
        } else {
            Ok(PrivateKey::new(n, d))
        }
    }
}
