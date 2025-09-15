use rand::RngCore;
use crate::cryptography::rng::rng;
use crate::cryptography::hashing::{HashFunction, Sha256};
use crate::cryptography::oaep::mgf1;

fn generate_random_seed(h_len: usize) -> Vec<u8> {
    let mut result = vec![0u8; h_len];

    rng!().fill_bytes(result.as_mut_slice());

    result
}

macro_rules! xor {
    ($a:ident, $b:ident) => {
        $a.into_iter()
            .zip($b.into_iter())
            .map(|(a, b)| a ^ b)
            .collect::<Vec<_>>()
    };
}

#[derive(Debug)]
pub struct OAEPDecodingError {
    reason: &'static str,
}

#[derive(Debug)]
pub struct OAEPEncodingError {
    reason: &'static str,
}

/// Pads a message using the OAEP encoding scheme.
///
/// # Arguments
///
/// * `message` - A byte slice representing the message to be padded
/// * `k` - The length in bytes of the RSA modulus (size of n in bytes)
///
/// # Returns
///
/// A `Result` containing the padded message as a `Vec<u8` on success, or an
/// `OAEPEncodingError` on failure.
///
/// # Errors
///
/// Returns `OAEPEncodingError` if the message is too long for the given `k`.
pub fn pad(message: &[u8], k: usize) -> Result<Vec<u8>, OAEPEncodingError> {
    let hash = Sha256;

    // length of output of hash function in bytes
    let h_len = hash.h_len() as usize;

    // length of message in bytes, with:
    // m_len <= k - 2 * h_len - 2
    let m_len = message.len();

    if m_len > k - 2 * h_len - 2 {
        return Err(OAEPEncodingError {
            reason: "Message too large",
        });
    }

    // optional label, usually an empty string
    let l = ""; // label

    // 1. Hash the label L: Hash(L) = lHash
    let mut l_hash = hash.hash(l.as_bytes());

    // 2. Create a padding-string consisting of k - m_len - 2 * h_len - 2 bytes with value 0x00
    let mut ps = vec![0u8; k - m_len - 2 * h_len - 2];

    // 3. Concatenate lHash, PS, the single byte 0x01 and the message M to form a data block DB
    let mut db: Vec<u8> = Vec::with_capacity(k - h_len - 1);
    db.append(&mut l_hash);
    db.append(&mut ps);
    db.push(0x01);
    db.extend_from_slice(message);

    // 4. Generate a random seed of length h_len
    let seed = generate_random_seed(h_len);

    // 5. Use the mask generating function fo generate a mask of the appropriate length for the data block
    let db_mask = mgf1(&hash, seed.as_slice(), k - h_len - 1);

    // 6. Mask the data block with generated mask
    let mut masked_db = xor!(db, db_mask);

    // 7. Use the mask generating function to generate a mask of length h_len for the seed
    let seed_mask = mgf1(&hash, masked_db.as_slice(), h_len);

    // 8. Mask the seed with the generated mask
    let mut masked_seed = xor!(seed, seed_mask);

    // 9. the encoded message is the byte 0x00 concatenated with the masked_seed and masked_db
    let mut encoded_message = Vec::new();
    encoded_message.push(0x00);
    encoded_message.append(&mut masked_seed);
    encoded_message.append(&mut masked_db);

    Ok(encoded_message)
}

/// Removes OAEP padding from a message.
///
/// # Arguments
///
/// * `padded_message` - A byte slice representing the OAEP padded message.
/// * `k` - The length in bytes of the RSA modulus (size of n in bytes)
///
/// # Returns
///
/// A `Result` containing the original unpadded message as a `Vec<u8` on success, or an
/// `OAEPDecodingError` on failure.
///
/// # Errors
///
/// Returns `OAEPDecodingError` if the padding is invalid or the message cannot be recovered.
pub fn unpad(padded_message: &[u8], k: usize) -> Result<Vec<u8>, OAEPDecodingError> {
    if padded_message.len() != k {
        return Err(OAEPDecodingError {
            reason: "len(EM) != k",
        });
    }

    if padded_message[0] != 0x00 {
        return Err(OAEPDecodingError {
            reason: "First byte of EM must be 0x00",
        });
    }

    let hash = Sha256;

    // length of output of hash function in bytes
    let h_len = hash.h_len() as usize;

    // optional label, usually an empty string
    let l = ""; // label

    // 1. Hash the label L: Hash(L) = lHash
    let l_hash = hash.hash(l.as_bytes());

    // 2. Split message into 0x00 || masked_seed || masked_db
    let masked_seed = &padded_message[1..=h_len];
    let masked_db = &padded_message[h_len + 1..];

    // 3. generate the seed_mask which was used to mask the seed
    let seed_mask = mgf1(&hash, masked_db, h_len);

    // 4. Recover the seed
    let seed = xor!(masked_seed, seed_mask);

    // 5. Generate the db_mask
    let db_mask = mgf1(&hash, seed.as_slice(), k - h_len - 1);

    // 6. Recover the data block db
    let mut db = xor!(masked_db, db_mask).into_iter();

    // 7. split db into its parts: db = lHash' || PS || 0x01 || M

    let l_hash_prime: Vec<u8> = db.by_ref().take(h_len).collect();

    let db: Vec<u8> = db.collect(); // db = PS || 0x01 || M

    let sep_index = db
        .iter()
        .position(|&b| b == 0x01)
        .ok_or(OAEPDecodingError {
            reason: "0x01 separator not found in db",
        })?;

    let ps = &db[..sep_index];

    // byte at `sep_index` is definitely 0x01

    let m: Vec<u8> = db[sep_index + 1..].to_vec();

    // Verify
    // lHash' == lHash
    if l_hash_prime.len() != l_hash.len()
        || l_hash_prime
            .into_iter()
            .zip(l_hash.into_iter())
            .any(|(a, b)| a != b)
    {
        return Err(OAEPDecodingError {
            reason: "lHash' != Hash(L)",
        });
    }

    if ps.into_iter().any(|&a| a != 0x00) {
        return Err(OAEPDecodingError {
            reason: "PS contains non-zero byte",
        });
    }

    // first byte of EM is 0x00?
    Ok(m)
}
