use crate::cryptography::hashing::{self, HashFunction};
use crate::tls::connection_state::security_parameters::SecurityParameters;

#[derive(Debug, Clone, Copy)]
pub enum MACAlgorithm {
    Null,
    HMacMd5,
    HMacSha1,
    HMacSha256,
    HMacSha384,
    HMacSha512,
}

// TODO: change m to be iterable, don't require a slice
/// Applies the HMAC-X algorithm, with x being the hash function of `self`. The return value
/// will always have the output length of the hashing algorithm as a length, since the
/// last step in `HMAC-X` is calling the Hash function.
///
/// ### Parameters:
/// * `k` - The secret key.
/// * `m` - The message to be authenticated.
pub fn hmac(hash: &dyn HashFunction, k: &[u8], m: &[u8]) -> Vec<u8> {
    let block_size = hash.block_size_bytes();
    let hash_size = hash.h_len();

    if hash_size > block_size {
        panic!("K' cannot be generated.");
    }

    // produce K'
    let mut key_prime = vec![0u8; block_size];

    if k.len() > block_size {
        key_prime[..hash_size].copy_from_slice(hash.hash(k).as_slice());
    } else {
        key_prime[..k.len()].copy_from_slice(k);
    }

    let mut value_to_be_hashed: Vec<u8> = Vec::with_capacity(block_size + hash_size);

    // (K' ^ opad)
    for key_byte in key_prime.iter() {
        value_to_be_hashed.push(*key_byte ^ 0x5c);
    }

    // key_prime will hold (K' ^ ipad) after this
    for p in key_prime.iter_mut() {
        *p ^= 0x36;
    }

    // (K' ^ ipad) || m
    key_prime.extend_from_slice(m);

    // H((K' ^ ipad) || m)
    let mut hashed_key = hash.hash(key_prime.as_slice());

    value_to_be_hashed.append(&mut hashed_key);

    hash.hash(value_to_be_hashed.as_slice())
}

impl MACAlgorithm {
    fn get_hash(&self) -> Box<dyn HashFunction> {
        match self {
            MACAlgorithm::Null => panic!("No hash function for Null"),
            MACAlgorithm::HMacMd5 => Box::new(hashing::Md5),
            MACAlgorithm::HMacSha1 => Box::new(hashing::Sha1),
            MACAlgorithm::HMacSha256 => Box::new(hashing::Sha256),
            MACAlgorithm::HMacSha384 => Box::new(hashing::Sha384),
            MACAlgorithm::HMacSha512 => Box::new(hashing::Sha512),
        }
    }

    /// Applies the HMAC-X algorithm, with x being the hash function of `self`. The return value
    /// will always have the output length of the hashing algorithm as a length, since the
    /// last step in `HMAC-X` is calling the Hash function.
    ///
    /// ### Parameters:
    /// * `k` - The secret key.
    /// * `m` - The message to be authenticated.
    pub fn hmac(&self, k: &[u8], m: &[u8]) -> Vec<u8> {
        hmac(self.get_hash().as_ref(), k, m)
    }

    /// Sets `.mac_algorithm`, `.mac_length` and `.mac_key_length` of a `SecurityParameters`
    /// to the values matching `self`.
    pub fn set_params(&self, params: &mut SecurityParameters) {
        match self {
            Self::Null => {
                params.mac_algorithm = Some(MACAlgorithm::Null);
                params.mac_length = Some(0);
                params.mac_key_length = Some(0);
            }
            Self::HMacMd5 => {
                params.mac_algorithm = Some(MACAlgorithm::HMacMd5);
                params.mac_length = Some(16);
                params.mac_key_length = Some(16);
            }
            Self::HMacSha1 => {
                params.mac_algorithm = Some(MACAlgorithm::HMacSha1);
                params.mac_length = Some(20);
                params.mac_key_length = Some(20);
            }
            Self::HMacSha256 => {
                params.mac_algorithm = Some(MACAlgorithm::HMacSha256);
                params.mac_length = Some(32);
                params.mac_key_length = Some(32);
            }
            Self::HMacSha384 => {
                params.mac_algorithm = Some(MACAlgorithm::HMacSha384);
                params.mac_length = Some(48);
                params.mac_key_length = Some(48);
            }
            Self::HMacSha512 => {
                params.mac_algorithm = Some(MACAlgorithm::HMacSha512);
                params.mac_length = Some(64);
                params.mac_key_length = Some(64);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::util::UintDisplay;

    #[test]
    fn test() {
        assert_eq!(
            MACAlgorithm::HMacMd5
                .hmac(
                    "key".as_bytes(),
                    "The quick brown fox jumps over the lazy dog".as_bytes()
                )
                .hex(),
            "80070713463e7749b90c2dc24911e275"
        );

        assert_eq!(
            MACAlgorithm::HMacSha1
                .hmac(
                    "key".as_bytes(),
                    "The quick brown fox jumps over the lazy dog".as_bytes()
                )
                .hex(),
            "de7c9b85b8b78aa6bc8a7a36f70a90701c9db4d9"
        );

        assert_eq!(
            MACAlgorithm::HMacSha256
                .hmac(
                    "key".as_bytes(),
                    "The quick brown fox jumps over the lazy dog".as_bytes()
                )
                .hex(),
            "f7bc83f430538424b13298e6aa6fb143ef4d59a14946175997479dbc2d1a3cd8"
        );

        assert_eq!(
            MACAlgorithm::HMacSha512
                .hmac(
                    "key".as_bytes(),
                    "The quick brown fox jumps over the lazy dog".as_bytes()
                )
                .hex(),
            "b42af09057bac1e2d41708e48a902e09b5ff7f12ab428a4fe86653c73dd248fb82f948a549f7b791a5b41915ee4d1ec3935357e4e2317250d0372afa2ebeeb3a"
        );
    }
}
