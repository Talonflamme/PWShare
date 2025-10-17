use super::hash_algorithm::HashAlgorithm;
use crate::cryptography::pem::asn1der::{self, FromASN1DER, ToASN1DER};
use crate::cryptography::pkcs1_v1_5;
use crate::cryptography::rsa::PrivateKey;
use crate::tls::record::alert::{Alert, Result};
use num_bigint::BigUint;
use pwshare_macros::{ReadableFromStream, WritableToSink};

#[derive(Debug, ReadableFromStream, WritableToSink)]
pub struct RsaSignature {}

struct DigestInfo {
    digest_algorithm_oid: Vec<u32>,
    digest: Vec<u8>,
}

fn algorithm_identifier_with_null(oid: &[u32]) -> Vec<u8> {
    let mut alg = asn1der::encode_object_identifier(oid);
    let mut null = asn1der::encode_null();

    alg.append(&mut null);

    asn1der::encode_sequence(alg)
}

impl ToASN1DER for DigestInfo {
    fn to_asn1_der(&self) -> Vec<u8> {
        let mut alg = algorithm_identifier_with_null(&self.digest_algorithm_oid);
        let mut dig = asn1der::encode_octet_string(self.digest.clone());

        alg.append(&mut dig);
        asn1der::encode_sequence(alg)
    }
}

impl FromASN1DER for DigestInfo {
    fn from_asn1_der(
        bytes: impl IntoIterator<Item = u8>,
    ) -> std::result::Result<Self, &'static str> {
        let mut iter = bytes.into_iter();

        let sequence = asn1der::decode_sequence(&mut iter)?;

        if iter.next().is_some() {
            return Err("Expected EOF");
        }

        let mut iter = sequence.into_iter();

        let alg = asn1der::decode_sequence(&mut iter)?;
        let dig = asn1der::decode_octet_string(&mut iter)?;

        if iter.next().is_some() {
            return Err("Expected EOF");
        }

        let mut iter = alg.into_iter();
        let alg_oid = asn1der::decode_object_identifier(&mut iter)?;
        asn1der::decode_null(&mut iter)?; // expect null as parameters

        if iter.next().is_some() {
            return Err("Expected EOF");
        }

        Ok(Self {
            digest_algorithm_oid: alg_oid,
            digest: dig,
        })
    }
}

pub fn sign(key: &PrivateKey, message: &[u8], hash_algorithm: &HashAlgorithm) -> Result<Vec<u8>> {
    let identifier = hash_algorithm
        .object_identifier()
        .ok_or(Alert::internal_error(format!(
            "No object identifier found for: {:?}",
            hash_algorithm
        )))?;

    let hasher = hash_algorithm
        .hasher()
        .ok_or(Alert::internal_error(format!(
            "No hash function found for: {:?}",
            hash_algorithm
        )))?;

    let hash = hasher.hash(message);
    let digest_info = DigestInfo {
        digest_algorithm_oid: identifier,
        digest: hash,
    };

    let asn1der = digest_info.to_asn1_der();
    let padded = pkcs1_v1_5::pad(&asn1der, key.size_in_bytes())
        .map_err(|_| Alert::internal_error("Padding using PKCS1 v1.5 failed"))?;
    let message = BigUint::from_bytes_be(&padded);

    let sig = key
        .decrypt(message)
        .map_err(|_| Alert::internal_error("Signing failed due to message being out of range"))?;

    Ok(sig.to_bytes_be())
}
