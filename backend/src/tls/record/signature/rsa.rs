use super::hash_algorithm::HashAlgorithm;
use crate::cryptography::pem::asn1der::{self, FromASN1DER, ToASN1DER};
use crate::cryptography::pkcs1_v1_5;
use crate::cryptography::pkcs1_v1_5::PKCS1v1_5Mode;
use crate::cryptography::rsa::RSAPrivateKey;
use crate::tls::record::alert::{Alert, Result};
use crate::util::UintDisplay;
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

pub fn sign(
    key: &RSAPrivateKey,
    message: &[u8],
    hash_algorithm: &HashAlgorithm,
) -> Result<Vec<u8>> {
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

    println!("Hash {}", hash.hex());

    let digest_info = DigestInfo {
        digest_algorithm_oid: identifier,
        digest: hash,
    };

    let asn1der = digest_info.to_asn1_der();

    println!("digest i {}", asn1der.hex());

    let padded = pkcs1_v1_5::pad(&asn1der, key.size_in_bytes(), PKCS1v1_5Mode::Signature)
        .map_err(|_| Alert::internal_error("Padding using PKCS1 v1.5 failed"))?;
    let message = BigUint::from_bytes_be(&padded);

    println!("pad {}", padded.hex());

    let sig = key
        .decrypt(message)
        .map_err(|_| Alert::internal_error("Signing failed due to message being out of range"))?;

    println!("{}", sig.hex());

    Ok(sig.to_bytes_be())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cryptography::rsa::RSAPrivateKey;
    use crate::util::UintDisplay;
    use num_traits::Num;

    #[test]
    fn test_sign() {
        let key = RSAPrivateKey::new(
            BigUint::from_str_radix("dc88b998ecca070c7fa4d4e901efb89721d50d9bc674d8bde71a6e2bd182b94bc3346857ce140d39b3de6dcd1cfb466ee217e31205b3aa5bb394b61906f46d2d2929deaac8facaa8e559e3010abf4d2f7b7694ca5cfac6226fc6062b29b79645abebf6cd9d6f5180b5cdc39feabed04830c590ebf7fbb655ceeb452ffe626acc6eb8f4a08c5caa40c0968334f0cf831166a9c520f698628e00dd694f9e2226339cc8acec24752891b3a00602844d3173e790b8bc037ce2fe1576d10cfafd12b5e1011b3e35f14a22ac222a8bc6459297b07ec45c2399b9da9bdeb994add92ef12274a11af912b14814bf1a7a68a246089b59b03afca04c335369011a08c4863d", 16).unwrap(),
            BigUint::from_str_radix("9d069d604df9ebdaf26823516597930fc97f321960cd8226758f5432cf130d6ceca93c4288f1ae191001a89d0badbf10e4dbad4affd455d0c5a575a38c582e04a1f2b62154c97dd394bad3efc1ff44ae3272d4aee2558d0ea8178ffcdbcf64a86729b4a9e3178828e54a85a830357d886971c326c183f0e858551d0677530c4700bab2bd49b14516f32be6b89f4824ef3690d8167a430cffaa57f04bb67f4f0aece45408bb8bfa4e3d3b12080b7e8cf58488c045acdb65b30c9ffc4b91849fbca262f4245d4ebd032915088c5a379c34dc4452c49a365baa0ef30be3386fb9fb7672b98fb87e1d9dbf5680df2e0a5d4bd30c93aa019d9b2cc554af68601215f", 16).unwrap(),
            BigUint::from(65537_u32),
            BigUint::from_str_radix("feee482b87c031319d98b2e503f948dcb9080948e4cb463995f1998bcd70105d538a6de715309ae1a755a3995e205e8ced98b815831da382d04f62779ee3217de4e062fc28069f7b3122c6bdde0b8aab92cfecf737050bff8af5d881bcb0b205a57f9584fbdffec4bd6f46aef8ee1bca72bafba4229da15c44126be37d1c3b37", 16).unwrap(),
            BigUint::from_str_radix("dd7582f05d0dcc8887b3048eea6b346a828881637d51a83b028e9f560eb170c2ddad5db6b8b1c2576576d8e45023d302f80c13b4de5fefa8496500894234cb8305a7607c3e004a70d99e9b7daa0f292a4252b9ad44bc68dc74c5722252b49c1b5e2859bcc664bd81ff4ae923164b84662ece54c9ff0de05ee424eb567fc00c2b", 16).unwrap(),
        );

        let message = b"Hello World";
        let expected_signature = "34132027d6b55d41e83be232e030f87051e810ec757dc176b781988ce81f0da52f3b22d486e09f8e92f9308d42a3998f48a46ca2f7647861789e5289dcd776135e17cdaefdd683843cfd075a9534ca9e483929fa1ac83d9c4864b5ed9ed2845f940ff9f89ab27b5cfdcca1ca0a27b87e6ba5ddf1cf7c2a47b197223b01b1b1d312bf25a57a81465b5e85c1672e15de194790fef0b128fe55688eebce6193dc285bbf45293af351bacb8a9a8db4716822abb2d37fc151106c47c55ce47ee0c565b73be19f48baff12ff0f066cf8bff7c7011d3e8227226103ee91a28e053355b9e3ea4af8d73f239ab25a29b2ea418a629970da910cd78484bfc7a3f5863a4e2f";

        let signature = sign(&key, message, &HashAlgorithm::Sha256).unwrap().hex();

        assert_eq!(signature, expected_signature);
    }
}
