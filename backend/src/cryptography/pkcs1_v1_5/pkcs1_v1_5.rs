use rand::RngCore;
use crate::cryptography::rng::rng;

#[derive(Debug)]
pub struct PKCS1v1_5EncodingError {
    pub reason: &'static str,
}

#[derive(Debug)]
pub struct PKCS1v1_5DecodingError {
    pub reason: &'static str,
}

fn generate_random_pad_string(length: usize) -> Vec<u8> {
    let mut res = vec![0x00; length];

    // store a couple of randoms in advance to not have to compute them every iteration
    let mut random_cache: Vec<u8> = Vec::with_capacity(4);

    for byte in res.iter_mut() {
        while *byte == 0 {
            // no 0, since it's required as a separator

            if random_cache.len() == 0 {
                random_cache.extend_from_slice(&rng!().next_u32().to_be_bytes());
            }

            *byte = random_cache.pop().unwrap();
        }
    }

    res
}

/// Pads a message using the PKCS#1 v1.5 padding specification.
///
/// # Arguments
///  * `message´ - A byte slice representing the message to be padded of arbitrary length
/// * `k` - The length in bytes of the RSA modulus (size of `n` in bytes)
///
/// # Returns
///
/// A `Result` containing the padded message as a `Vec<u8` on success, or an
/// `PKCS1v1_5EncodingError` on failure.
///
/// # Errors
///
/// Returns `OAEPEncodingError` if the message is too long for the given `k`.
pub fn pad(message: &[u8], k: usize) -> Result<Vec<u8>, PKCS1v1_5EncodingError> {
    // Need 2 marker bytes, 1 separator and at least 8 random bytes (PS)
    if message.len() > k - 11 {
        return Err(PKCS1v1_5EncodingError {
            reason: "Message too large",
        });
    }

    let mut encoded_message = Vec::with_capacity(k);

    // Start with 0x00
    encoded_message.push(0x00);

    // Block Type, 0x02 for encryption
    encoded_message.push(0x02);

    // Pad String (PS)
    let mut pad_string = generate_random_pad_string(k - message.len() - 3);
    encoded_message.append(&mut pad_string);

    // Separator between padding and data
    encoded_message.push(0x00);

    // actual data
    encoded_message.extend_from_slice(message);

    Ok(encoded_message)
}

/// Removes PKCS#1 v1.5 padding from a message.
///
/// # Arguments
///
/// * `padded_message` - A byte slice representing the PKCS#1 v1.5 padded message.
/// * `k` - The length in bytes of the RSA modulus (size of `n` in bytes)
///
/// # Returns
///
/// A `Result` containing the original unpadded message as a `Vec<u8` on success, or an
/// `PKCS1v1_5DecodingError` on failure.
///
/// # Errors
///
/// Returns `PKCS1v1_5DecodingError` if the padding is invalid or the message cannot be recovered.
pub fn unpad(padded_message: &[u8], k: usize) -> Result<Vec<u8>, PKCS1v1_5DecodingError> {
    if padded_message.len() != k {
        return Err(PKCS1v1_5DecodingError {
            reason: "len(EM) != k",
        });
    }

    if padded_message[0] != 0x00 {
        return Err(PKCS1v1_5DecodingError {
            reason: "First byte of EM must be 0x00",
        });
    }

    match padded_message[1] {
        0x02 => {}
        0x01 => {
            return Err(PKCS1v1_5DecodingError {
                reason: "Block Type 0x01 is not supported in this implementation",
            })
        }
        _ => {
            return Err(PKCS1v1_5DecodingError {
                reason: "Block Type must be 0x02",
            })
        }
    }

    let separator_index = 2 + padded_message
        .iter()
        .skip(2)
        .position(|byte| *byte == 0x00)
        .ok_or(PKCS1v1_5DecodingError {
            reason: "No separator 0x00 found",
        })?;

    if separator_index < 10 {
        return Err(PKCS1v1_5DecodingError {
            reason: "len(PS) < 8",
        });
    }

    let message = &padded_message[separator_index + 1..];

    Ok(message.to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn from_hex(hex: &str) -> Vec<u8> {
        (0..hex.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&hex[i..=i + 1], 16).unwrap())
            .collect()
    }

    fn test_case_unpad(em: &str, k: usize, expected: &str) {
        assert_eq!(
            unpad(from_hex(em).as_slice(), k).unwrap(),
            from_hex(expected)
        );
    }

    #[test]
    fn test_unpad() {
        test_case_unpad("0002909347d2957a7f4a2a7c3325255b9645dce8059e5c4ea648c0ecefb88d24153aadb325bdb2311a6626c6df26297c3ac7688c51eeee31c242ed341888abd03861de4399b842652ecddde5d3c0dd46ddf285fd7dd12daf34bf8c95e64e7fdace959dd4ee20229eb04d8347c4a94e728329e9477a93170b27070a9ea91ca012ae7c59f30712a8ab83b66346a13b2d7d5fb6f15c5a0096946c9765d1a26ab024d317182a969be0763cd4ae4b54dad83f56f07fa95ed8fb00558eb87ab6fb97a75d8fb4e8bb4fb309629698adba6f4fc2d6d7c22cede105a349fa0855115ab68571afa261fba6e26bf7b07bae4cf25be40984472bc1522163c778777066eccf6c", 256, "96946c9765d1a26ab024d317182a969be0763cd4ae4b54dad83f56f07fa95ed8fb00558eb87ab6fb97a75d8fb4e8bb4fb309629698adba6f4fc2d6d7c22cede105a349fa0855115ab68571afa261fba6e26bf7b07bae4cf25be40984472bc1522163c778777066eccf6c");
        test_case_unpad("000257f9271d4948c30dab8b8f6341651ea0be0a5ac9bdbb7eda413f79382fbd17e4e74f69dd0f34fea7ba587395316ffd225f016e4b7d492a0b9a00bc694779cb9b7ed0bd8796cea502502cba66095680246f7d052175e14dc5a224dfea3adde9e5c9330bb14b2c1fdb9ffdbd79e88fba69a1ba309150f71d8be28d4791841d6df8851c73456ee3ab56c5968d833f212a9c73ba090f3fb0717c927dc4de3e9c6648abe637081ccb9191c31967c8665724170a1d61578ad713f0705d0ef8526177be76d7d39b2d012c85abf725aa87562dcdef76173917875c87e3aacaa41912df190d9999d158e14b90f89220b0cee30f6d1459e3c64ae23d00ce1edd5105cf", 256, "bc694779cb9b7ed0bd8796cea502502cba66095680246f7d052175e14dc5a224dfea3adde9e5c9330bb14b2c1fdb9ffdbd79e88fba69a1ba309150f71d8be28d4791841d6df8851c73456ee3ab56c5968d833f212a9c73ba090f3fb0717c927dc4de3e9c6648abe637081ccb9191c31967c8665724170a1d61578ad713f0705d0ef8526177be76d7d39b2d012c85abf725aa87562dcdef76173917875c87e3aacaa41912df190d9999d158e14b90f89220b0cee30f6d1459e3c64ae23d00ce1edd5105cf");
        test_case_unpad("00024b3c130d04bf15baf3b672ccfb249f25055feec4d7f1a3c24674a8fe1e237a4d3298a7e40b39f80825d65f38a12d2906d98b321bbb4afd433cfca41fdb51d17571fd6b372d89349bdfe5ae134fc321cad86b23becc6d4f1b81897b09dd8722b90a5baf02018e59e56f7a202fb46ea7e04a89f38e20921f842fef22c13822faea410c60e24af568caf9005fb95586ca8e2061a130695bba0c44f1772f6ce8bc2fd0b80c9ce9c1a47f2f936e5a4c140fe696bedcacb8bcb1dfba69acf20cf6a02f5d174c2d3944093b112fa3e43c7b23210f2ed45aa750ef4e72ee3a1ae29f08cb1e6c27e23e4347216c1a43428d16d43934781594a5d33d703e1e4423fb0d", 256, "5fb95586ca8e2061a130695bba0c44f1772f6ce8bc2fd0b80c9ce9c1a47f2f936e5a4c140fe696bedcacb8bcb1dfba69acf20cf6a02f5d174c2d3944093b112fa3e43c7b23210f2ed45aa750ef4e72ee3a1ae29f08cb1e6c27e23e4347216c1a43428d16d43934781594a5d33d703e1e4423fb0d");
        test_case_unpad("000270d932d8fba6dae0bd639d2b0e1c4d9fb02ae7e7fd481dc4c4a67db00aae685602921e95ab71aa41cd18aec9d5db8876977f1262d6f184eeea73746ebb46f672ee97ea91acec785ff9715b41d15d443343bb08ae42f259c590b3bc23ad5844106b50b75193f43d2f304d641937b1a3591e8f4b42be01811b6b4e51ceabb4a06daf248820f6f2d40a98e79e4bb5817eb0459ed1bfcb77647a48e4cc98c7aa0017f25dafcb1187dda30f2a83d07f2f0334ceabd2f701b1c7a03698e545e286846ec02141c4098dda75c820a5eeddf75bd9d97726aa03a92172bb6809df460c6eee1564455b2360f77ab3ef81b784e91711261e34dd4e3d8041b7a54cd300be", 256, "17f25dafcb1187dda30f2a83d07f2f0334ceabd2f701b1c7a03698e545e286846ec02141c4098dda75c820a5eeddf75bd9d97726aa03a92172bb6809df460c6eee1564455b2360f77ab3ef81b784e91711261e34dd4e3d8041b7a54cd300be");
        test_case_unpad("0002849d3887e88fd17419a4d5203fa533b20c7c82f1b31673a3d709647b6f494e4f8fc544561545200c7ee12b92033df8226122c457e961f3d6cd697dca7255cbba28491fad0d537ae56c758ad0f900641cba33d66029d8edb85c7023da52505e57268531ad2d1e28eb5d65a5ef11104c183b042c50c0eacabf4b700e8c27e7d20195d4c545c1eaa806e76f6398877ada25b4bcd7bf048832a2f7bd0b9a6e0ca9b1992e8cee7aec5a6169f206a495bf6a7f90c63d9c6b38485c7583c5efdc68d09a01c22267f91879d3afc11292735113cfbb1ed6a323b0824ef2b41ff891a47216cf3194d96acf65882a00e70bb4be8a0d5e03c4306cae650772256736a822", 256, "641cba33d66029d8edb85c7023da52505e57268531ad2d1e28eb5d65a5ef11104c183b042c50c0eacabf4b700e8c27e7d20195d4c545c1eaa806e76f6398877ada25b4bcd7bf048832a2f7bd0b9a6e0ca9b1992e8cee7aec5a6169f206a495bf6a7f90c63d9c6b38485c7583c5efdc68d09a01c22267f91879d3afc11292735113cfbb1ed6a323b0824ef2b41ff891a47216cf3194d96acf65882a00e70bb4be8a0d5e03c4306cae650772256736a822");
    }

    fn test_case_pad(message: &str, k: usize) {
        let m = from_hex(message);
        let em = pad(m.as_slice(), k).unwrap();
        let dm = unpad(em.as_slice(), k).unwrap();
        assert_eq!(m, dm);
    }

    #[test]
    fn test_pad() {
        // since we know that unpad works correctly (see above test), we can simply call pad and unpad and check if it matches
        test_case_pad("5982b08411fca02e0f62b2dbd6bc65e52160a37a7921956715109a7d9f5e6b77db6af2a213857009aed62fca5fdfe17ef1f7997990a7ec6e5a12fabbca729e9ec87abe8e41161d56987e0d123f5f83e762037e23017ed1aa5e054f70ad18bed4d8b9c29be2159bc7e2114f72c1077d16a32084535dc7d07dfd86dad331e1d72cd62b855ae0031c53088281d99aa787d80708eb77087a842415c2537f2a82ed2a4abf00a821e13a045c679910854da305298c005669588b10f132417915f22de91c2a7e62f1e2344d6989e7521cfa19404f829478e6709f37413b5fc22f5d9934908ec3ed70944350ad", 256);
        test_case_pad("5fdd71fffd492cefa752b02eb4b4", 256);
        test_case_pad("75d4df02d862a42292b31a2ddc125604040b7da9decce9e965c9208b7aaa9d965d4f81a8df5773db12912ad2b2eb4f91bdd683af55fbb3db9b2840ca2fe24f9fc50d505c7ff9ef14c3b959ed0c51bd03c27abb1ca703678e36931820c8855f64baeef7ea619c4b20d07e9bc5f8ca75d45d05eae1d9b585c020f869827878e3b5bc893d81662445", 256);
        test_case_pad("913a42ce70f0c9c58e01fd7649318b028a070d05a036d7eac3e839edc877d920e243c95a6c32bdc46e7f154f70299179ac4ae40fe4c4ca0c50fdbbee82d34a91ec761db015c039fafdfa55415c4f7f3713269a90b5adb5975786b6e408bdd5f43f7e827fd9a5e3b2bbd5fd34cac7dfe3", 256);
        test_case_pad("d4f00c0cf9b004194029147f6202f1dcf168bc5c74799da769b9b301778b2439d1f9dd1ec0e03bd9f0c79e49e26dc6f7703c2dc5c203ae42e92f03a516e4be7a3a7989dd2592cc78df56a705984b3b00aded3ecebc44d4e9224fe649c9e06b4f672b63afc64b121119d29924005a27ed7150b4b48181864e7c7b3f1804ac4896a681c9e76687a989bb11d5b1d71d64af913c15841b19d27c40a7c7e3b1e00e74a1dd21e3ec478abd21de257fbc775a08ada12019c39bca50677ed519cf163404fe7c09bbd314e9e6ef4a84ef448b1ea878a0cca6a2d34a", 256);
    }

    #[test]
    #[should_panic(expected = "too large")]
    fn test_pad_error() {
        pad(from_hex(
            "4e219d225ac2f765f562c78ede33ef7a976cc3a4b95e169981118fbbe931be146fcf14abf349286f52abccbf5da4b06ea2153c67ae16ca66c9ad95c1e12b2e64540e2c5028cf2cf542ae947d6262ce322b097b1a76ef084fa4c7744264b6ca387f726da7e8da8b5a4e565bb55a4986ecdd496f60a368c48e5c36a1b3f9f09e3d32d8b0d7df32acd5fff6fd6e118227b2470956812381b7149ba50acfce62da568a2309e9ea11e674bda7a090a46bf6832f08f64ef42094dd7ced74158256596bacdc61f7f71c0b895dec17b3a14decbef68a6d5bb11b0007cfb665d7bcfa8094b16f76ed612097245b3dc7db8b834a675451bcda8a08f541a8b7dfdc"
        ).as_slice(), 256).unwrap();
    }

    #[test]
    #[should_panic(expected = "len(EM) != k")]
    fn test_unpad_len_missmatch() {
        unpad(
            from_hex("00023859ef1c21e0cb6ae0af7a501343cf0d21a780828290eabbe43f9a9dac6584c6c7382eec049dcc88daf493c87ee79de4c613af2a48af91463586acd75ae1d03fb95e6afe836c8f4d2c2607e8601db6d32c73e758cc51361fd35858ab856b6a8be3cc44d0bf0a9db387f2c17d8fdc434071a5ab6a91aec339ff7d66b998").as_slice(),
            128
        ).unwrap();
    }
}
