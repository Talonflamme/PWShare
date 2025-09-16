use crate::cryptography::hashing::HashFunction;

/// Applies the mgf1 algorithm over `hash`. The `seed` is transformed and the result
/// will have a length of `length` bytes.
pub fn mgf1(
    hash: &impl HashFunction,
    seed: &[u8],
    length: usize,
) -> Vec<u8> {
    let h_len = hash.h_len();

    assert!((length >> 32) <= h_len, "mask too long");

    let mut t = vec![];

    let mut counter: u32 = 0;

    while t.len() < length {
        let c = counter.to_be_bytes();

        let concat_z_c = [seed, &c].concat();
        let mut hashed = hash.hash(concat_z_c.as_slice()).to_vec();

        t.append(&mut hashed);
        counter += 1;
    }

    t.truncate(length);

    t
}
