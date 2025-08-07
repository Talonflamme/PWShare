use crate::cryptography::aes::state::State;
use crate::cryptography::aes::AESKey;
use crate::cryptography::aes::{galois_mul, sbox};

#[derive(Copy, Clone)]
pub enum AES {
    AES128,
    AES192,
    AES256,
}

impl AES {
    pub const fn key_size_bits(&self) -> usize {
        match self {
            AES::AES128 => 128,
            AES::AES192 => 192,
            AES::AES256 => 256,
        }
    }

    pub const fn num_rounds(&self) -> usize {
        match self {
            AES::AES128 => 10,
            AES::AES192 => 12,
            AES::AES256 => 14,
        }
    }
}

pub(super) fn add_round_key(state: &mut State, round_key: u128) {
    let rk_bytes = round_key.to_be_bytes();

    for (a, k) in state.bytes.iter_mut().zip(rk_bytes) {
        *a = *a ^ k;
    }
}

/// Substitute each byte `b[i]` with the substitution of `SBOX[b[i]]`
pub(super) fn sub_bytes(state: &mut State) {
    for byte in state.bytes.iter_mut() {
        *byte = sbox::SBOX[*byte as usize];
    }
}

/// Substitute each byte `b[i]` with the substitution `INV_SBOX[b[i]]`
pub(super) fn inv_sub_bytes(state: &mut State) {
    for byte in state.bytes.iter_mut() {
        *byte = sbox::INV_SBOX[*byte as usize];
    }
}

/// Shift the second row by an offset of 1 to the left.
/// The third and fourth row are offset by 2 and 3 to the left.
pub(super) fn shift_rows(state: &mut State) {
    // first row is left unchanged
    state.left_shift_row(1, 1);
    state.left_shift_row(2, 2);
    state.left_shift_row(3, 3);
}

/// Shifts  the second row by an offset of 1 to the right. The third and fourth row are offset
/// by 2 and 3 respectively.
pub(super) fn inv_shift_rows(state: &mut State) {
    // first row is left unchanged
    state.left_shift_row(1, -1);
    state.left_shift_row(2, -2);
    state.left_shift_row(3, -3);
}

pub(super) fn mix_column(column: &mut [u8; 4]) {
    let mut a = [0u8; 4]; // copy of column
    let mut b = [0u8; 4]; // each element of `a` multiplied by 2 in GF(2)
                          // a[n] ^ b[n] = element n multiplied by 3 in GF(2)

    for i in 0..4 {
        a[i] = column[i];
        b[i] = galois_mul::mul2[a[i] as usize];
    }

    column[0] = b[0] ^ a[3] ^ a[2] ^ b[1] ^ a[1]; // 2 * a0 + a3 + a2 + 3 * a1
    column[1] = b[1] ^ a[0] ^ a[3] ^ b[2] ^ a[2]; // 2 * a1 + a0 + a3 + 3 * a2
    column[2] = b[2] ^ a[1] ^ a[0] ^ b[3] ^ a[3]; // 2 * a2 + a1 + a0 + 3 * a3
    column[3] = b[3] ^ a[2] ^ a[1] ^ b[0] ^ a[0]; // 2 * a3 + a2 + a1 + 3 * a0
}

pub(super) fn inv_mix_column(column: &mut [u8; 4]) {
    let mut buffer: [u8; 4] = [0; 4];

    // b0 = 14*d0 + 11*d1 + 13*d2 + 9*d3
    buffer[0] = galois_mul::mul14[column[0] as usize]
        ^ galois_mul::mul11[column[1] as usize]
        ^ galois_mul::mul13[column[2] as usize]
        ^ galois_mul::mul9[column[3] as usize];

    // b1 = 9*d0 + 14*d1 + 11*d2 + 13*d3
    buffer[1] = galois_mul::mul9[column[0] as usize]
        ^ galois_mul::mul14[column[1] as usize]
        ^ galois_mul::mul11[column[2] as usize]
        ^ galois_mul::mul13[column[3] as usize];

    // b2 = 13*d0 + 9*d1 + 14*d2 + 11*d3
    buffer[2] = galois_mul::mul13[column[0] as usize]
        ^ galois_mul::mul9[column[1] as usize]
        ^ galois_mul::mul14[column[2] as usize]
        ^ galois_mul::mul11[column[3] as usize];

    // b3 = 11*d0 + 13*d1 + 9*d2 + 14*d3
    buffer[3] = galois_mul::mul11[column[0] as usize]
        ^ galois_mul::mul13[column[1] as usize]
        ^ galois_mul::mul9[column[2] as usize]
        ^ galois_mul::mul14[column[3] as usize];

    *column = buffer;
}

fn mix_columns(state: &mut State) {
    let columns = state.columns();
    for column in columns {
        mix_column(column);
    }
}

fn inv_mix_columns(state: &mut State) {
    let columns = state.columns();
    for column in columns {
        inv_mix_column(column);
    }
}

/// Encrypts the message (128 bits) using the key.
pub fn aes_encrypt<K: AESKey>(plain_message: u128, key: K) -> u128 {
    // 1. Key Expansion
    let round_keys = key.generate_round_keys();

    let mut state = State::new(plain_message);

    // 2. Initial round key addition
    add_round_key(&mut state, round_keys[0]);

    // 3. Rounds
    for i in 1..K::R {
        sub_bytes(&mut state);
        shift_rows(&mut state);

        // in the last round, mix_columns is skipped
        if i != K::VARIANT.num_rounds() {
            mix_columns(&mut state);
        }

        add_round_key(&mut state, round_keys[i]);
    }

    state.into()
}

pub fn aes_decrypt<K: AESKey>(cipher_message: u128, key: K) -> u128 {
    // 1. Key Expansion
    let round_keys = key.generate_round_keys();

    let mut state = State::new(cipher_message);

    // 2. Rounds
    for i in (1..K::R).rev() {
        add_round_key(&mut state, round_keys[i]);

        if i != K::VARIANT.num_rounds() {
            inv_mix_columns(&mut state);
        }

        inv_shift_rows(&mut state);
        inv_sub_bytes(&mut state);
    }

    // 3. Initial round key addition
    add_round_key(&mut state, round_keys[0]);

    state.into()
}
