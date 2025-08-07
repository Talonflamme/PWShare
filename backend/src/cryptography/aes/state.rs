/// The state stores 16 bytes (128-bit) into a 4x4 column-major order matrix
pub struct State {
    pub bytes: [u8; 16],
}

impl State {
    pub fn new(block: u128) -> Self {
        Self {
            bytes: block.to_be_bytes(),
        }
    }

    pub fn columns(&mut self) -> &mut [[u8; 4]] {
        self.bytes.as_chunks_mut::<4>().0
    }

    /// Shits the `row_index` th row by `n`.
    pub fn left_shift_row(&mut self, row_index: usize, n: i32) {
        let mut buffer = [0u8; 4];

        for i in 0..4 {
            buffer[i] = self.bytes[4 * i + row_index];
        }

        let n = (((n % 4) + 4) % 4) as usize; // ensure positive mod 4 n

        for i in 0..4 {
            self.bytes[4 * i + row_index] = buffer[(i + n) % 4];
        }
    }
}

impl Into<u128> for State {
    fn into(self) -> u128 {
        u128::from_be_bytes(self.bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_new() {
        let block: u128 = 0x000102030405060708090a0b0c0d0e0f;
        let state = State::new(block);
        assert_eq!(state.bytes, block.to_be_bytes());
    }

    #[test]
    fn test_columns() {
        let block: u128 = 0x000102030405060708090a0b0c0d0e0f;
        let mut state = State::new(block);
        let columns = state.columns();

        let expected: &[[u8; 4]] = &[
            [0x0, 0x1, 0x2, 0x3],
            [0x4, 0x5, 0x6, 0x7],
            [0x8, 0x9, 0xa, 0xb],
            [0xc, 0xd, 0xe, 0xf],
        ];

        assert_eq!(columns, expected);
    }

    #[test]
    fn test_left_shift_row() {
        let mut state = State::new(0x000102030405060708090a0b0c0d0e0f);
        // 00 04 08 0c
        // 01 05 09 0d
        // 02 06 0a 0e
        // 03 07 0b 0f

        state.left_shift_row(0, 0);
        state.left_shift_row(1, 1);
        state.left_shift_row(2, 2);
        state.left_shift_row(3, 3);

        // 00 04 08 0c
        // 05 09 0d 01
        // 0a 0e 02 06
        // 0f 03 07 0b

        let actual = u128::from_be_bytes(state.bytes);

        assert_eq!(actual, 0x00050a0f04090e03080d02070c01060b);

        state.left_shift_row(1, 5);
        state.left_shift_row(2, -1);
        state.left_shift_row(3, -3);

        // 00 04 08 0c
        // 09 0d 01 05
        // 06 0a 0e 02
        // 03 07 0b 0f

        let actual = u128::from_be_bytes(state.bytes);
        assert_eq!(actual, 0x00090603040d0a0708010e0b0c05020f);

        state.left_shift_row(1, 2);
        state.left_shift_row(2, -1);

        let actual: u128 = state.into();

        assert_eq!(actual, 0x000102030405060708090a0b0c0d0e0f);
    }
}
