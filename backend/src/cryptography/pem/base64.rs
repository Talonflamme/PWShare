const CHARACTERS: [char; 64] = [
    'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S',
    'T', 'U', 'V', 'W', 'X', 'Y', 'Z', 'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l',
    'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z', '0', '1', '2', '3', '4',
    '5', '6', '7', '8', '9', '+', '/',
];
const PAD_CHAR: char = '=';

const fn ct_make_reverse_map() -> [Option<u8>; 128] {
    let mut map = [None; 128];

    let mut i = 0;
    while i < CHARACTERS.len() {
        let c = CHARACTERS[i];
        map[c as usize] = Some(i as u8);
        i += 1;
    }

    map
}

const REV_CHARACTERS: [Option<u8>; 128] = ct_make_reverse_map();

pub fn base64encode(bytes: &[u8]) -> String {
    let mut result = String::new();

    let iter = bytes.chunks_exact(3);
    let rem = iter.remainder();

    for chunk in iter {
        // bits 0..6
        result.push(CHARACTERS[(chunk[0] >> 2) as usize]);
        // bits 6..8 + 1..4
        result.push(CHARACTERS[(((chunk[0] & 0b11) << 4) | (chunk[1] >> 4)) as usize]);
        // bits 5..8 + 1..2
        result.push(CHARACTERS[(((chunk[1] & 0b1111) << 2) | (chunk[2] >> 6)) as usize]);
        // bits 3..8
        result.push(CHARACTERS[(chunk[2] & 0b111111) as usize]);
    }

    match rem.len() {
        1 => {
            result.push(CHARACTERS[(rem[0] >> 2) as usize]);
            result.push(CHARACTERS[((rem[0] & 0b11) << 4) as usize]);
            result.push(PAD_CHAR);
            result.push(PAD_CHAR);
        }
        2 => {
            result.push(CHARACTERS[(rem[0] >> 2) as usize]);
            result.push(CHARACTERS[(((rem[0] & 0b11) << 4) | (rem[1] >> 4)) as usize]);
            result.push(CHARACTERS[((rem[1] & 0b1111) << 2) as usize]);
            result.push(PAD_CHAR);
        }
        _ => {}
    }

    result
}

pub fn base64decode(string: String) -> Vec<u8> {
    let num_pads = string.chars().rev().take_while(|&c| c == PAD_CHAR).count();
    let chars: Vec<char> = string.chars().take(string.len() - num_pads).collect();

    let mut result = Vec::new();
    let chunks = chars.chunks(4);

    for chunk in chunks {
        let v0 = REV_CHARACTERS[chunk[0] as usize].unwrap();
        let v1 = chunk
            .get(1)
            .map_or(0, |&c| REV_CHARACTERS[c as usize].unwrap());
        let v2 = chunk
            .get(2)
            .map_or(0, |&c| REV_CHARACTERS[c as usize].unwrap());
        let v3 = chunk
            .get(3)
            .map_or(0, |&c| REV_CHARACTERS[c as usize].unwrap());

        let b1 = v0 << 2 | (v1 >> 4);
        let b2 = ((v1 & 0b1111) << 4) | (v2 >> 2);
        let b3 = ((v2 & 0b0011) << 6) | v3;

        result.push(b1);

        if chunk.len() == 4 || num_pads < 2 {
            // 2 pad chars? last two bytes are omitted
            result.push(b2);
        }
        if chunk.len() == 4 || num_pads < 1 {
            // at least one pad character? last byte is omitted
            result.push(b3);
        }
    }

    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_base64_encode() {
        assert_eq!(
            base64encode("Many hands make light work.".as_bytes()),
            "TWFueSBoYW5kcyBtYWtlIGxpZ2h0IHdvcmsu"
        );

        assert_eq!(base64encode("light work.".as_bytes()), "bGlnaHQgd29yay4=");
        assert_eq!(base64encode("light work".as_bytes()), "bGlnaHQgd29yaw==");
        assert_eq!(base64encode("light wor".as_bytes()), "bGlnaHQgd29y");
        assert_eq!(base64encode("abc".as_bytes()), "YWJj");

        assert_eq!(
            base64encode("The quick brown fox jumps over the lazy dog".as_bytes()),
            "VGhlIHF1aWNrIGJyb3duIGZveCBqdW1wcyBvdmVyIHRoZSBsYXp5IGRvZw=="
        );
    }

    #[test]
    fn test_base64_decode() {
        assert_eq!(base64decode("YWJjZGU=".into()), "abcde".as_bytes());
        assert_eq!(base64decode("d3hZeg==".into()), "wxYz".as_bytes());
        assert_eq!(base64decode("SGVsbG8gV29ybGQgMTIz".into()), "Hello World 123".as_bytes());
        assert_eq!(base64decode("QXktMDk=".into()), "Ay-09".as_bytes());
    }
}
