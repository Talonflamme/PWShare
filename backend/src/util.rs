use num_bigint::BigUint;
use std::time::{Duration, SystemTime};

pub fn time<T, F: Fn() -> T>(f: F) -> (Duration, T) {
    let start = SystemTime::now();
    let t = f();
    let end = SystemTime::now();
    (end.duration_since(start).unwrap(), t)
}

pub fn print_time<T, F: Fn() -> T>(f: F) -> T {
    let (d, t) = time(f);
    println!("Time elapsed: {d:?}");
    t
}

#[derive(Debug)]
pub struct UintToRadixError;

pub trait UintDisplay {
    fn dec(&self) -> String {
        self.radix(10).unwrap()
    }

    fn hex(&self) -> String {
        self.radix(16).unwrap()
    }

    fn hex_with_sep(&self, sep: &str) -> String;

    fn bin(&self) -> String {
        self.radix(2).unwrap()
    }

    fn radix(&self, radix: u32) -> Result<String, UintToRadixError>;
}

impl UintDisplay for BigUint {
    fn hex_with_sep(&self, _: &str) -> String {
        self.hex()
    }

    fn radix(&self, radix: u32) -> Result<String, UintToRadixError> {
        Ok(self.to_str_radix(radix))
    }
}

impl UintDisplay for Vec<BigUint> {
    fn hex_with_sep(&self, sep: &str) -> String {
        self.iter()
            .map(|uint| uint.hex())
            .collect::<Vec<_>>()
            .join(sep)
    }

    fn radix(&self, radix: u32) -> Result<String, UintToRadixError> {
        let mut strings = Vec::new();

        for u in self.iter() {
            strings.push(u.radix(radix)?);
        }

        Ok(format!("{:?}", strings))
    }
}

impl UintDisplay for &[u8] {
    fn hex(&self) -> String {
        self.iter().map(|b| format!("{:02x}", b)).collect()
    }

    fn hex_with_sep(&self, sep: &str) -> String {
        self.iter()
            .map(|b| format!("{:02x}", b))
            .collect::<Vec<_>>()
            .join(sep)
    }

    fn bin(&self) -> String {
        self.iter().map(|b| format!("{:08b}", b)).collect()
    }

    fn radix(&self, radix: u32) -> Result<String, UintToRadixError> {
        let mut result = String::new();

        for &byte in self.iter() {
            let mut b = byte;
            let mut byte_str = String::new();

            if b == 0 {
                byte_str.push('0');
            }

            while b > 0 {
                let rem = (b as u32) % radix;
                b = (b as u32 / radix) as u8;

                let ch = char::from_digit(rem, radix).ok_or(UintToRadixError {})?;
                byte_str.push(ch);
            }

            byte_str = byte_str.chars().rev().collect();
            result.push_str(byte_str.as_str());
        }

        Ok(result)
    }
}

impl UintDisplay for Vec<u8> {
    fn hex(&self) -> String {
        self.as_slice().hex()
    }

    fn hex_with_sep(&self, sep: &str) -> String {
        self.as_slice().hex_with_sep(sep)
    }

    fn radix(&self, radix: u32) -> Result<String, UintToRadixError> {
        self.as_slice().radix(radix)
    }
}
