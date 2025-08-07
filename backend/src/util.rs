use std::time::{Duration, SystemTime};

use crypto_bigint::{NonZero, Uint, Zero};

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

    fn bin(&self) -> String {
        self.radix(2).unwrap()
    }

    fn radix(&self, radix: u32) -> Result<String, UintToRadixError>;
}

impl<const L: usize> UintDisplay for Uint<L> {
    fn radix(&self, radix: u32) -> Result<String, UintToRadixError> {
        let mut clone = self.clone();

        let non_zero = NonZero::new(Uint::<L>::from(radix)).unwrap();
        let mut string = String::new();

        while (!clone.is_zero()).into() {
            let (div, rem) = clone.div_rem(&non_zero);
            clone = div;
            let remainder = rem.as_words()[0] as u32;

            let ch = char::from_digit(remainder, radix).ok_or(UintToRadixError {})?;
            string.push(ch);
        }

        // rev string
        Ok(string.chars().rev().collect())
    }
}

impl<const L: usize> UintDisplay for Vec<Uint<L>> {
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
    fn dec(&self) -> String {
        self.as_slice().dec()
    }

    fn hex(&self) -> String {
        self.as_slice().hex()
    }

    fn bin(&self) -> String {
        self.as_slice().bin()
    }

    fn radix(&self, radix: u32) -> Result<String, UintToRadixError> {
        self.as_slice().radix(radix)
    }
}
