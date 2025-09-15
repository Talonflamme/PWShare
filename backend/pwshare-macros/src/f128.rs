use std::fmt::{Debug, Formatter};
use std::ops::{Add, Div};

const MANTISSA_BITS: usize = 112;
const MANTISSA_MASK: u128 = (1 << MANTISSA_BITS) - 1;

const EXP_BITS: usize = 15;
const EXP_SHIFT: usize = MANTISSA_BITS;
const EXP_MASK: u128 = ((1 << EXP_BITS) - 1) << EXP_SHIFT;
const EXP_BIAS: i32 = (1 << (EXP_BITS - 1)) - 1;

#[derive(Clone, Copy)]
pub struct Mantissa {
    bits: u128,
}

impl Mantissa {
    pub fn with_leading_1(self) -> u128 {
        self.bits | (1 << MANTISSA_BITS)
    }

    pub fn without_leading_1(self) -> u128 {
        self.bits
    }

    fn from_bits(bits: u128) -> Self {
        Self {
            bits: bits & MANTISSA_MASK,
        }
    }
}

fn multiply_u128(a: u128, b: u128) -> (u128, u128) {
    const MASK: u128 = (1 << 64) - 1; // 64 bits 1

    let a_hi = a >> 64;
    let a_lo = a & MASK;
    let b_hi = b >> 64;
    let b_lo = b & MASK;

    let lo_lo = a_lo * b_lo;
    let hi_lo = a_hi * b_lo;
    let lo_hi = a_lo * b_hi;
    let hi_hi = a_hi * b_hi;

    let mid = (lo_lo >> 64) + (hi_lo & MASK) + (lo_hi & MASK);
    let lo = (lo_lo & MASK) | (mid << 64);
    let hi = hi_hi + (hi_lo >> 64) + (lo_hi >> 64) + (mid >> 64);

    (hi, lo)
}

fn divide_mantissa(mut a: u128, b: u128) -> u128 {
    let mut q = 0;

    for _ in 0..113 {
        q <<= 1;
        if a >= b {
            a -= b;
            q |= 1;
        }
        a <<= 1;
    }

    q
}

#[derive(Copy, Clone)]
pub struct F128 {
    // sign is positive
    pub exp: i32,           // 15 bit
    pub mantissa: Mantissa, // 112 bit
}

const THREE: F128 = F128 {
    exp: 1,
    mantissa: Mantissa { bits: 1 << 111 },
};

impl F128 {
    pub fn to_bits(self) -> u128 {
        self.into()
    }

    pub fn from_bits(bits: u128) -> Self {
        bits.into()
    }

    pub fn multiply_with_2(self) -> Self {
        let mut exp = self.exp;

        exp += 1;
        if exp > 0x7ffe {
            // 0x7fff is reserved for infinity
            panic!("Overflow");
        }

        Self {
            exp,
            mantissa: self.mantissa,
        }
    }

    pub fn square(self) -> Self {
        let mut exp = self.exp * 2;

        let mantissa = self.mantissa.with_leading_1();
        let (hi, lo) = multiply_u128(mantissa, mantissa); // result is u226, since we multiply
        // two 113-bit numbers
        let new_mantissa_bits: u128;

        // if bit 225 is set, that means the mantissa is no longer normalized, we need to increase
        // the exponent
        if hi & (1 << 97) != 0 {
            exp += 1;
            // right shift mantissa by 1
            new_mantissa_bits = (hi << 30 >> 15) | (lo >> 113);
        } else {
            // since the result is 226 bits, we use the lowest 98 bits of the high word
            // and the highest 14 of the lower word
            new_mantissa_bits = (hi << 30 >> 14) | (lo >> 112);
        }

        assert_ne!(new_mantissa_bits & (1 << 112), 0); // this is the leading bit, must be 1

        Self {
            exp,
            mantissa: Mantissa::from_bits(new_mantissa_bits),
        }
    }

    fn cbrt_newton_iteration(y: F128, x: F128) -> F128 {
        // if it was a float, we could do:
        // y = (2.0 * y + x / (y * y)) / 3.0

        (y.multiply_with_2() + (x / y.square())) / THREE
    }

    pub fn cbrt(self) -> Self {
        const K: u128 = 0x1555 << 113;

        let y = self.to_bits() / 3 + K;

        let mut y = Self::from_bits(y);

        y = Self::cbrt_newton_iteration(y, self);
        y = Self::cbrt_newton_iteration(y, self);
        y = Self::cbrt_newton_iteration(y, self);
        y = Self::cbrt_newton_iteration(y, self);
        y = Self::cbrt_newton_iteration(y, self);

        y
    }

    pub fn set_integer_part_to_one(self) -> Self {
        Self {
            exp: 0,
            mantissa: Mantissa::from_bits(self.mantissa.without_leading_1() << self.exp),
        }
    }
}

impl From<u128> for F128 {
    fn from(bits: u128) -> Self {
        let exponent = ((bits & EXP_MASK) >> EXP_SHIFT) as i32 - EXP_BIAS;
        let mantissa = bits & MANTISSA_MASK;

        Self {
            exp: exponent,
            mantissa: Mantissa::from_bits(mantissa),
        }
    }
}

impl From<f64> for F128 {
    fn from(value: f64) -> Self {
        let bits = value.to_bits() as u128;

        let exponent = (((bits >> 52) & 0x7ff) as i32) - 1023;
        let mantissa = (bits & 0xfffffffffffff) << 60;

        Self {
            exp: exponent,
            mantissa: Mantissa::from_bits(mantissa),
        }
    }
}

impl Into<u128> for F128 {
    fn into(self) -> u128 {
        let exp = ((self.exp + EXP_BIAS) as u128) << EXP_SHIFT;
        let mantissa = self.mantissa.without_leading_1();

        exp | mantissa
    }
}

impl Into<f64> for F128 {
    fn into(self) -> f64 {
        let exp = self.exp;
        let mantissa = self.mantissa;

        if exp < -1024 || exp > 1023 {
            panic!("exponent out of range");
        }

        let new_exp = ((exp + 1023) as u64) << 52;
        let new_mantissa = (mantissa.without_leading_1() >> (MANTISSA_BITS - 52)) as u64;

        f64::from_bits(new_exp | new_mantissa)
    }
}

impl Add for F128 {
    type Output = Self;

    fn add(self, rhs: Self) -> Self::Output {
        let mut m_a = self.mantissa.with_leading_1(); // 113 bit
        let mut m_b = rhs.mantissa.with_leading_1(); // 113 bit

        let mut new_exp: i32;

        if self.exp > rhs.exp {
            m_b >>= self.exp - rhs.exp;
            new_exp = self.exp;
        } else {
            m_a >>= rhs.exp - self.exp;
            new_exp = rhs.exp;
        }

        let mut new_mantissa = m_a + m_b; // 113 bit + 113 bit = max. 114 bit

        if new_mantissa & (1 << 113) != 0 {
            // leading bit is 1, there was overflow
            // we increase exponent
            new_exp += 1;
            new_mantissa >>= 1;
        }

        assert_ne!(new_mantissa & (1 << 112), 0); // This is the leading 1

        Self {
            exp: new_exp,
            mantissa: Mantissa::from_bits(new_mantissa),
        }
    }
}

impl Div for F128 {
    type Output = Self;

    fn div(self, rhs: Self) -> Self::Output {
        let mantissa_a = self.mantissa.with_leading_1();
        let mantissa_b = rhs.mantissa.with_leading_1();

        let mut new_exp = self.exp - rhs.exp;
        let mut new_mantissa = divide_mantissa(mantissa_a, mantissa_b);

        if new_mantissa & (1 << 112) == 0 {
            // top bit not set, result is < 1, we need to normalize
            new_mantissa <<= 1;
            new_exp -= 1;
        }

        // remove implicit
        assert_ne!(new_mantissa & (1 << 112), 0);

        Self {
            exp: new_exp,
            mantissa: Mantissa::from_bits(new_mantissa),
        }
    }
}

impl Debug for F128 {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        let bits = self.to_bits();

        let sign = bits >> 127; // always 0
        let exp = (bits & EXP_MASK) >> EXP_SHIFT;
        let mantissa = bits & MANTISSA_MASK;

        const RED: &str = "\x1b[31m";
        const BLUE: &str = "\x1b[34m";
        const GREEN: &str = "\x1b[32m";
        const CLEAR: &str = "\x1b[0m";

        write!(
            f,
            "{RED}{:b}{BLUE}{:0>e$b}{GREEN}{:0>m$b}{CLEAR}",
            sign,
            exp,
            mantissa,
            e = EXP_BITS,
            m = MANTISSA_BITS
        )
    }
}
