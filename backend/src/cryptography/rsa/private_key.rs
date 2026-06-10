use crate::cryptography::rsa::RSAPublicKey;
use crypto_bigint::{BoxedUint, Encoding, Odd, One};
use std::fmt::{Debug, Display};

#[derive(Debug)]
pub struct RSAPrivateKey {
    pub n: Odd<BoxedUint>,
    pub d: BoxedUint,
    pub e: BoxedUint,
    pub p: Odd<BoxedUint>,
    pub q: Odd<BoxedUint>,
    /// d mod (p - 1)
    pub d_mod_p_minus_1: BoxedUint,
    /// d mod (p - 1)
    pub d_mod_q_minus_1: BoxedUint,
    pub inverse_q_mod_p: BoxedUint,
}

#[derive(Debug)]
pub struct DecryptError {
    reason: &'static str,
}

impl RSAPrivateKey {
    pub fn new_detailed(
        n: Odd<BoxedUint>,
        d: BoxedUint,
        e: BoxedUint,
        p: Odd<BoxedUint>,
        q: Odd<BoxedUint>,
        d_mod_p_minus_1: BoxedUint,
        d_mod_q_minus_1: BoxedUint,
        inverse_q_mod_p: BoxedUint,
    ) -> Self {
        Self {
            n,
            d,
            e,
            p,
            q,
            d_mod_p_minus_1,
            d_mod_q_minus_1,
            inverse_q_mod_p,
        }
    }

    pub fn new(
        n: Odd<BoxedUint>,
        d: BoxedUint,
        e: BoxedUint,
        p: Odd<BoxedUint>,
        q: Odd<BoxedUint>,
    ) -> Self {
        let p_minus_1 = p.as_ref() - BoxedUint::one_like(&p);
        let q_minus_1 = q.as_ref() - BoxedUint::one_like(&q);

        let exp1 = &d % p_minus_1.into_nz().unwrap();
        let exp2 = &d % q_minus_1.into_nz().unwrap();

        let inv = q.invert_mod(&p.as_nz_ref()).unwrap();

        Self::new_detailed(n, d, e, p, q, exp1, exp2, inv)
    }

    /// Computes `M^d (mod n)` and returns the result or an error if `M` was outside of
    /// range.
    ///
    /// See [RFC 8017 Section 5.1.2](https://datatracker.ietf.org/doc/html/rfc8017#section-5.1.2)
    /// for the exact algorithm.
    pub fn decrypt(&self, message_cipher: BoxedUint) -> Result<BoxedUint, DecryptError> {
        if self.n.as_ref() <= &message_cipher {
            Err(DecryptError {
                reason: "ciphertext representative out of range",
            })
        } else {
            // use Chinese Remainder Theorem (CRT) to save some computation
            let m_p = message_cipher.pow_mod(&self.d_mod_p_minus_1, &self.p);
            let m_q = message_cipher.pow_mod(&self.d_mod_q_minus_1, &self.q);

            let diff = m_p.sub_mod(&m_q, self.p.as_nz_ref());
            let h = diff.mul_mod(&self.inverse_q_mod_p, self.p.as_nz_ref());

            let m = m_q + h * self.q.as_ref();
            Ok(m)
        }
    }

    pub fn decrypt_bytes(&self, ciphertext: &[u8]) -> Result<Vec<u8>, DecryptError> {
        if ciphertext.len() != self.size_in_bytes() {
            return Err(DecryptError {
                reason: "len(C) != len(N)",
            });
        }

        let uint = BoxedUint::from_be_bytes(ciphertext.into());
        let plain = self.decrypt(uint)?;
        Ok(plain.to_be_bytes().into())
    }

    pub fn public(&self) -> RSAPublicKey {
        RSAPublicKey {
            n: self.n.clone(),
            e: self.e.clone(),
        }
    }

    /// The size of the RSA modulus `n` in bytes.
    pub fn size_in_bytes(&self) -> usize {
        self.n.bits().div_ceil(8) as usize
    }
}

impl Display for RSAPrivateKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "({}, {})", self.n, self.d)
    }
}

impl PartialEq for RSAPrivateKey {
    fn eq(&self, other: &Self) -> bool {
        self.n == other.n && self.d == other.d
    }
}

impl Eq for RSAPrivateKey {}
