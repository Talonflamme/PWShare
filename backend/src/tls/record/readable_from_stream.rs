use crate::tls::record::alert::{Alert, Result};
use crate::tls::record::ciphers::cipher_suite::CipherConfig;

/// The type can be constructed from a stream of bytes.
pub trait ReadableFromStream: Sized {
    /// Produce a value of `Self` by consuming any number of bytes from `stream`.
    /// Returns a `Result` holding the constructed value or an error describing
    /// why an `Ok` could not be returned. If a `CipherSuite` was already chosen,
    /// the `suite` parameter will be `Some(chosen_suite)`. This will be `None`
    /// otherwise.
    fn read(stream: &mut impl Iterator<Item = u8>, suite: Option<&CipherConfig>) -> Result<Self>;
}

impl ReadableFromStream for u8 {
    fn read(stream: &mut impl Iterator<Item = u8>, _: Option<&CipherConfig>) -> Result<Self> {
        stream.next().ok_or_else(Alert::decode_error)
    }
}

impl ReadableFromStream for u16 {
    fn read(stream: &mut impl Iterator<Item = u8>, _: Option<&CipherConfig>) -> Result<Self> {
        let b0 = stream.next().ok_or_else(Alert::decode_error)? as u16;
        let b1 = stream.next().ok_or_else(Alert::decode_error)? as u16;

        Ok((b0 << 8) | b1)
    }
}

impl ReadableFromStream for u32 {
    fn read(stream: &mut impl Iterator<Item = u8>, _: Option<&CipherConfig>) -> Result<Self> {
        let b0 = stream.next().ok_or_else(Alert::decode_error)? as u32;
        let b1 = stream.next().ok_or_else(Alert::decode_error)? as u32;
        let b2 = stream.next().ok_or_else(Alert::decode_error)? as u32;
        let b3 = stream.next().ok_or_else(Alert::decode_error)? as u32;

        Ok((b0 << 24) | (b1 << 16) | (b2 << 8) | b3)
    }
}

impl<T, const N: usize> ReadableFromStream for [T; N]
where
    T: ReadableFromStream,
{
    fn read(stream: &mut impl Iterator<Item = u8>, suite: Option<&CipherConfig>) -> Result<Self> {
        let mut vec = Vec::with_capacity(N);
        for _ in 0..N {
            vec.push(T::read(stream, suite)?);
        }
        let arr: [T; N] = vec.try_into().map_err(|_| Alert::decode_error())?;
        Ok(arr)
    }
}
