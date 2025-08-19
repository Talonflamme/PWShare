use crate::tls::record::readable_from_stream::{unexpected_eof, ReadableFromStream};
use std::fmt::{Debug, Formatter};
use std::io::{Error, ErrorKind};
use std::ops::{Deref, DerefMut};

/// A wrapper type for `Vec<T>`, that can be parsed using `ReadableFromStream`.
///
/// `T`: Any type that will be held inside the inner vector.
/// `MIN`: The minimum length of the field in bytes.
/// `MAX`: The maximum length of the field in bytes.
///
/// For TLS, the length precedes the vector's contents in the byte stream. The length will
/// be a big-endian number of enough bytes to represent `MAX`.
///
/// E.g: `MIN=0`, `MAX=255` => 1 byte for length.
/// E.g: `MIN=10`, MAX=`900` => 2 bytes for length.
///
/// Note: `MIN` and `MAX` are the length in bytes. This means, the number of elements
/// that can be held the inner `Vec<T>` is calculated by `MAX / sizeof(T)`.
pub struct VariableLengthVec<T, const MIN: usize, const MAX: usize>(Vec<T>);

impl<T, const MIN: usize, const MAX: usize> Deref for VariableLengthVec<T, MIN, MAX> {
    type Target = Vec<T>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<T, const MIN: usize, const MAX: usize> DerefMut for VariableLengthVec<T, MIN, MAX> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl<T, const MIN: usize, const MAX: usize> ReadableFromStream for VariableLengthVec<T, MIN, MAX>
where
    T: ReadableFromStream,
{
    fn read(stream: &mut impl Iterator<Item = u8>) -> std::io::Result<Self> {
        let length_bytes = (MAX as f64).log(256.0).ceil() as usize;

        let mut buf = [0; size_of::<usize>()];

        for i in 0..length_bytes {
            // big-endian, but at the end of the buffer
            buf[size_of::<usize>() - length_bytes + i] = stream.next().ok_or(unexpected_eof!())?;
        }

        let length_bytes = usize::from_be_bytes(buf);

        if length_bytes < MIN || length_bytes > MAX {
            return Err(Error::new(
                ErrorKind::InvalidData,
                format!(
                    "Length {} is oustide of permitted range: {}..={}",
                    length_bytes, MIN, MAX
                ),
            ));
        }

        if length_bytes % size_of::<T>() != 0 {
            return Err(Error::new(
                ErrorKind::InvalidData,
                format!(
                    "Length {} (bytes) is not divisible by {} bytes (size of {})",
                    length_bytes,
                    size_of::<T>(),
                    std::any::type_name::<T>()
                ),
            ));
        }

        let length_elements = length_bytes / size_of::<T>();
        let mut res = Vec::with_capacity(length_elements);

        for _ in 0..length_elements {
            res.push(T::read(stream)?);
        }

        Ok(VariableLengthVec(res))
    }
}

impl<T, const MIN: usize, const MAX: usize> Debug for VariableLengthVec<T, MIN, MAX>
where
    T: Debug,
{
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(f)
    }
}
