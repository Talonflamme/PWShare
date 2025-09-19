use crate::tls::record::readable_from_stream::{unexpected_eof, ReadableFromStream};
use crate::tls::{Sink, WritableToSink};
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

impl<T, const MIN: usize, const MAX: usize> Into<Vec<T>> for VariableLengthVec<T, MIN, MAX> {
    fn into(self) -> Vec<T> {
        self.0
    }
}

impl<T, const MIN: usize, const MAX: usize> ReadableFromStream for VariableLengthVec<T, MIN, MAX>
where
    T: ReadableFromStream,
{
    fn read(stream: &mut impl Iterator<Item = u8>) -> std::io::Result<Self> {
        let amount_bytes_for_len = (MAX as f64).log(256.0).ceil() as usize;

        let mut buf = [0; size_of::<usize>()];

        for i in 0..amount_bytes_for_len {
            // big-endian, but at the end of the buffer
            buf[size_of::<usize>() - amount_bytes_for_len + i] =
                stream.next().ok_or(unexpected_eof!())?;
        }

        let length_in_bytes = usize::from_be_bytes(buf);

        if length_in_bytes < MIN || length_in_bytes > MAX {
            return Err(Error::new(
                ErrorKind::InvalidData,
                format!(
                    "Length {} is outside of permitted range: {}..={}",
                    length_in_bytes, MIN, MAX
                ),
            ));
        }

        // we can't really know beforehand, how many elements to allocate, because some
        // values of T, such as VariableLenVec, have more dynamic sizes, where the amount
        // of elements cannot be calculated
        let mut res = Vec::new();

        let mut take = stream.take(length_in_bytes).peekable();

        while take.peek().is_some() {
            res.push(T::read(&mut take)?);
        }

        Ok(VariableLengthVec(res))
    }
}

impl<T, const MIN: usize, const MAX: usize> WritableToSink for VariableLengthVec<T, MIN, MAX>
where
    T: WritableToSink,
{
    fn write(&self, buffer: &mut impl Sink<u8>) -> std::io::Result<()> {
        let amount_bytes_for_len = (MAX as f64).log(256.0).ceil() as usize;

        // we use a separate Vec<u8> here, because we need to verify that the length is in bounds
        // before sending.
        // Even though can't say for sure that this capacity is enough, it will be a good
        // estimate and will only ever be too little, not too large.
        let mut content_buf: Vec<u8> = Vec::with_capacity(self.len() * size_of::<T>());

        for el in self.iter() {
            el.write(&mut content_buf)?;
        }

        let length = content_buf.len();

        if length < MIN || length > MAX {
            Err(Error::new(
                ErrorKind::InvalidData,
                format!(
                    "Length {} is outside of permitted range: {}..={}",
                    content_buf.len(),
                    MIN,
                    MAX
                ),
            ))
        } else {
            let length = &length.to_be_bytes()[size_of::<usize>() - amount_bytes_for_len..];

            buffer.extend_from_slice(length);
            buffer.extend(content_buf.into_iter());
            Ok(())
        }
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

impl<T, const MIN: usize, const MAX: usize> From<Vec<T>> for VariableLengthVec<T, MIN, MAX> {
    fn from(value: Vec<T>) -> Self {
        Self(value)
    }
}

impl<T, const MAX: usize> VariableLengthVec<T, 0, MAX> {
    /// Creates an empty `VariableLengthVec<T>`. This function is only available when
    /// `MIN` is 0.
    pub fn new_empty() -> Self {
        VariableLengthVec(Vec::new())
    }
}

impl<const MIN: usize, const MAX: usize> VariableLengthVec<u8, MIN, MAX> {
    pub fn check_bounds(&self) -> std::io::Result<()> {
        if self.len() < MIN || self.len() > MAX {
            Err(Error::new(
                ErrorKind::InvalidData,
                format!("Length: {} out of bounds ({}..{})", self.len(), MIN, MAX),
            ))
        } else {
            Ok(())
        }
    }

    pub fn try_into<const NEW_MIN: usize, const NEW_MAX: usize>(self) -> Result<VariableLengthVec<u8, NEW_MIN, NEW_MAX>, ()> {
        if self.len() < NEW_MIN || self.len() > NEW_MAX {
            Err(())
        } else {
            Ok(VariableLengthVec(self.0))
        }
    }
}
