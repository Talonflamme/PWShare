use std::io::Result;

macro_rules! unexpected_eof {
    () => {
        std::io::Error::new(std::io::ErrorKind::UnexpectedEof, "Unexpected EOF")
    };
    ($msg: expr) => {
        std::io::Error::new(std::io::ErrorKind::UnexpectedEof, $msg)
    };
    ($format: expr, $($arg:tt)*) => {
        std::io::Error::new(std::io::ErrorKind::UnexpectedEof, format!($format, $($arg)*))
    };
}

/// The type can be constructed from a stream of bytes.
pub trait ReadableFromStream: Sized {
    /// Produce a value of `Self` by consuming any number of bytes from `stream`.
    /// Returns a `Result` holding the constructed value or an error describing
    /// why an `Ok` could not be returned.
    fn read(stream: &mut impl Iterator<Item = u8>) -> Result<Self>;
}

impl ReadableFromStream for u8 {
    fn read(stream: &mut impl Iterator<Item = u8>) -> Result<Self> {
        stream.next().ok_or(unexpected_eof!())
    }
}

impl ReadableFromStream for u16 {
    fn read(stream: &mut impl Iterator<Item = u8>) -> Result<Self> {
        let b0 = stream.next().ok_or(unexpected_eof!())? as u16;
        let b1 = stream.next().ok_or(unexpected_eof!())? as u16;

        Ok((b0 << 8) | b1)
    }
}

impl ReadableFromStream for u32 {
    fn read(stream: &mut impl Iterator<Item = u8>) -> Result<Self> {
        let b0 = stream.next().ok_or(unexpected_eof!())? as u32;
        let b1 = stream.next().ok_or(unexpected_eof!())? as u32;
        let b2 = stream.next().ok_or(unexpected_eof!())? as u32;
        let b3 = stream.next().ok_or(unexpected_eof!())? as u32;

        Ok((b0 << 24) | (b1 << 16) | (b2 << 8) | b3)
    }
}

impl<T, const N: usize> ReadableFromStream for [T; N]
where
    T: ReadableFromStream,
{
    fn read(stream: &mut impl Iterator<Item = u8>) -> Result<Self> {
        let mut vec = Vec::with_capacity(N);
        for _ in 0..N {
            vec.push(T::read(stream)?);
        }
        let arr: [T; N] = vec.try_into().map_err(|_| unexpected_eof!())?;
        Ok(arr)
    }
}

pub(crate) use unexpected_eof;
