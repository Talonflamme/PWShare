use crate::tls::record::variable_length_vec::VariableLengthVec;
use crate::tls::{ReadableFromStream, Sink, WritableToSink};
use std::any::type_name;
use std::io::{Error, ErrorKind, Result};
use std::marker::PhantomData;

#[derive(Debug)]
pub struct PublicKeyEncrypted<T>
where
    T: ReadableFromStream,
{
    bytes: VariableLengthVec<u8, 0, 65535>,
    _marker: PhantomData<T>,
}

impl<T> WritableToSink for PublicKeyEncrypted<T>
where
    T: ReadableFromStream,
{
    fn write(&self, buffer: &mut impl Sink<u8>) -> Result<()> {
        self.bytes.write(buffer)
    }
}

impl<T> ReadableFromStream for PublicKeyEncrypted<T>
where T: ReadableFromStream {
    fn read(stream: &mut impl Iterator<Item=u8>) -> Result<Self> {
        Ok(Self {
            bytes: VariableLengthVec::read(stream)?,
            _marker: PhantomData,
        })
    }
}

impl<T> PublicKeyEncrypted<T>
where
    T: ReadableFromStream,
{
    pub fn decrypt<F>(self, decrypt_func: F) -> Result<T>
    where
        F: FnOnce(Vec<u8>) -> Vec<u8>,
    {
        let decrypted_bytes = decrypt_func(self.bytes.into());
        let mut iter = decrypted_bytes.into_iter();

        let t = T::read(&mut iter)?;

        if iter.next().is_some() {
            Err(Error::new(
                ErrorKind::InvalidData,
                format!(
                    "Did not use up all bytes when decrypting to {}",
                    type_name::<T>()
                ),
            ))
        } else {
            Ok(t)
        }
    }
}
