use crate::tls::record::alert::Result;

pub trait Sink<T> {
    fn push(&mut self, byte: T);
    fn extend_from_slice(&mut self, src: &[T]);
    fn extend(&mut self, iter: impl IntoIterator<Item=T>);
    fn append(&mut self, vec: Vec<T>);
}

impl Sink<u8> for Vec<u8> {
    fn push(&mut self, byte: u8) {
        self.push(byte)
    }

    fn extend_from_slice(&mut self, src: &[u8]) {
        self.extend_from_slice(src)
    }

    fn extend(&mut self, iter: impl IntoIterator<Item=u8>) {
        Extend::extend(self, iter)
    }

    fn append(&mut self, mut vec: Vec<u8>) {
        self.append(&mut vec)
    }
}

/// The type can be written to a buffer.
pub trait WritableToSink: Sized {
    /// Write this struct to a given buffer. Return `Ok(())` if the data was written
    /// to the buffer. Returns an `Err` if something with the data was wrong.
    fn write(&self, buffer: &mut impl Sink<u8>) -> Result<()>;
}

impl WritableToSink for u8 {
    fn write(&self, buffer: &mut impl Sink<u8>) -> Result<()> {
        buffer.push(self.clone());
        Ok(())
    }
}

impl WritableToSink for u16 {
    fn write(&self, buffer: &mut impl Sink<u8>) -> Result<()> {
        buffer.extend_from_slice(&self.to_be_bytes());
        Ok(())
    }
}

impl WritableToSink for u32 {
    fn write(&self, buffer: &mut impl Sink<u8>) -> Result<()> {
        buffer.extend_from_slice(&self.to_be_bytes());
        Ok(())
    }
}

impl<T, const N: usize> WritableToSink for [T; N] where T: WritableToSink {
    fn write(&self, buffer: &mut impl Sink<u8>) -> Result<()> {
        for e in self {
            e.write(buffer)?;
        }

        Ok(())
    }
}
