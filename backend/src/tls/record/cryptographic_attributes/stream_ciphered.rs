use std::marker::PhantomData;

pub struct StreamCiphered<T> {
    pub bytes: Vec<u8>,
    _marker: PhantomData<T>,
}

impl<T> StreamCiphered<T> {
    pub fn new(bytes: Vec<u8>) -> Self {
        Self {
            bytes,
            _marker: PhantomData,
        }
    }
}
