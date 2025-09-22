use std::marker::PhantomData;

pub struct BlockCiphered<T> {
    pub bytes: Vec<u8>,
    _marker: PhantomData<T>,
}

impl<T> BlockCiphered<T> {
    pub fn new(bytes: Vec<u8>) -> Self {
        Self {
            bytes,
            _marker: PhantomData,
        }
    }
}
