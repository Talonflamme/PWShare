mod public_key_encrypted;

use std::marker::PhantomData;
pub use public_key_encrypted::PublicKeyEncrypted;

macro_rules! impl_ciphered {
    ($typ: ident) => {
        pub struct $typ <T> {
            pub bytes: Vec<u8>,
            _marker: PhantomData<T>
        }

        impl<T> $typ <T> {
            pub fn new(bytes: Vec<u8>) -> Self {
                Self { bytes, _marker: PhantomData }
            }
        }
    }
}

impl_ciphered!(BlockCiphered);
impl_ciphered!(StreamCiphered);
impl_ciphered!(AeadCiphered);
