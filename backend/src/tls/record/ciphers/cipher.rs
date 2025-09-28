use crate::tls::connection_state::connection_state::ConnectionState;
use crate::tls::record::alert::Result;
use crate::tls::record::fragmentation::tls_ciphertext::TLSCiphertext;
use crate::tls::record::fragmentation::tls_compressed::TLSCompressed;
use std::fmt::Debug;

pub trait TLSCipher: Debug {
    fn encrypt(
        &self,
        plaintext: TLSCompressed,
        con_state: &ConnectionState,
    ) -> Result<TLSCiphertext>;
    fn decrypt(
        &self,
        ciphertext: TLSCiphertext,
        con_state: &ConnectionState,
    ) -> Result<TLSCompressed>;
}

