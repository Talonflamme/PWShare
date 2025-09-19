use crate::tls::connection_state::connection_state::ConnectionState;
use crate::tls::record::fragmentation::tls_ciphertext::{CipherType, GenericStreamCipher, TLSCiphertext};
use crate::tls::record::fragmentation::tls_compressed::TLSCompressed;
use std::io::{Result, Error, ErrorKind};

pub trait TLSCipher {
    fn encrypt(&self, plaintext: TLSCompressed, con_state: &ConnectionState) -> Result<TLSCiphertext>;
    fn decrypt(&self, ciphertext: TLSCiphertext, cons_state: &ConnectionState) -> Result<TLSCompressed>;
}

pub struct TLSNullCipher;

impl TLSCipher for TLSNullCipher {
    fn encrypt(&self, plaintext: TLSCompressed, con_state: &ConnectionState) -> Result<TLSCiphertext> {
        let mac = plaintext.generate_mac(con_state)?;

        Ok(TLSCiphertext {
            content_type: plaintext.content_type,
            version: plaintext.version,
            fragment: CipherType::Stream(GenericStreamCipher {
                content: plaintext.fragment.into(), // identity function
                mac, // identity function
            }),
        })
    }

    fn decrypt(&self, ciphertext: TLSCiphertext, con_state: &ConnectionState) -> Result<TLSCompressed> {
        todo!()
    }
}
