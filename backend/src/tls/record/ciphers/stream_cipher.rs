use crate::tls::connection_state::connection_state::ConnectionState;
use crate::tls::record::ciphers::cipher::TLSCipher;
use crate::tls::record::cryptographic_attributes::StreamCiphered;
use crate::tls::record::fragmentation::tls_ciphertext::{
    CipherType, GenericStreamCipher, TLSCiphertext,
};
use crate::tls::record::fragmentation::tls_compressed::TLSCompressed;
use crate::tls::record::variable_length_vec::VariableLengthVec;
use std::fmt::Debug;
use std::io::{Error, ErrorKind};

#[derive(Debug)]
pub struct TLSNullCipher;

impl TLSNullCipher {
    fn encrypt_struct(
        &self,
        fragment: GenericStreamCipher,
    ) -> std::io::Result<StreamCiphered<GenericStreamCipher>> {
        // no encryption
        Ok(StreamCiphered::new(fragment.to_bytes()))
    }

    fn decrypt_struct(
        &self,
        fragment: StreamCiphered<GenericStreamCipher>,
        con_state: &ConnectionState,
    ) -> std::io::Result<GenericStreamCipher> {
        GenericStreamCipher::read(fragment.bytes, con_state)
    }
}

impl TLSCipher for TLSNullCipher {
    fn encrypt(
        &self,
        plaintext: TLSCompressed,
        con_state: &ConnectionState,
    ) -> std::io::Result<TLSCiphertext> {
        let mac = plaintext.generate_mac(con_state)?;

        let generic_stream_cipher = GenericStreamCipher {
            content: plaintext.fragment.into(),
            mac,
        };

        Ok(TLSCiphertext {
            content_type: plaintext.content_type,
            version: plaintext.version,
            fragment: CipherType::Stream(self.encrypt_struct(generic_stream_cipher)?),
        })
    }

    fn decrypt(
        &self,
        ciphertext: TLSCiphertext,
        con_state: &ConnectionState,
    ) -> std::io::Result<TLSCompressed> {
        let frag =
            match ciphertext.fragment {
                CipherType::Stream(s) => s,
                _ => return Err(Error::new(
                    ErrorKind::InvalidInput,
                    "Called TLSStreamCipher.decrypt on something that is not StreamCipherEncrypted",
                )),
            };

        let generic_stream_cipher = self.decrypt_struct(frag, con_state)?;
        let mac = generic_stream_cipher.mac.clone();
        let fragment: VariableLengthVec<u8, 0, 17408> = generic_stream_cipher.to_bytes().into();

        fragment.check_bounds()?;

        let compressed: TLSCompressed = TLSCompressed {
            content_type: ciphertext.content_type,
            version: ciphertext.version,
            fragment,
        };

        let generated_mac = compressed.generate_mac(con_state)?;

        if generated_mac == mac {
            Ok(compressed)
        } else {
            Err(Error::new(ErrorKind::Other, "MAC mismatch"))
        }
    }
}
