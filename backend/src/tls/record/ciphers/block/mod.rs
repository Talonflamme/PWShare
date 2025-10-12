pub mod aes_cbc;

use crate::cryptography::rng::rng;
use crate::tls::connection_state::connection_state::ConnectionState;
use crate::tls::record::alert::{Alert, Result};
use crate::tls::record::ciphers::cipher::TLSCipher;
use crate::tls::record::cryptographic_attributes::BlockCiphered;
use crate::tls::record::fragmentation::tls_ciphertext::{
    CipherType, GenericBlockCipher, GenericBlockCipherInner, TLSCiphertext,
};
use crate::tls::record::fragmentation::tls_compressed::TLSCompressed;
use crate::tls::record::variable_length_vec::VariableLengthVec;
use rand::RngCore;
use std::fmt::Debug;

pub(super) trait TLSBlockCipher: Debug + TLSCipher {
    fn encrypt_struct(
        &self,
        fragment: GenericBlockCipherInner,
        iv: &[u8],
    ) -> Result<BlockCiphered<GenericBlockCipherInner>>;
    fn decrypt_struct(
        &self,
        fragment: BlockCiphered<GenericBlockCipherInner>,
        con_state: &ConnectionState,
        iv: &[u8],
    ) -> Result<DecryptStructResult>;
}

/// We use a different struct as this result in order to prevent a timing attack based on
/// invalid padding. This way, even when the padding is incorrect, operations like computing
/// the MAC is still performed to have constant time. In that case, `padding_error` will be Some.
pub(super) struct DecryptStructResult {
    inner: GenericBlockCipherInner,
    /// `Some` if the padding was incorrect, `None` otherwise.
    padding_error: Option<Alert>,
}

pub(super) fn block_encrypt(
    cipher: &impl TLSBlockCipher,
    plaintext: TLSCompressed,
    con_state: &ConnectionState,
) -> Result<TLSCiphertext> {
    let mac = plaintext.generate_mac(con_state)?;

    let record_iv_len = *con_state.parameters.record_iv_length()? as usize;
    let mac_length = *con_state.parameters.mac_length()? as usize;
    let block_size = *con_state.parameters.block_length()? as usize;

    let mut iv = vec![0; record_iv_len];
    rng!().fill_bytes(iv.as_mut_slice());

    // TLSCiphertext.length = 1 + block_length + TLSCompressed.length + mac_length + padding_length
    // This length must be a multiple of block_length
    let length_without_padding = plaintext.fragment.len() + mac_length + 1;
    let padding_length = (block_size - (length_without_padding % block_size)) as u8;
    let padding = vec![padding_length; padding_length as usize];

    let inner = GenericBlockCipherInner {
        content: plaintext.fragment.into(),
        mac,
        padding,
        padding_length,
    };

    let generic_block_cipher = GenericBlockCipher {
        inner: cipher.encrypt_struct(inner, &iv)?,
        iv,
    };

    Ok(TLSCiphertext {
        content_type: plaintext.content_type,
        version: plaintext.version,
        fragment: CipherType::Block(generic_block_cipher),
    })
}

pub(super) fn block_decrypt(
    cipher: &impl TLSBlockCipher,
    ciphertext: TLSCiphertext,
    con_state: &ConnectionState,
) -> Result<TLSCompressed> {
    let fragment = if let CipherType::Block(gcb) = ciphertext.fragment {
        gcb
    } else {
        return Err(Alert::internal_error(
            "TLSBlockCipher.decrypt called on something other than GenericBlockCipher",
        ));
    };

    // even when padding is invalid, we still compute the mac and do all other
    // operations to prevent a timing attack
    let DecryptStructResult {
        inner,
        padding_error,
    } = cipher.decrypt_struct(fragment.inner, con_state, &fragment.iv)?;

    let mac = inner.mac;

    let fragment_bytes: VariableLengthVec<u8, 0, 17408> = inner.content.into();
    fragment_bytes.check_bounds()?;

    let tls_compressed = TLSCompressed {
        content_type: ciphertext.content_type,
        version: ciphertext.version,
        fragment: fragment_bytes,
    };

    let calculated_mac = tls_compressed.generate_mac(con_state)?;

    if let Some(padding_error) = padding_error {
        Err(padding_error)
    } else if mac == calculated_mac {
        Ok(tls_compressed)
    } else {
        Err(Alert::bad_record_mac())
    }
}
