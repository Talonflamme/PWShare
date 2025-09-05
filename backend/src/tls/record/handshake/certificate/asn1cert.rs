use crate::cryptography::pem::base64::base64decode;
use crate::cryptography::pem::find_content_between_header;
use crate::tls::record::variable_length_vec::VariableLengthVec;
use pwshare_macros::{ReadableFromStream, WritableToSink};
use std::fs;
use std::io::{Error, ErrorKind, Result};
use std::path::Path;

#[derive(WritableToSink, ReadableFromStream, Debug)]
pub struct ASN1Cert {
    pub bytes: VariableLengthVec<u8, 0, 16777215>,
}

impl ASN1Cert {
    pub fn from_file(path: impl AsRef<Path>) -> Result<Self> {
        let file_content = fs::read_to_string(path)?;

        let base64content = find_content_between_header(
            file_content,
            "-----BEGIN CERTIFICATE-----",
            "-----END CERTIFICATE-----",
        )
        .ok_or(Error::new(ErrorKind::InvalidData, "No certificate found"))?;

        let bytes = base64decode(base64content);

        Ok(ASN1Cert {
            bytes: bytes.into(),
        })
    }
}
