use crate::tls::record::hello::extensions::renegotiation_info::RenegotiationInfoExtension;
use crate::tls::record::variable_length_vec::VariableLengthVec;
use crate::tls::WritableToSink;
use pwshare_macros::{IntoRepr, ReadableFromStream, WritableToSink};
use std::fmt::{Debug, Formatter};

#[repr(u16)]
#[derive(Debug, IntoRepr, ReadableFromStream, WritableToSink)]
#[fallback(Unknown)]
pub enum ExtensionType {
    RenegotiationInfo(OpaqueExtensionData<RenegotiationInfoExtension>) = 65281,
    Unknown(OpaqueExtensionData<u8>) = 65535,
}

impl ExtensionType {
    pub fn new_renegotiation_info(rie: RenegotiationInfoExtension) -> Self {
        ExtensionType::RenegotiationInfo(vec![rie].into())
    }
}

#[derive(ReadableFromStream, WritableToSink)]
pub struct Extension {
    pub extension_type: ExtensionType,
}

/// Struct used to indicate that there is data after this, but it is not interpreted (e.g. because
/// it's not yet implemented).
pub type OpaqueExtensionData<T> = VariableLengthVec<T, 0, 65535>;

impl Debug for Extension {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "Extension {:?}({})",
            self.extension_type,
            Into::<u16>::into(&self.extension_type)
        )
    }
}

/// Returns a list of extensions that are supported and are present in `client_extensions`.
///
/// `client_extensions`: The list of extensions from the `ClientHello` message.
pub fn filter_extensions(client_extensions: &Vec<Extension>) -> Vec<Extension> {
    Vec::new()
}
