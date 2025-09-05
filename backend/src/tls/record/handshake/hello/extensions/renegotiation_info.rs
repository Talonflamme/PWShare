use pwshare_macros::{ReadableFromStream, WritableToSink};
use crate::tls::record::variable_length_vec::VariableLengthVec;

#[derive(Debug, ReadableFromStream, WritableToSink)]
pub struct RenegotiationInfoExtension {
    pub renegotiated_connection: VariableLengthVec<u8, 0, 255>
}