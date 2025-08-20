use crate::tls::record::cipher_suite::CipherSuite;
use crate::tls::record::compression_method::CompressionMethod;
use crate::tls::record::handshake::extension::Extension;
use crate::tls::record::protocol_version::ProtocolVersion;
use crate::tls::record::variable_length_vec::VariableLengthVec;
use crate::tls::record::{Random, SessionID};
use pwshare_macros::ReadableFromStream;

#[derive(Debug, ReadableFromStream)]
/// https://www.rfc-editor.org/rfc/rfc5246#section-7.4.1.2
pub struct ClientHello {
    client_version: ProtocolVersion,
    random: Random,
    session_id: SessionID,
    cipher_suites: VariableLengthVec<CipherSuite, 2, 65534>, // 2^16-2
    compression_methods: VariableLengthVec<CompressionMethod, 1, 255>, // 2^8-1
    extensions: VariableLengthVec<Extension, 0, 65535>,      // 2^16 - 1
}
