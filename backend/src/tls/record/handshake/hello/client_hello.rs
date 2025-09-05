use crate::tls::connection_state::security_parameters::CompressionMethod;
use crate::tls::record::cipher_suite::CipherSuite;
use crate::tls::record::extensions::Extension;
use crate::tls::record::handshake::hello::SessionID;
use crate::tls::record::protocol_version::ProtocolVersion;
use crate::tls::record::variable_length_vec::VariableLengthVec;
use crate::tls::record::Random;
use pwshare_macros::{ReadableFromStream, WritableToSink};

#[derive(Debug, ReadableFromStream, WritableToSink)]
/// https://www.rfc-editor.org/rfc/rfc5246#section-7.4.1.2
pub struct ClientHello {
    pub client_version: ProtocolVersion,
    pub random: Random,
    pub session_id: SessionID,
    pub cipher_suites: VariableLengthVec<CipherSuite, 2, 65534>, // 2^16-2
    pub compression_methods: VariableLengthVec<CompressionMethod, 1, 255>, // 2^8-1
    pub extensions: VariableLengthVec<Extension, 0, 65535>,      // 2^16 - 1
}
