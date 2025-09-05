use crate::tls::connection_state::security_parameters::CompressionMethod;
use crate::tls::record::cipher_suite::CipherSuite;
use crate::tls::record::hello::extensions::Extension;
use crate::tls::record::handshake::hello::SessionID;
use crate::tls::record::protocol_version::ProtocolVersion;
use crate::tls::record::variable_length_vec::VariableLengthVec;
use crate::tls::record::Random;
use pwshare_macros::{ReadableFromStream, WritableToSink};

#[derive(Debug, ReadableFromStream, WritableToSink)]
pub struct ServerHello {
    pub server_version: ProtocolVersion,
    pub random: Random,
    pub session_id: SessionID,
    pub cipher_suite: CipherSuite,
    pub compression_method: CompressionMethod,
    pub extensions: VariableLengthVec<Extension, 0, 65335>
}
