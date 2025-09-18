use crate::tls::connection_state::security_parameters::{ConnectionEnd, SecurityParameters};

#[derive(Clone, Copy)]
pub struct ConnectionState {
    pub parameters: SecurityParameters,
    // compression state
    // cipher state
    // MAC key
    /// Must be set to 0 when this connection state becomes the active state. Increments
    /// after each record is sent. The first record sent under this connection must
    /// use sequence number 0.
    sequence_number: u64
}

impl ConnectionState {
    pub fn create_no_encryption(entity: ConnectionEnd) -> Self {
        Self {
            parameters: SecurityParameters::new(entity),
            sequence_number: 0
        }
    }
}
