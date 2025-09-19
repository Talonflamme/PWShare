use crate::tls::connection_state::security_parameters::{ConnectionEnd, SecurityParameters};
use crate::tls::record::ciphers::cipher::TLSCipher;
use crate::tls::record::ciphers::TLSNullCipher;
use std::io::{Error, ErrorKind, Result};

#[derive(Debug)]
pub struct ConnectionState {
    pub parameters: SecurityParameters,
    // compression state
    // cipher state
    // MAC key
    /// Must be set to 0 when this connection state becomes the active state. Increments
    /// after each record is sent. The first record sent under this connection must
    /// use sequence number 0.
    pub sequence_number: u64,
    pub cipher: Box<dyn TLSCipher>,

    enc_key: Vec<u8>,
    iv: Vec<u8>,
    mac_key: Vec<u8>,
}

macro_rules! require_entity {
    ($self: expr, $field: expr, Client) => {
        if let Some(entity) = $self.parameters.entity {
            match entity {
                ConnectionEnd::Server => Err(Error::new(ErrorKind::Other, "Not client end")),
                ConnectionEnd::Client => Ok($field),
            }
        } else {
            Err(Error::new(ErrorKind::Other, "No entity specified"))
        }
    };

    ($self: expr, $field: expr, Server) => {
        if let Some(entity) = $self.parameters.entity {
            match entity {
                ConnectionEnd::Server => Ok($field),
                ConnectionEnd::Client => Err(Error::new(ErrorKind::Other, "Not server end")),
            }
        } else {
            Err(Error::new(ErrorKind::Other, "No entity specified"))
        }
    };
}

impl ConnectionState {
    pub fn create_no_encryption(entity: ConnectionEnd) -> Self {
        Self {
            parameters: SecurityParameters::new_no_encryption(entity),
            sequence_number: 0,
            cipher: Box::new(TLSNullCipher {}),
            enc_key: Vec::new(),
            iv: Vec::new(),
            mac_key: Vec::new(),
        }
    }

    pub fn get_client_write_key(&self) -> Result<&Vec<u8>> {
        require_entity!(self, &self.enc_key, Client)
    }

    pub fn get_server_write_key(&self) -> Result<&Vec<u8>> {
        require_entity!(self, &self.enc_key, Server)
    }

    pub fn get_client_write_mac_key(&self) -> Result<&Vec<u8>> {
        require_entity!(self, &self.mac_key, Client)
    }

    pub fn get_server_write_mac_key(&self) -> Result<&Vec<u8>> {
        require_entity!(self, &self.mac_key, Server)
    }

    pub fn get_client_write_iv(&self) -> Result<&Vec<u8>> {
        require_entity!(self, &self.iv, Client)
    }

    pub fn get_server_write_iv(&self) -> Result<&Vec<u8>> {
        require_entity!(self, &self.iv, Server)
    }
}
