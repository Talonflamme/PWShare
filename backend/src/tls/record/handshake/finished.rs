use crate::tls::connection_state::connection_state::ConnectionState;
use crate::tls::connection_state::security_parameters::ConnectionEnd;
use crate::tls::record::alert::{Alert, Result};
use crate::util::UintDisplay;
use pwshare_macros::{ReadableFromStream, WritableToSink};
use std::fmt::{Debug, Formatter};

const VERIFY_DATA_LENGTH: usize = 12;

#[derive(ReadableFromStream, WritableToSink)]
pub struct Finished {
    verify_data: [u8; VERIFY_DATA_LENGTH],
}

impl Debug for Finished {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "Finished {{ verify_data: {} }}",
            (&self.verify_data[..]).hex()
        )
    }
}

impl Finished {
    pub fn new(verify_data: [u8; VERIFY_DATA_LENGTH]) -> Self {
        Self { verify_data }
    }

    pub fn calculate_verify_data(
        con_state: &ConnectionState,
        handshake_messages: &[u8],
    ) -> Result<[u8; VERIFY_DATA_LENGTH]> {
        let prf = con_state.parameters.prf_algorithm()?;
        let master_secret = con_state.parameters.master_secret()?;
        let entity = *con_state.parameters.entity()?;

        let finished_label = if entity == ConnectionEnd::Client {
            "client finished"
        } else {
            "server finished"
        };

        let hash_func = prf.get_hash();
        let hash = hash_func.hash(handshake_messages);

        let data: [u8; VERIFY_DATA_LENGTH] = prf
            .prf(master_secret, finished_label, hash.as_slice())
            .take(VERIFY_DATA_LENGTH)
            .collect::<Vec<_>>()
            .try_into()
            .unwrap();

        Ok(data)
    }

    /// Computed the `verify_data` field and checks if it matches to `self.verify_data`. If it
    /// does, `Ok(())` is returned. An `Err` is returned otherwise.
    pub fn verify(&self, con_state: &ConnectionState, handshake_messages: &[u8]) -> Result<()> {
        let data = Self::calculate_verify_data(con_state, handshake_messages)?;

        if self.verify_data == data {
            Ok(())
        } else {
            Err(Alert::decrypt_error()) // failed to verify
        }
    }
}
