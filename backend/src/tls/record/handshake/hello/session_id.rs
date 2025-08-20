use crate::tls::record::variable_length_vec::VariableLengthVec;

pub type SessionID = VariableLengthVec<u8, 0, 32>;
