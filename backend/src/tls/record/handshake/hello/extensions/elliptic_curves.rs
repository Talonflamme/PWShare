use crate::tls::record::key_exchange::ecdhe::elliptic_curve::NamedCurve;
use crate::tls::record::variable_length_vec::VariableLengthVec;
use pwshare_macros::{ReadableFromStream, WritableToSink};

pub type NamedCurveList = VariableLengthVec<NamedCurve, 2, 65535>;

#[repr(u8)]
#[derive(Debug, ReadableFromStream, WritableToSink)]
#[fallback(UnknownOrDeprecated)]
pub enum ECPointFormat {
    Uncompressed = 0,
    UnknownOrDeprecated,
}

pub type ECPointFormatList = VariableLengthVec<ECPointFormat, 1, 255>;
