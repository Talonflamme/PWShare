use pwshare_macros::{ReadableFromStream, WritableToSink};
use crate::tls::record::handshake::certificate::asn1cert::ASN1Cert;
use crate::tls::record::variable_length_vec::VariableLengthVec;

#[derive(WritableToSink, ReadableFromStream, Debug)]
pub struct Certificate {
    /// Chain of certificates. The first one is the sender's certificate. After that,
    /// each certificate verifies the one before it.
    pub certificate_list: VariableLengthVec<ASN1Cert, 0, 16777215>  // 2^24 - 1
}
