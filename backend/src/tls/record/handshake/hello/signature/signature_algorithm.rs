use pwshare_macros::ReadableFromStream;

#[repr(u8)]
#[derive(ReadableFromStream, Clone, Copy, Debug)]
pub enum SignatureAlgorithm {
    Anonymous = 0,
    RSA = 1,
    DSA = 2,
    ECDSA = 3
}
