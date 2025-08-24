pub type CipherSuite = [u8; 2];

// initial, must not be used as it does not protect any data
pub const TLS_NULL_WITH_NULL_NULL: CipherSuite = [0x00, 0x00];

// Server must provide RSA certificate that can be used for key exchange
pub const TLS_RSA_WITH_NULL_MD5: CipherSuite = [0x00, 0x01];
pub const TLS_RSA_WITH_NULL_SHA: CipherSuite = [0x00, 0x02];
pub const TLS_RSA_WITH_NULL_SHA256: CipherSuite = [0x00, 0x3B];
pub const TLS_RSA_WITH_RC4_128_MD5: CipherSuite = [0x00, 0x04];
pub const TLS_RSA_WITH_RC4_128_SHA: CipherSuite = [0x00, 0x05];
pub const TLS_RSA_WITH_3DES_EDE_CBC_SHA: CipherSuite = [0x00, 0x0A];
pub const TLS_RSA_WITH_AES_128_CBC_SHA: CipherSuite = [0x00, 0x2f];
pub const TLS_RSA_WITH_AES_128_CBC_SHA256: CipherSuite = [0x00, 0x3c];
pub const TLS_RSA_WITH_AES_256_CBC_SHA256: CipherSuite = [0x00, 0x3d];

// Server-authenticated Diffie-Hellman
pub const TLS_DH_DSS_WITH_3DES_EDE_CBC_SHA: CipherSuite = [0x00, 0x0D];
pub const TLS_DH_RSA_WITH_3DES_EDE_CBC_SHA: CipherSuite = [0x00, 0x10];
pub const TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA: CipherSuite = [0x00, 0x13];
pub const TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA: CipherSuite = [0x00, 0x16];
pub const TLS_DH_DSS_WITH_AES_128_CBC_SHA: CipherSuite = [0x00, 0x30];
pub const TLS_DH_RSA_WITH_AES_128_CBC_SHA: CipherSuite = [0x00, 0x31];
pub const TLS_DHE_DSS_WITH_AES_128_CBC_SHA: CipherSuite = [0x00, 0x32];
pub const TLS_DHE_RSA_WITH_AES_128_CBC_SHA: CipherSuite = [0x00, 0x33];
pub const TLS_DH_DSS_WITH_AES_256_CBC_SHA: CipherSuite = [0x00, 0x36];
pub const TLS_DH_RSA_WITH_AES_256_CBC_SHA: CipherSuite = [0x00, 0x37];
pub const TLS_DHE_DSS_WITH_AES_256_CBC_SHA: CipherSuite = [0x00, 0x38];
pub const TLS_DHE_RSA_WITH_AES_256_CBC_SHA: CipherSuite = [0x00, 0x39];
pub const TLS_DH_DSS_WITH_AES_128_CBC_SHA256: CipherSuite = [0x00, 0x3E];
pub const TLS_DH_RSA_WITH_AES_128_CBC_SHA256: CipherSuite = [0x00, 0x3F];
pub const TLS_DHE_DSS_WITH_AES_128_CBC_SHA256: CipherSuite = [0x00, 0x40];
pub const TLS_DHE_RSA_WITH_AES_128_CBC_SHA256: CipherSuite = [0x00, 0x67];
pub const TLS_DH_DSS_WITH_AES_256_CBC_SHA256: CipherSuite = [0x00, 0x68];
pub const TLS_DH_RSA_WITH_AES_256_CBC_SHA256: CipherSuite = [0x00, 0x69];
pub const TLS_DHE_DSS_WITH_AES_256_CBC_SHA256: CipherSuite = [0x00, 0x6A];
pub const TLS_DHE_RSA_WITH_AES_256_CBC_SHA256: CipherSuite = [0x00, 0x6B];

// Anonymous Diffie-Hellman, must not be used unless explicitly requested by application layer
pub const TLS_DH_ANON_WITH_RC4_128_MD5: CipherSuite = [0x00, 0x18];
pub const TLS_DH_ANON_WITH_3DES_EDE_CBC_SHA: CipherSuite = [0x00, 0x1B];
pub const TLS_DH_ANON_WITH_AES_128_CBC_SHA: CipherSuite = [0x00, 0x34];
pub const TLS_DH_ANON_WITH_AES_256_CBC_SHA: CipherSuite = [0x00, 0x3A];
pub const TLS_DH_ANON_WITH_AES_128_CBC_SHA256: CipherSuite = [0x00, 0x6C];
pub const TLS_DH_ANON_WITH_AES_256_CBC_SHA256: CipherSuite = [0x00, 0x6D];
