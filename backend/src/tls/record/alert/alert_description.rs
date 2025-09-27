use pwshare_macros::{ReadableFromStream, WritableToSink};

/// Description of an Alert layer of TLS.
/// More info: https://www.rfc-editor.org/rfc/rfc5246.html#section-7.2.2
#[repr(u8)]
#[derive(ReadableFromStream, WritableToSink)]
pub enum AlertDescription {
    /// Signals that the connection will be terminated. Both parties are required to send
    /// this before closing the connection. Upon receiving this, a CloseNotify must be sent.
    /// The sender is not required to wait for a response to close the connection.
    CloseNotify = 0,
    /// An inappropriate message was received.
    /// This alert is always fatal.
    UnexpectedMessage = 10,
    /// This alert is returned if a record is received with an incorrect MAC. This message
    /// should also be sent when a TLSCiphertext is decrypted in an invalid way: either not
    /// a multiple of block_length or padding values incorrect.
    /// This alert is always fatal.
    BadRecordMac = 20,
    /// Earlier version, *MUST NOT* be sent.
    #[deprecated(note = "Only used in an earlier version. MUST NOT be sent.")]
    DecryptionFailedReserved = 21,
    /// A TLSCiphertext record was received that had a length more than `2^14+2048` bytes or a
    /// TLSCompressed record with more than `2^14+1024` bytes.
    /// This message is always fatal.
    RecordOverflow = 22,
    /// The decompression function received improper input.
    /// This message is always fatal.
    DecompressionFailure = 30,
    /// This message indicates that no acceptable security parameters were agreed upon.
    /// This message is always fatal.
    HandshakeFailure = 40,
    /// Earlier version, *MUST NOT* be sent.
    #[deprecated(note = "Only used in an earlier version. MUST NOT be sent.")]
    NoCertificateReserved = 41,
    /// A certificate was corrupt, contained signatures that did not verify correctly, etc.
    BadCertificate = 42,
    /// A certificate was of an unsupported type.
    UnsupportedCertificate = 43,
    /// A certificate was revoked by its signer.
    CertificateRevoked = 44,
    /// A certificate has expired or is not currently valid.
    CertificateExpired = 45,
    /// Some other (unspecified) issue with the certificate.
    CertificateUnknown = 46,
    /// A field in the handshake was out of range or inconsistent with other fields.
    /// This message is always fatal.
    IllegalParameter = 47,
    /// A valid certificate chain or partial chain was received, but the
    /// certificate was not accepted because the CA certificate could not
    /// be located or couldn't be matched with a known, trusted CA.
    /// This message is always fatal.
    UnknownCa = 48,
    /// A valid certificate was received, but when access control was applied, the sender
    /// decided not to proceed with negotiation.
    /// This message is always fatal.
    AccessDenied = 49,
    /// A message could not be decoded because some field was out of the specified range
    /// or the length of the message was incorrect.
    /// This message is always fatal.
    DecodeError = 50,
    /// A handshake cryptographic operation failed, including being unable to correctly verify a
    /// signature or validate a Finished message.
    /// This message is always fatal.
    DecryptError = 51,
    /// Earlier version, *MUST NOT* be sent.
    #[deprecated(note = "Only used in an earlier version. MUST NOT be sent.")]
    ExportRestrictionReserved = 60,
    /// The protocol version the client has attempted to negotiate is recognized  but not
    /// supported.
    /// This message is always fatal.
    ProtocolVersion = 70,
    /// Returned instead of `handshake_failure` because the serveer required ciphers more
    /// secure than those supported by the client.
    /// This message is always fatal.
    InsufficientSecurity = 71,
    /// An internal error unrelated to the peer or the correctness
    /// of the protocol makes it impossible to continue.
    /// This message is always fatal.
    InternalError = 80,
    /// This handshake was canceled for some reason unrelated to protocol failure.
    /// This alert should be followed by a `close_notify` and is generally a warning.
    UserCanceled = 90,
    /// Sent by the client in response to a `HelloRequest` or by a server in response
    /// to a `ClientHello` after the initial handshaking. This message is used when a
    /// renegotiation is not appropriate. The peer can choose whether to proceed with
    /// the connection.
    /// This message is always a warning.
    NoRenegotiation = 100,
    /// Sent by clients that receive an extended `ServerHello` containing an extension that
    /// they did not put in the corresponding `ClientHello`.
    /// This message is always fatal.
    UnsupportedExtension = 110,
}
