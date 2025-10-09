use super::alert_description::AlertDescription;
use super::alert_level::AlertLevel;
use pwshare_macros::{ReadableFromStream, WritableToSink};

#[derive(ReadableFromStream, WritableToSink, Debug)]
pub struct Alert {
    level: AlertLevel,
    description: AlertDescription,
}

impl Alert {
    pub fn is_fatal(&self) -> bool {
        self.level == AlertLevel::Fatal
    }
    
    #[inline]
    pub fn close_notify() -> Self {
        Self {
            level: AlertLevel::Warning,
            description: AlertDescription::CloseNotify,
        }
    }

    #[inline]
    pub fn unexpected_message() -> Self {
        Self {
            level: AlertLevel::Fatal,
            description: AlertDescription::UnexpectedMessage,
        }
    }

    #[inline]
    pub fn bad_record_mac() -> Self {
        Self {
            level: AlertLevel::Fatal,
            description: AlertDescription::BadRecordMac,
        }
    }

    #[inline]
    pub fn record_overflow() -> Self {
        Self {
            level: AlertLevel::Fatal,
            description: AlertDescription::RecordOverflow,
        }
    }

    #[inline]
    pub fn decompression_failure() -> Self {
        Self {
            level: AlertLevel::Fatal,
            description: AlertDescription::DecompressionFailure,
        }
    }

    #[inline]
    pub fn handshake_failure() -> Self {
        Self {
            level: AlertLevel::Fatal,
            description: AlertDescription::HandshakeFailure,
        }
    }

    #[inline]
    pub fn bad_certificate(level: AlertLevel) -> Self {
        Self {
            level,
            description: AlertDescription::BadCertificate,
        }
    }

    #[inline]
    pub fn unsupported_certificate(level: AlertLevel) -> Self {
        Self {
            level,
            description: AlertDescription::UnsupportedCertificate,
        }
    }

    #[inline]
    pub fn certificate_revoked(level: AlertLevel) -> Self {
        Self {
            level,
            description: AlertDescription::CertificateRevoked,
        }
    }

    #[inline]
    pub fn certificate_expired(level: AlertLevel) -> Self {
        Self {
            level,
            description: AlertDescription::CertificateExpired,
        }
    }

    #[inline]
    pub fn certificate_unknown(level: AlertLevel) -> Self {
        Self {
            level,
            description: AlertDescription::CertificateUnknown,
        }
    }

    #[inline]
    pub fn illegal_parameter() -> Self {
        Self {
            level: AlertLevel::Fatal,
            description: AlertDescription::IllegalParameter,
        }
    }

    #[inline]
    pub fn unknown_ca() -> Self {
        Self {
            level: AlertLevel::Fatal,
            description: AlertDescription::UnknownCa,
        }
    }

    #[inline]
    pub fn access_denied() -> Self {
        Self {
            level: AlertLevel::Fatal,
            description: AlertDescription::AccessDenied,
        }
    }

    #[inline]
    pub fn decode_error() -> Self {
        Self {
            level: AlertLevel::Fatal,
            description: AlertDescription::DecodeError,
        }
    }

    #[inline]
    pub fn decrypt_error() -> Self {
        Self {
            level: AlertLevel::Fatal,
            description: AlertDescription::DecryptError,
        }
    }

    #[inline]
    pub fn protocol_version() -> Self {
        Self {
            level: AlertLevel::Fatal,
            description: AlertDescription::ProtocolVersion,
        }
    }

    #[inline]
    pub fn insufficient_security() -> Self {
        Self {
            level: AlertLevel::Fatal,
            description: AlertDescription::InsufficientSecurity,
        }
    }

    #[inline]
    pub fn internal_error() -> Self {
        Self {
            level: AlertLevel::Fatal,
            description: AlertDescription::InternalError,
        }
    }

    #[inline]
    pub fn user_canceled() -> Self {
        Self {
            level: AlertLevel::Warning,
            description: AlertDescription::UserCanceled,
        }
    }

    #[inline]
    pub fn no_renegotiation() -> Self {
        Self {
            level: AlertLevel::Warning,
            description: AlertDescription::NoRenegotiation,
        }
    }

    #[inline]
    pub fn unsupported_extension() -> Self {
        Self {
            level: AlertLevel::Fatal,
            description: AlertDescription::UnsupportedExtension,
        }
    }
}
