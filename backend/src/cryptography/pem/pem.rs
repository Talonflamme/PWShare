use crate::cryptography::pem::asn1der::{FromASN1DER, ToASN1DER};
use crate::cryptography::pem::base64::{base64decode, base64encode};
use crate::cryptography::rsa::{PrivateKey, PublicKey};
use crypto_bigint::{Encoding, Uint};

pub trait ToPemContent {
    fn to_pem_content(&self) -> String;
}

fn insert_newlines(s: String, line_length: usize) -> String {
    let mut result = String::with_capacity(s.len() + s.len() / line_length);
    let mut start = 0;

    while start < s.len() {
        let end = (start + line_length).min(s.len());
        result.push_str(&s[start..end]);
        if end < s.len() {
            result.push('\n');
        }
        start = end;
    }

    result
}

impl<const L: usize> ToPemContent for PublicKey<L>
where
    Uint<L>: Encoding,
    <Uint<L> as Encoding>::Repr: AsRef<[u8]>,
{
    fn to_pem_content(&self) -> String {
        let asn1der_repr = self.to_asn1_der();
        let b64 = base64encode(asn1der_repr.as_slice());

        let content = insert_newlines(b64, 64);

        let result = format!(
            "-----BEGIN RSA PUBLIC KEY-----
{}
-----END RSA PUBLIC KEY-----",
            content
        );

        result
    }
}

impl<const L: usize> ToPemContent for PrivateKey<L>
where
    Uint<L>: Encoding,
    <Uint<L> as Encoding>::Repr: AsRef<[u8]>,
{
    fn to_pem_content(&self) -> String {
        let asn1der_repr = self.to_asn1_der();
        let b64 = base64encode(asn1der_repr.as_slice());

        let content = insert_newlines(b64, 64);

        let result = format!(
            "-----BEGIN RSA PRIVATE KEY-----
{}
-----END RSA PRIVATE KEY-----",
            content
        );

        result
    }
}

pub fn find_content_between_header(content: String, header: &str, footer: &str) -> Option<String> {
    let mut lines = content.lines();

    // advance iter until header is found
    if !lines.any(|line| line == header) {
        return None; // no header found
    }

    let mut result = String::new();
    for line in lines {
        if line == footer {
            return Some(result);
        }
        result.push_str(line);
    }

    None // no footer found
}

pub trait FromPemContent: Sized {
    fn from_pem_content(content: String) -> Result<Self, &'static str>;
}

// TODO: potentially add version to match the PKCS#1 RSA key definition

impl<const L: usize> FromPemContent for PublicKey<L> {
    fn from_pem_content(content: String) -> Result<Self, &'static str> {
        let content = find_content_between_header(
            content,
            "-----BEGIN RSA PUBLIC KEY-----",
            "-----END RSA PUBLIC KEY-----",
        )
        .ok_or("Could not find header/footer for `RSA PUBLIC KEY`")?;

        let decoded = base64decode(content);

        Self::from_asn1_der(decoded.into_iter())
    }
}

impl<const L: usize> FromPemContent for PrivateKey<L> {
    fn from_pem_content(content: String) -> Result<Self, &'static str> {
        let content = find_content_between_header(
            content,
            "-----BEGIN RSA PRIVATE KEY-----",
            "-----END RSA PRIVATE KEY-----",
        )
        .ok_or("Could not find header/footer for `RSA PRIVATE KEY`")?;

        let decoded = base64decode(content);

        Self::from_asn1_der(decoded.into_iter())
    }
}
