/// TLS credentials to authenticate the endpoint.
#[derive(Clone, Copy, Debug)]
pub struct TlsCertificatePaths<'p> {
    /// Path to the endpoint's TLS certificate.
    pub cert: &'p str,
    /// Path to the endpoint's private key.
    pub private_key: &'p str,
    /// `cert`'s PKI certificate type.
    pub kind: CertificateKind,
}

/// Types of PKI certificates supported by the crate.
#[derive(Default, Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum CertificateKind {
    /// Standard X509 TLS certificate.
    #[default]
    X509,
    /// [Raw public key] TLS certificate.
    ///
    ///
    /// [Raw public key]: https://datatracker.ietf.org/doc/html/rfc7250
    RawPublicKey,
}
