//! Configuration for QUIC connections.

mod config;
mod hooks;
mod quic;
mod tls;

pub(crate) use self::config::*;

pub use self::hooks::*;
pub use self::quic::*;
pub use self::tls::*;

/// Combined configuration parameters required to establish a QUIC connection.
///
/// [`ConnectionParams`] aggregates the parameters required for all QUIC connections,
/// regardless of whether it's a client- or server-side connection. To construct them,
/// either `ConnectionParams::new_server` or `ConnectionParams::new_client` must be
/// used. The parameters can be modified freely after construction.
#[derive(Debug, Default)]
#[non_exhaustive] // force use of constructor functions
pub struct ConnectionParams<'a> {
    /// QUIC connection settings.
    pub settings: QuicSettings,
    /// Optional TLS credentials to authenticate with.
    pub tls_cert: Option<TlsCertificatePaths<'a>>,
    /// Hooks to use for the connection.
    pub hooks: Hooks,
}

impl<'a> ConnectionParams<'a> {
    /// Creates [`ConnectionParams`] for a QUIC server.
    /// Servers should always specify TLS credentials.
    #[inline]
    pub fn new_server(
        settings: QuicSettings,
        tls_cert: TlsCertificatePaths<'a>,
        hooks: Hooks,
    ) -> Self {
        Self {
            settings,
            tls_cert: Some(tls_cert),
            hooks,
        }
    }

    /// Creates [`ConnectionParams`] for a QUIC client.
    /// Clients may enable mTLS by specifying TLS credentials.
    #[inline]
    pub fn new_client(
        settings: QuicSettings,
        tls_cert: Option<TlsCertificatePaths<'a>>,
        hooks: Hooks,
    ) -> Self {
        Self {
            settings,
            tls_cert,
            hooks,
        }
    }
}
