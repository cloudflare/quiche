use crate::settings::TlsCertificatePaths;
use boring::ssl::SslContextBuilder;

/// A set of hooks executed at the level of a [quiche::Connection].
pub trait ConnectionHook {
    /// Constructs an optional [`SslContextBuilder`].
    ///
    /// This method allows full customization of quiche's SSL context, for example to
    /// specify async callbacks during the QUIC handshake. It is called once per socket
    /// during initial setup, and then reused across all connections on that socket.
    ///
    /// Only called if both the hook and [`TlsCertificatePaths`] are set in
    /// [`ConnectionParams`](crate::ConnectionParams).
    fn create_custom_ssl_context_builder(
        &self,
        settings: TlsCertificatePaths<'_>,
    ) -> Option<SslContextBuilder>;
}
