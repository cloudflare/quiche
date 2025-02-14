//! Network socket utilities and wrappers.

mod capabilities;
mod connected;
mod listener;

pub use self::capabilities::SocketCapabilities;
#[cfg(target_os = "linux")]
pub use self::capabilities::SocketCapabilitiesBuilder;
pub use self::connected::BoxedSocket;
pub use self::connected::Socket;
pub use self::listener::QuicListener;
