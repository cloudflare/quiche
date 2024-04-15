use std::io;
use std::os::fd::AsFd;

#[cfg(target_os = "linux")]
use super::linux_imports::*;

/// Indicators of settings applied to a socket. These settings aren't "applied"
/// to a socket. Rather, the same (maximal) settings are always applied to a
/// socket, and this struct indicates which of those settings were successfully
/// applied to a socket.
#[derive(Default)]
pub struct SocketCapabilities {
    /// Indicates if the socket has "Generic Segmentation Offload" enabled.
    pub has_gso: bool,

    /// Indicates if the socket has "SO_RXQ_OVFL" set.
    pub check_udp_drop: bool,

    /// Indicates if the monotonic clock is set for transimssion timestamps.
    pub has_txtime: bool,

    /// Indicates if the monotonic clock is set for receiving timestamps.
    pub has_rxtime: bool,

    /// Indicates if the socket has "Generic Receive Offload" enabled.
    pub has_gro: bool,
}

impl SocketCapabilities {
    /// Try applying maximal settings to a socket and returns indicators of
    /// which settings were successfully applied.
    #[cfg(unix)]
    pub fn apply_all_and_get_compatibility(
        socket: &impl AsFd, max_send_udp_payload_size: usize,
    ) -> Self {
        let fd = socket.as_fd();

        Self {
            has_gso: set_gso_segment(&fd, max_send_udp_payload_size).is_ok(),
            check_udp_drop: set_udp_rxq_ovfl(&fd).is_ok(),
            has_txtime: set_tx_time(&fd).is_ok(),
            has_rxtime: set_rx_time(&fd).is_ok(),
            has_gro: set_gro(&fd).is_ok(),
        }
    }
}

#[cfg(target_os = "linux")]
pub fn set_gso_segment(sock: &impl AsFd, segment: usize) -> io::Result<()> {
    setsockopt(sock, UdpGsoSegment, &(segment as i32))?;

    Ok(())
}

#[cfg(not(target_os = "linux"))]
pub fn set_gso_segment(_: &impl AsFd, _: usize) -> io::Result<()> {
    Err(std::io::Error::from(std::io::ErrorKind::Unsupported))
}

#[cfg(target_os = "linux")]
pub fn set_gro(sock: &impl AsFd) -> io::Result<()> {
    UdpGroSegment.set(sock, &true)?;

    Ok(())
}

#[cfg(not(target_os = "linux"))]
pub fn set_gro(_: &impl AsFd) -> io::Result<()> {
    Err(std::io::Error::from(std::io::ErrorKind::Unsupported))
}

#[cfg(target_os = "linux")]
fn set_udp_rxq_ovfl(sock: &impl AsFd) -> io::Result<()> {
    setsockopt(sock, RxqOvfl, &1)?;

    Ok(())
}

#[cfg(not(target_os = "linux"))]
fn set_udp_rxq_ovfl(_: &impl AsFd) -> io::Result<()> {
    Err(std::io::Error::from(std::io::ErrorKind::Unsupported))
}

#[cfg(target_os = "linux")]
pub fn set_tx_time(sock: &impl AsFd) -> io::Result<()> {
    let cfg = libc::sock_txtime {
        clockid: libc::CLOCK_MONOTONIC,
        flags: 0,
    };

    setsockopt(sock, TxTime, &cfg)?;

    Ok(())
}

#[cfg(not(target_os = "linux"))]
pub fn set_tx_time(_: &impl AsFd) -> io::Result<()> {
    Err(std::io::Error::from(std::io::ErrorKind::Unsupported))
}

#[cfg(target_os = "linux")]
pub fn set_rx_time(sock: &impl AsFd) -> io::Result<()> {
    setsockopt(sock, ReceiveTimestampns, &true)?;

    Ok(())
}

#[cfg(not(target_os = "linux"))]
pub fn set_rx_time(_: &impl AsFd) -> io::Result<()> {
    Err(std::io::Error::from(std::io::ErrorKind::Unsupported))
}
