mod datagram;
mod shutdown;
mod socket_stats;

#[cfg(target_os = "linux")]
#[macro_use]
mod mmsg;

pub use self::datagram::*;

#[cfg(target_os = "linux")]
pub use mmsg::*;

#[cfg(unix)]
use std::os::fd::AsRawFd;

pub use self::shutdown::*;
pub use self::socket_stats::*;

#[cfg(target_os = "linux")]
pub fn is_nonblocking(fd: &impl AsRawFd) -> std::io::Result<bool> {
    let flags = unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_GETFL) };

    if flags == -1 {
        return Err(std::io::Error::last_os_error());
    }

    if flags & libc::O_NONBLOCK != 0 {
        Ok(true)
    } else {
        Ok(false)
    }
}

#[cfg(all(unix, not(target_os = "linux")))]
pub fn is_nonblocking(_fd: &impl AsRawFd) -> std::io::Result<bool> {
    Ok(true)
}
