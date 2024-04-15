use crate::RecvData;
use crate::RecvMsgSettings;
use crate::SendMsgSettings;
use std::io::Result;
use std::os::fd::AsFd;

#[cfg(target_os = "linux")]
use super::linux_imports::*;

#[cfg(target_os = "linux")]
pub fn send_to(
    fd: &impl AsFd, send_buf: &[u8], sendmsg_settings: SendMsgSettings,
) -> Result<usize> {
    // TODO: separate mio module that uses try_io? This works for stateless
    // polling e.g. epoll/kqueue, but stateful polling (select(), poll()) will
    // require re-registering the socket after an event. try_io() does that for us
    let sent = send_msg(fd, send_buf, sendmsg_settings);

    match sent {
        Ok(s) => Ok(s),
        Err(Errno::EAGAIN) => Err(std::io::Error::last_os_error()),
        Err(e) => Err(e.into()),
    }
}

#[cfg(target_os = "linux")]
pub fn recv_from(
    fd: &impl AsFd, read_buf: &mut [u8], recvmsg_settings: &mut RecvMsgSettings,
) -> Result<RecvData> {
    let recvd = recv_msg(fd, read_buf, recvmsg_settings);

    match recvd {
        Ok(r) => Ok(r),
        Err(Errno::EAGAIN) => Err(std::io::Error::last_os_error()),
        Err(e) => Err(e.into()),
    }
}
