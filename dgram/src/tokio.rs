use crate::RecvData;
use std::io::ErrorKind;
use std::io::Result;
use std::task::Context;
use std::task::Poll;

use tokio::io::Interest;
use tokio::net::UdpSocket;

#[cfg(target_os = "linux")]
mod linux {
    pub(super) use super::super::linux_imports::*;
    pub(super) use std::os::fd::AsFd;
}

#[cfg(target_os = "linux")]
use linux::*;

#[cfg(target_os = "linux")]
pub fn poll_send_to(
    socket: &UdpSocket, ctx: &mut Context<'_>, send_buf: &[u8],
    sendmsg_settings: SendMsgSettings,
) -> Poll<Result<usize>> {
    loop {
        match socket.poll_send_ready(ctx) {
            Poll::Ready(Ok(())) => {
                // Important to use try_io so that Tokio can clear the socket's
                // readiness flag
                match socket.try_io(Interest::WRITABLE, || {
                    let fd = socket.as_fd();
                    send_msg(fd, send_buf, sendmsg_settings).map_err(Into::into)
                }) {
                    Err(e) if e.kind() == ErrorKind::WouldBlock => {},
                    io_res => break Poll::Ready(io_res),
                }
            },
            Poll::Ready(Err(e)) => break Poll::Ready(Err(e)),
            Poll::Pending => break Poll::Pending,
        }
    }
}

#[cfg(target_os = "linux")]
pub async fn send_to(
    socket: &UdpSocket, send_buf: &[u8], sendmsg_settings: SendMsgSettings,
) -> Result<usize> {
    std::future::poll_fn(|mut cx| {
        poll_send_to(socket, &mut cx, send_buf, sendmsg_settings)
    })
    .await
}

#[cfg(target_os = "linux")]
pub fn poll_recv_from(
    socket: &UdpSocket, ctx: &mut Context<'_>, recv_buf: &mut [u8],
    recvmsg_settings: &mut RecvMsgSettings,
) -> Poll<Result<RecvData>> {
    loop {
        match socket.poll_recv_ready(ctx) {
            Poll::Ready(Ok(())) => {
                // Important to use try_io so that Tokio can clear the socket's
                // readiness flag
                match socket.try_io(Interest::READABLE, || {
                    let fd = socket.as_fd();
                    recv_msg(fd, recv_buf, recvmsg_settings).map_err(Into::into)
                }) {
                    // The `poll_recv_ready` future registers the ctx with Tokio.
                    // We can only return Pending when that
                    // future is Pending or we won't wake the
                    // runtime properly
                    Err(e) if e.kind() == ErrorKind::WouldBlock => {},
                    io_res => break Poll::Ready(io_res),
                }
            },
            Poll::Ready(Err(e)) => break Poll::Ready(Err(e)),
            Poll::Pending => break Poll::Pending,
        }
    }
}

#[cfg(target_os = "linux")]
pub async fn recv_from(
    socket: &UdpSocket, recv_buf: &mut [u8],
    recvmsg_settings: &mut RecvMsgSettings<'_>,
) -> Result<RecvData> {
    std::future::poll_fn(|mut ctx| {
        poll_recv_from(socket, &mut ctx, recv_buf, recvmsg_settings)
    })
    .await
}
