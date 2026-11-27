// Copyright (C) 2026, Cloudflare, Inc.
// All rights reserved.
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are
// met:
//
//     * Redistributions of source code must retain the above copyright notice,
//       this list of conditions and the following disclaimer.
//
//     * Redistributions in binary form must reproduce the above copyright
//       notice, this list of conditions and the following disclaimer in the
//       documentation and/or other materials provided with the distribution.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS
// IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO,
// THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
// PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR
// CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
// EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
// PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
// PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
// LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
// NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
// SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

//! Batched UDP receives on macOS.

use std::io;
use std::net::SocketAddr;
use std::os::fd::AsFd;

use datagram_socket::MAX_DATAGRAM_SIZE;
use tokio::net::UdpSocket;

use super::PollRecvData;
use crate::socket::macos;
use crate::socket::macos::MAX_RECV_BATCH;

/// Receives datagrams from a connected UDP socket with `recvmsg_x` and hands
/// them out in runs the IO worker splits as it splits a GRO receive.
pub(super) struct BatchReceiver {
    peer: SocketAddr,
    /// One `MAX_DATAGRAM_SIZE` slot per datagram of a batch.
    slots: Box<[u8]>,
    lens: [usize; MAX_RECV_BATCH],
    received: usize,
    handed_out: usize,
}

impl BatchReceiver {
    /// Returns a receiver for `socket`, or `None` if it isn't connected.
    pub(super) fn new(socket: &UdpSocket) -> Option<Self> {
        Some(Self {
            peer: socket.peer_addr().ok()?,
            slots: vec![0; MAX_RECV_BATCH * MAX_DATAGRAM_SIZE].into_boxed_slice(),
            lens: [0; MAX_RECV_BATCH],
            received: 0,
            handed_out: 0,
        })
    }

    /// Receives a batch of datagrams from `socket`, dropping any not yet
    /// handed out.
    ///
    /// # Errors
    /// [`io::ErrorKind::WouldBlock`] if no datagram is waiting.
    pub(super) fn recv(&mut self, socket: &UdpSocket) -> io::Result<()> {
        let received = macos::recv_batch(
            socket.as_fd(),
            &mut self.slots,
            MAX_DATAGRAM_SIZE,
            &mut self.lens,
        )?;
        if received == 0 {
            return Err(io::ErrorKind::WouldBlock.into());
        }

        self.received = received;
        self.handed_out = 0;
        Ok(())
    }

    /// Takes the next run of equal-size datagrams, the last of which may be
    /// shorter, or `None` once the batch is handed out.
    pub(super) fn next_run(&mut self) -> Option<PollRecvData> {
        let lens = &self.lens[self.handed_out..self.received];
        let &size = lens.first()?;

        let mut count = lens.iter().take_while(|&&len| len == size).count();
        if lens.get(count).is_some_and(|&len| len < size) {
            count += 1;
        }

        let mut buf = Vec::with_capacity(lens[..count].iter().sum());
        for (slot, &len) in self
            .slots
            .chunks_exact(MAX_DATAGRAM_SIZE)
            .skip(self.handed_out)
            .zip(&lens[..count])
        {
            buf.extend_from_slice(&slot[..len]);
        }

        self.handed_out += count;
        Some(PollRecvData {
            buf,
            src_addr: self.peer,
            dst_addr_override: None,
            rx_time: None,
            gro: (count > 1 && size > 0).then_some(size as i32),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::metrics::DefaultMetrics;
    use crate::quic::router::tests::NoopInitialHandler;
    use crate::quic::router::InboundPacketRouter;
    use crate::settings::Config;
    use crate::socket::SocketCapabilities;
    use crate::ConnectionParams;

    use std::sync::Arc;
    use std::time::Duration;

    type TestRouter = InboundPacketRouter<
        UdpSocket,
        Arc<UdpSocket>,
        DefaultMetrics,
        NoopInitialHandler,
    >;

    /// A connected router hands out each run of equal-size datagrams as one
    /// GRO-style receive; an unconnected one receives one datagram at a time.
    #[tokio::test]
    async fn router_receives_runs_with_recvmsg_x() {
        let peer = UdpSocket::bind("127.0.0.1:0").await.expect("bind");
        let peer_addr = peer.local_addr().expect("local addr");
        let connected = UdpSocket::bind("127.0.0.1:0").await.expect("bind");
        connected.connect(peer_addr).await.expect("connect");
        let mut connected = router(connected);
        let mut unconnected =
            router(UdpSocket::bind("127.0.0.1:0").await.expect("bind"));
        assert!(connected.batch_receiver.is_some());
        assert!(unconnected.batch_receiver.is_none());

        let dgrams: Vec<Vec<u8>> = [1200, 1200, 1200, 800, 1200, 1200, 1300]
            .iter()
            .enumerate()
            .map(|(i, &len)| vec![i as u8; len])
            .collect();
        for dgram in &dgrams {
            peer.send_to(dgram, connected.local_addr)
                .await
                .expect("send");
        }

        for (expected, gro) in [
            (dgrams[..4].concat(), Some(1200)),
            (dgrams[4..6].concat(), Some(1200)),
            (dgrams[6].clone(), None),
        ] {
            let packet = recv(&mut connected).await.expect("recv");
            assert_eq!(packet.buf, expected);
            assert_eq!(packet.src_addr, peer_addr);
            assert_eq!(packet.gro, gro);
        }

        for dgram in &dgrams[..2] {
            peer.send_to(dgram, unconnected.local_addr)
                .await
                .expect("send");
        }
        for dgram in &dgrams[..2] {
            let packet = recv(&mut unconnected).await.expect("recv");
            assert_eq!(&packet.buf, dgram);
            assert_eq!(packet.gro, None);
        }
    }

    fn router(socket: UdpSocket) -> TestRouter {
        let capabilities =
            SocketCapabilities::apply_all_and_get_compatibility(&socket);
        let socket = Arc::new(socket);
        let local_addr = socket.local_addr().expect("local addr");
        let config = Config::new(&ConnectionParams::default(), capabilities)
            .expect("config");

        InboundPacketRouter::new(
            config,
            Arc::clone(&socket),
            socket,
            local_addr,
            NoopInitialHandler,
            DefaultMetrics,
        )
        .0
    }

    async fn recv(router: &mut TestRouter) -> io::Result<PollRecvData> {
        tokio::time::timeout(
            Duration::from_secs(5),
            std::future::poll_fn(|cx| router.poll_recv_and_rx_time(cx)),
        )
        .await
        .expect("timed out receiving")
    }
}
