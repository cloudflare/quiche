use crate::error::Error;
use crate::error::Result;
use crate::frame;
use crate::packet;
use crate::packet::ConnectionId;
use crate::packet::Header;
use crate::packet::Type;
use crate::rand;
use crate::range_buf::BufFactory;
use crate::recovery;
use crate::AddrTupleFmt;
use crate::Connection;
use crate::SendInfo;
use crate::CONNECTION_WINDOW_FACTOR;
use crate::MIN_CLIENT_INITIAL_LEN;
use crate::PAYLOAD_LENGTH_LEN;
use crate::PAYLOAD_MIN_LEN;
use crate::QLOG_DATA_MV;
use crate::QLOG_METRICS;
use crate::QLOG_PACKET_TX;
use std::cmp;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Instant;

#[cfg(feature = "qlog")]
use qlog::events::DataRecipient;
#[cfg(feature = "qlog")]
use qlog::events::EventData;
#[cfg(feature = "qlog")]
use qlog::events::EventImportance;
#[cfg(feature = "qlog")]
use qlog::events::RawInfo;

use crate::recovery::RecoveryOps;
use smallvec::SmallVec;

struct SendSingleContext {
    is_closing: bool,
    out_len: usize,
}

impl<F: BufFactory> Connection<F> {
    /// Writes a single QUIC packet to be sent to the peer.
    ///
    /// On success the number of bytes written to the output buffer is
    /// returned, or [`Done`] if there was nothing to write.
    ///
    /// The application should call `send()` multiple times until [`Done`] is
    /// returned, indicating that there are no more packets to send. It is
    /// recommended that `send()` be called in the following cases:
    ///
    ///  * When the application receives QUIC packets from the peer (that is,
    ///    any time [`recv()`] is also called).
    ///
    ///  * When the connection timer expires (that is, any time [`on_timeout()`]
    ///    is also called).
    ///
    ///  * When the application sends data to the peer (for example, any time
    ///    [`stream_send()`] or [`stream_shutdown()`] are called).
    ///
    ///  * When the application receives data from the peer (for example any
    ///    time [`stream_recv()`] is called).
    ///
    /// Once [`is_draining()`] returns `true`, it is no longer necessary to call
    /// `send()` and all calls will return [`Done`].
    ///
    /// [`Done`]: enum.Error.html#variant.Done
    /// [`recv()`]: struct.Connection.html#method.recv
    /// [`on_timeout()`]: struct.Connection.html#method.on_timeout
    /// [`stream_send()`]: struct.Connection.html#method.stream_send
    /// [`stream_shutdown()`]: struct.Connection.html#method.stream_shutdown
    /// [`stream_recv()`]: struct.Connection.html#method.stream_recv
    /// [`is_draining()`]: struct.Connection.html#method.is_draining
    ///
    /// ## Examples:
    ///
    /// ```no_run
    /// # let mut out = [0; 512];
    /// # let socket = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    /// # let mut config = quiche::Config::new(quiche::PROTOCOL_VERSION)?;
    /// # let scid = quiche::ConnectionId::from_ref(&[0xba; 16]);
    /// # let peer = "127.0.0.1:1234".parse().unwrap();
    /// # let local = socket.local_addr().unwrap();
    /// # let mut conn = quiche::accept(&scid, None, local, peer, &mut config)?;
    /// loop {
    ///     let (write, send_info) = match conn.send(&mut out) {
    ///         Ok(v) => v,
    ///
    ///         Err(quiche::Error::Done) => {
    ///             // Done writing.
    ///             break;
    ///         },
    ///
    ///         Err(e) => {
    ///             // An error occurred, handle it.
    ///             break;
    ///         },
    ///     };
    ///
    ///     socket.send_to(&out[..write], &send_info.to).unwrap();
    /// }
    /// # Ok::<(), quiche::Error>(())
    /// ```
    pub fn send(&mut self, out: &mut [u8]) -> Result<(usize, SendInfo)> {
        self.send_on_path(out, None, None)
    }

    /// Writes a single QUIC packet to be sent to the peer from the specified
    /// local address `from` to the destination address `to`.
    ///
    /// The behavior of this method differs depending on the value of the `from`
    /// and `to` parameters:
    ///
    ///  * If both are `Some`, then the method only consider the 4-tuple
    ///    (`from`, `to`). Application can monitor the 4-tuple availability,
    ///    either by monitoring [`path_event_next()`] events or by relying on
    ///    the [`paths_iter()`] method. If the provided 4-tuple does not exist
    ///    on the connection (anymore), it returns an [`InvalidState`].
    ///
    ///  * If `from` is `Some` and `to` is `None`, then the method only
    ///    considers sending packets on paths having `from` as local address.
    ///
    ///  * If `to` is `Some` and `from` is `None`, then the method only
    ///    considers sending packets on paths having `to` as peer address.
    ///
    ///  * If both are `None`, all available paths are considered.
    ///
    /// On success the number of bytes written to the output buffer is
    /// returned, or [`Done`] if there was nothing to write.
    ///
    /// The application should call `send_on_path()` multiple times until
    /// [`Done`] is returned, indicating that there are no more packets to
    /// send. It is recommended that `send_on_path()` be called in the
    /// following cases:
    ///
    ///  * When the application receives QUIC packets from the peer (that is,
    ///    any time [`recv()`] is also called).
    ///
    ///  * When the connection timer expires (that is, any time [`on_timeout()`]
    ///    is also called).
    ///
    ///  * When the application sends data to the peer (for examples, any time
    ///    [`stream_send()`] or [`stream_shutdown()`] are called).
    ///
    ///  * When the application receives data from the peer (for example any
    ///    time [`stream_recv()`] is called).
    ///
    /// Once [`is_draining()`] returns `true`, it is no longer necessary to call
    /// `send_on_path()` and all calls will return [`Done`].
    ///
    /// [`Done`]: enum.Error.html#variant.Done
    /// [`InvalidState`]: enum.Error.html#InvalidState
    /// [`recv()`]: struct.Connection.html#method.recv
    /// [`on_timeout()`]: struct.Connection.html#method.on_timeout
    /// [`stream_send()`]: struct.Connection.html#method.stream_send
    /// [`stream_shutdown()`]: struct.Connection.html#method.stream_shutdown
    /// [`stream_recv()`]: struct.Connection.html#method.stream_recv
    /// [`path_event_next()`]: struct.Connection.html#method.path_event_next
    /// [`paths_iter()`]: struct.Connection.html#method.paths_iter
    /// [`is_draining()`]: struct.Connection.html#method.is_draining
    ///
    /// ## Examples:
    ///
    /// ```no_run
    /// # let mut out = [0; 512];
    /// # let socket = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    /// # let mut config = quiche::Config::new(quiche::PROTOCOL_VERSION)?;
    /// # let scid = quiche::ConnectionId::from_ref(&[0xba; 16]);
    /// # let peer = "127.0.0.1:1234".parse().unwrap();
    /// # let local = socket.local_addr().unwrap();
    /// # let mut conn = quiche::accept(&scid, None, local, peer, &mut config)?;
    /// loop {
    ///     let (write, send_info) = match conn.send_on_path(&mut out, Some(local), Some(peer)) {
    ///         Ok(v) => v,
    ///
    ///         Err(quiche::Error::Done) => {
    ///             // Done writing.
    ///             break;
    ///         },
    ///
    ///         Err(e) => {
    ///             // An error occurred, handle it.
    ///             break;
    ///         },
    ///     };
    ///
    ///     socket.send_to(&out[..write], &send_info.to).unwrap();
    /// }
    /// # Ok::<(), quiche::Error>(())
    /// ```
    pub fn send_on_path(
        &mut self, out: &mut [u8], from: Option<SocketAddr>,
        to: Option<SocketAddr>,
    ) -> Result<(usize, SendInfo)> {
        if out.is_empty() {
            return Err(Error::BufferTooShort);
        }

        if self.is_closed() || self.is_draining() {
            return Err(Error::Done);
        }

        let now = Instant::now();

        if self.local_error.is_none() {
            self.do_handshake(now)?;
        }

        // Forwarding the error value here could confuse
        // applications, as they may not expect getting a `recv()`
        // error when calling `send()`.
        //
        // We simply fall-through to sending packets, which should
        // take care of terminating the connection as needed.
        let _ = self.process_undecrypted_0rtt_packets();

        // There's no point in trying to send a packet if the Initial secrets
        // have not been derived yet, so return early.
        if !self.derived_initial_secrets {
            return Err(Error::Done);
        }

        let mut has_initial = false;

        let mut done = 0;

        // Limit output packet size to respect the sender and receiver's
        // maximum UDP payload size limit.
        let mut left = cmp::min(out.len(), self.max_send_udp_payload_size());

        let send_pid = match (from, to) {
            (Some(f), Some(t)) => self
                .paths
                .path_id_from_addrs(&(f, t))
                .ok_or(Error::InvalidState)?,

            _ => self.get_send_path_id(from, to)?,
        };

        let send_path = self.paths.get_mut(send_pid)?;

        // Update max datagram size to allow path MTU discovery probe to be sent.
        if let Some(pmtud) = send_path.pmtud.as_mut() {
            if pmtud.should_probe() {
                let size = if self.handshake_confirmed || self.handshake_completed
                {
                    pmtud.get_probe_size()
                } else {
                    pmtud.get_current_mtu()
                };

                send_path.recovery.pmtud_update_max_datagram_size(size);

                left =
                    cmp::min(out.len(), send_path.recovery.max_datagram_size());
            }
        }

        // Limit data sent by the server based on the amount of data received
        // from the client before its address is validated.
        if !send_path.verified_peer_address && self.is_server {
            left = cmp::min(left, send_path.max_send_bytes);
        }

        // Generate coalesced packets.
        while left > 0 {
            let (ty, written) = match self.send_single(
                &mut out[done..done + left],
                send_pid,
                has_initial,
                now,
            ) {
                Ok(v) => v,

                Err(Error::BufferTooShort) | Err(Error::Done) => break,

                Err(e) => return Err(e),
            };

            done += written;
            left -= written;

            match ty {
                Type::Initial => has_initial = true,

                // No more packets can be coalesced after a 1-RTT.
                Type::Short => break,

                _ => (),
            };

            // When sending multiple PTO probes, don't coalesce them together,
            // so they are sent on separate UDP datagrams.
            if let Ok(epoch) = ty.to_epoch() {
                if self.paths.get_mut(send_pid)?.recovery.loss_probes(epoch) > 0 {
                    break;
                }
            }

            // Don't coalesce packets that must go on different paths.
            if !(from.is_some() && to.is_some()) &&
                self.get_send_path_id(from, to)? != send_pid
            {
                break;
            }
        }

        if done == 0 {
            self.last_tx_data = self.tx_data;

            return Err(Error::Done);
        }

        if has_initial && left > 0 && done < MIN_CLIENT_INITIAL_LEN {
            let pad_len = cmp::min(left, MIN_CLIENT_INITIAL_LEN - done);

            // Fill padding area with null bytes, to avoid leaking information
            // in case the application reuses the packet buffer.
            out[done..done + pad_len].fill(0);

            done += pad_len;
        }

        let send_path = self.paths.get(send_pid)?;

        let info = SendInfo {
            from: send_path.local_addr(),
            to: send_path.peer_addr(),

            at: send_path.recovery.get_packet_send_time(now),
        };

        Ok((done, info))
    }

    pub(crate) fn send_single(
        &mut self, out: &mut [u8], send_pid: usize, has_initial: bool,
        now: Instant,
    ) -> Result<(Type, usize)> {
        if out.is_empty() {
            return Err(Error::BufferTooShort);
        }

        if self.is_draining() {
            return Err(Error::Done);
        }

        let ctx = SendSingleContext {
            is_closing: self.local_error.is_some(),
            out_len: out.len(),
        };

        let mut b = octets::OctetsMut::with_slice(out);

        let pkt_type = self.write_pkt_type(send_pid)?;

        let max_dgram_len = if !self.dgram_send_queue.is_empty() {
            self.dgram_max_writable_len()
        } else {
            None
        };

        let epoch = pkt_type.to_epoch()?;
        let pkt_space = &mut self.pkt_num_spaces[epoch];
        let crypto_ctx = &mut self.crypto_ctx[epoch];

        let mut should_retransmit_max_streams = false;

        // Process lost frames. There might be several paths having lost frames.
        for (_, p) in self.paths.iter_mut() {
            while let Some(lost) = p.recovery.next_lost_frame(epoch) {
                match lost {
                    frame::Frame::CryptoHeader { offset, length } => {
                        crypto_ctx.crypto_stream.send.retransmit(offset, length);

                        self.stream_retrans_bytes += length as u64;
                        p.stream_retrans_bytes += length as u64;

                        self.retrans_count += 1;
                        p.retrans_count += 1;
                    },

                    frame::Frame::StreamHeader {
                        stream_id,
                        offset,
                        length,
                        fin,
                    } => {
                        let stream = match self.streams.get_mut(stream_id) {
                            // Only retransmit data if the stream is not closed
                            // or stopped.
                            Some(v) if !v.send.is_stopped() => v,

                            // Data on a closed stream will not be retransmitted
                            // or acked after it is declared lost, so update
                            // tx_buffered and qlog.
                            _ => {
                                self.tx_buffered =
                                    self.tx_buffered.saturating_sub(length);

                                qlog_with_type!(QLOG_DATA_MV, self.qlog, q, {
                                    let ev_data = EventData::DataMoved(
                                        qlog::events::quic::DataMoved {
                                            stream_id: Some(stream_id),
                                            offset: Some(offset),
                                            length: Some(length as u64),
                                            from: Some(DataRecipient::Transport),
                                            to: Some(DataRecipient::Dropped),
                                            ..Default::default()
                                        },
                                    );

                                    q.add_event_data_with_instant(ev_data, now)
                                        .ok();
                                });

                                continue;
                            },
                        };

                        let was_flushable = stream.is_flushable();

                        let empty_fin = length == 0 && fin;

                        stream.send.retransmit(offset, length);

                        // If the stream is now flushable push it to the
                        // flushable queue, but only if it wasn't already
                        // queued.
                        //
                        // Consider the stream flushable also when we are
                        // sending a zero-length frame that has the fin flag
                        // set.
                        if (stream.is_flushable() || empty_fin) && !was_flushable
                        {
                            let priority_key = Arc::clone(&stream.priority_key);
                            self.streams.insert_flushable(&priority_key);
                        }

                        self.stream_retrans_bytes += length as u64;
                        p.stream_retrans_bytes += length as u64;

                        self.retrans_count += 1;
                        p.retrans_count += 1;
                    },

                    frame::Frame::ACK { .. } => {
                        pkt_space.ack_elicited = true;
                    },

                    frame::Frame::ResetStream {
                        stream_id,
                        error_code,
                        final_size,
                    } => {
                        self.streams
                            .insert_reset(stream_id, error_code, final_size);
                    },

                    frame::Frame::StopSending {
                        stream_id,
                        error_code,
                    } =>
                    // We only need to retransmit the STOP_SENDING frame if
                    // the stream is still active and not FIN'd. Even if the
                    // packet was lost, if the application has the final
                    // size at this point there is no need to retransmit.
                        if let Some(stream) = self.streams.get(stream_id) {
                            if !stream.recv.is_fin() {
                                self.streams
                                    .insert_stopped(stream_id, error_code);
                            }
                        },

                    // Retransmit HANDSHAKE_DONE only if it hasn't been acked at
                    // least once already.
                    frame::Frame::HandshakeDone if !self.handshake_done_acked => {
                        self.handshake_done_sent = false;
                    },

                    frame::Frame::MaxStreamData { stream_id, .. } => {
                        if self.streams.get(stream_id).is_some() {
                            self.streams.insert_almost_full(stream_id);
                        }
                    },

                    frame::Frame::MaxData { .. } => {
                        self.should_send_max_data = true;
                    },

                    frame::Frame::MaxStreamsUni { .. } => {
                        should_retransmit_max_streams = true;
                    },

                    frame::Frame::MaxStreamsBidi { .. } => {
                        should_retransmit_max_streams = true;
                    },

                    frame::Frame::NewConnectionId { seq_num, .. } => {
                        self.ids.mark_advertise_new_scid_seq(seq_num, true);
                    },

                    frame::Frame::RetireConnectionId { seq_num } => {
                        self.ids.mark_retire_dcid_seq(seq_num, true)?;
                    },

                    frame::Frame::Ping {
                        mtu_probe: Some(failed_probe),
                    } =>
                        if let Some(pmtud) = p.pmtud.as_mut() {
                            trace!("pmtud probe dropped: {failed_probe}");
                            pmtud.failed_probe(failed_probe);
                        },

                    _ => (),
                }
            }
        }
        self.check_tx_buffered_invariant();

        let is_app_limited = self.delivery_rate_check_if_app_limited();
        let n_paths = self.paths.len();
        let path = self.paths.get_mut(send_pid)?;
        let flow_control = &mut self.flow_control;
        let pkt_space = &mut self.pkt_num_spaces[epoch];
        let crypto_ctx = &mut self.crypto_ctx[epoch];
        let pkt_num_manager = &mut self.pkt_num_manager;

        let mut left = if let Some(pmtud) = path.pmtud.as_mut() {
            // Limit output buffer size by estimated path MTU.
            cmp::min(pmtud.get_current_mtu(), b.cap())
        } else {
            b.cap()
        };

        if pkt_num_manager.should_skip_pn(self.handshake_completed) {
            pkt_num_manager.set_skip_pn(Some(self.next_pkt_num));
            self.next_pkt_num += 1;
        };
        let pn = self.next_pkt_num;

        let largest_acked_pkt =
            path.recovery.get_largest_acked_on_epoch(epoch).unwrap_or(0);
        let pn_len = packet::pkt_num_len(pn, largest_acked_pkt);

        // The AEAD overhead at the current encryption level.
        let crypto_overhead = crypto_ctx.crypto_overhead().ok_or(Error::Done)?;

        let dcid_seq = path.active_dcid_seq.ok_or(Error::OutOfIdentifiers)?;

        let dcid =
            ConnectionId::from_ref(self.ids.get_dcid(dcid_seq)?.cid.as_ref());

        let scid = if let Some(scid_seq) = path.active_scid_seq {
            ConnectionId::from_ref(self.ids.get_scid(scid_seq)?.cid.as_ref())
        } else if pkt_type == Type::Short {
            ConnectionId::default()
        } else {
            return Err(Error::InvalidState);
        };

        let hdr = Header {
            ty: pkt_type,

            version: self.version,

            dcid,
            scid,

            pkt_num: 0,
            pkt_num_len: pn_len,

            // Only clone token for Initial packets, as other packets don't have
            // this field (Retry doesn't count, as it's not encoded as part of
            // this code path).
            token: if pkt_type == Type::Initial {
                self.token.clone()
            } else {
                None
            },

            versions: None,
            key_phase: self.key_phase,
        };

        hdr.to_bytes(&mut b)?;

        let hdr_trace = if log::max_level() == log::LevelFilter::Trace {
            Some(format!("{hdr:?}"))
        } else {
            None
        };

        let hdr_ty = hdr.ty;

        #[cfg(feature = "qlog")]
        let qlog_pkt_hdr = self.qlog.streamer.as_ref().map(|_q| {
            qlog::events::quic::PacketHeader::with_type(
                hdr.ty.to_qlog(),
                Some(pn),
                Some(hdr.version),
                Some(&hdr.scid),
                Some(&hdr.dcid),
            )
        });

        // Calculate the space required for the packet, including the header
        // the payload length, the packet number and the AEAD overhead.
        let mut overhead = b.off() + pn_len + crypto_overhead;

        // We assume that the payload length, which is only present in long
        // header packets, can always be encoded with a 2-byte varint.
        if pkt_type != Type::Short {
            overhead += PAYLOAD_LENGTH_LEN;
        }

        // Make sure we have enough space left for the packet overhead.
        match left.checked_sub(overhead) {
            Some(v) => left = v,

            None => {
                // We can't send more because there isn't enough space available
                // in the output buffer.
                //
                // This usually happens when we try to send a new packet but
                // failed because cwnd is almost full. In such case app_limited
                // is set to false here to make cwnd grow when ACK is received.
                path.recovery.update_app_limited(false);
                return Err(Error::Done);
            },
        }

        // Make sure there is enough space for the minimum payload length.
        if left < PAYLOAD_MIN_LEN {
            path.recovery.update_app_limited(false);
            return Err(Error::Done);
        }

        let mut frames: SmallVec<[frame::Frame; 1]> = SmallVec::new();

        let mut ack_eliciting = false;
        let mut in_flight = false;
        let mut is_pmtud_probe = false;
        let mut has_data = false;

        // Whether or not we should explicitly elicit an ACK via PING frame if we
        // implicitly elicit one otherwise.
        let ack_elicit_required = path.recovery.should_elicit_ack(epoch);

        let header_offset = b.off();

        // Reserve space for payload length in advance. Since we don't yet know
        // what the final length will be, we reserve 2 bytes in all cases.
        //
        // Only long header packets have an explicit length field.
        if pkt_type != Type::Short {
            b.skip(PAYLOAD_LENGTH_LEN)?;
        }

        packet::encode_pkt_num(pn, pn_len, &mut b)?;

        let payload_offset = b.off();

        let cwnd_available =
            path.recovery.cwnd_available().saturating_sub(overhead);

        let left_before_packing_ack_frame = left;

        // Create ACK frame.
        //
        // When we need to explicitly elicit an ACK via PING later, go ahead and
        // generate an ACK (if there's anything to ACK) since we're going to
        // send a packet with PING anyways, even if we haven't received anything
        // ACK eliciting.
        if pkt_space.recv_pkt_need_ack.len() > 0 &&
            (pkt_space.ack_elicited || ack_elicit_required) &&
            (!ctx.is_closing ||
                (pkt_type == Type::Handshake &&
                    self.local_error
                        .as_ref()
                        .is_some_and(|le| le.is_app))) &&
            path.active()
        {
            #[cfg(not(feature = "fuzzing"))]
            let ack_delay = pkt_space.largest_rx_pkt_time.elapsed();

            #[cfg(not(feature = "fuzzing"))]
            let ack_delay = ack_delay.as_micros() as u64 /
                2_u64
                    .pow(self.local_transport_params.ack_delay_exponent as u32);

            // pseudo-random reproducible ack delays when fuzzing
            #[cfg(feature = "fuzzing")]
            let ack_delay = rand::rand_u8() as u64 + 1;

            let frame = frame::Frame::ACK {
                ack_delay,
                ranges: pkt_space.recv_pkt_need_ack.clone(),
                ecn_counts: None, // sending ECN is not supported at this time
            };

            // When a PING frame needs to be sent, avoid sending the ACK if
            // there is not enough cwnd available for both (note that PING
            // frames are always 1 byte, so we just need to check that the
            // ACK's length is lower than cwnd).
            if pkt_space.ack_elicited || frame.wire_len() < cwnd_available {
                // ACK-only packets are not congestion controlled so ACKs must
                // be bundled considering the buffer capacity only, and not the
                // available cwnd.
                if push_frame_to_pkt!(b, frames, frame, left) {
                    pkt_space.ack_elicited = false;
                }
            }
        }

        // Limit output packet size by congestion window size.
        left = cmp::min(
            left,
            // Bytes consumed by ACK frames.
            cwnd_available.saturating_sub(left_before_packing_ack_frame - left),
        );

        let mut challenge_data = None;

        if pkt_type == Type::Short {
            // Create PMTUD probe.
            //
            // In order to send a PMTUD probe the current `left` value, which was
            // already limited by the current PMTU measure, needs to be ignored,
            // but the outgoing packet still needs to be limited by
            // the output buffer size, as well as the congestion
            // window.
            //
            // In addition, the PMTUD probe is only generated when the handshake
            // is confirmed, to avoid interfering with the handshake
            // (e.g. due to the anti-amplification limits).
            //
            // self.bla(
            //     &ctx,
            //     &mut b,
            //     &mut frames,
            //     &mut left,
            //     overhead,
            //     &mut ack_eliciting,
            //     &mut in_flight,
            //     &mut is_pmtud_probe,
            // );
            if let Ok(active_path) = self.paths.get_active_mut() {
                let should_probe_pmtu = active_path.should_send_pmtu_probe(
                    self.handshake_confirmed,
                    self.handshake_completed,
                    ctx.out_len,
                    ctx.is_closing,
                    frames.is_empty(),
                );

                if should_probe_pmtu {
                    if let Some(pmtud) = active_path.pmtud.as_mut() {
                        let probe_size = pmtud.get_probe_size();
                        trace!(
                        "{} sending pmtud probe pmtu_probe={} estimated_pmtu={}",
                        self.trace_id,
                        probe_size,
                        pmtud.get_current_mtu(),
                    );

                        left = probe_size;

                        match left.checked_sub(overhead) {
                            Some(v) => left = v,

                            None => {
                                // We can't send more because there isn't enough
                                // space available
                                // in the output buffer.
                                //
                                // This usually happens when we try to send a new
                                // packet but failed
                                // because cwnd is almost full.
                                //
                                // In such case app_limited is set to false here
                                // to
                                // make cwnd grow when ACK
                                // is received.
                                active_path.recovery.update_app_limited(false);
                                return Err(Error::Done);
                            },
                        }

                        let frame = frame::Frame::Padding {
                            len: probe_size - overhead - 1,
                        };

                        if push_frame_to_pkt!(b, frames, frame, left) {
                            let frame = frame::Frame::Ping {
                                mtu_probe: Some(probe_size),
                            };

                            if push_frame_to_pkt!(b, frames, frame, left) {
                                ack_eliciting = true;
                                in_flight = true;
                            }
                        }

                        // Reset probe flag after sending to prevent duplicate
                        // probes in a single flight.
                        pmtud.set_in_flight(true);
                        is_pmtud_probe = true;
                    }
                }
            }

            let path = self.paths.get_mut(send_pid)?;
            // Create PATH_RESPONSE frame if needed.
            // We do not try to ensure that these are really sent.
            while let Some(challenge) = path.pop_received_challenge() {
                let frame = frame::Frame::PathResponse { data: challenge };

                if push_frame_to_pkt!(b, frames, frame, left) {
                    ack_eliciting = true;
                    in_flight = true;
                } else {
                    // If there are other pending PATH_RESPONSE, don't lose them
                    // now.
                    break;
                }
            }

            // Create PATH_CHALLENGE frame if needed.
            if path.validation_requested() {
                // TODO: ensure that data is unique over paths.
                let data = rand::rand_u64().to_be_bytes();

                let frame = frame::Frame::PathChallenge { data };

                if push_frame_to_pkt!(b, frames, frame, left) {
                    // Let's notify the path once we know the packet size.
                    challenge_data = Some(data);

                    ack_eliciting = true;
                    in_flight = true;
                }
            }

            if let Some(key_update) = crypto_ctx.key_update.as_mut() {
                key_update.update_acked = true;
            }
        }

        let path = self.paths.get_mut(send_pid)?;

        if pkt_type == Type::Short && !ctx.is_closing {
            // Create NEW_CONNECTION_ID frames as needed.
            while let Some(seq_num) = self.ids.next_advertise_new_scid_seq() {
                let frame = self.ids.get_new_connection_id_frame_for(seq_num)?;

                if push_frame_to_pkt!(b, frames, frame, left) {
                    self.ids.mark_advertise_new_scid_seq(seq_num, false);

                    ack_eliciting = true;
                    in_flight = true;
                } else {
                    break;
                }
            }
        }

        if pkt_type == Type::Short && !ctx.is_closing && path.active() {
            // Create HANDSHAKE_DONE frame.
            // self.should_send_handshake_done() but without the need to borrow
            if self.handshake_completed &&
                !self.handshake_done_sent &&
                self.is_server
            {
                let frame = frame::Frame::HandshakeDone;

                if push_frame_to_pkt!(b, frames, frame, left) {
                    self.handshake_done_sent = true;

                    ack_eliciting = true;
                    in_flight = true;
                }
            }

            // Create MAX_STREAMS_BIDI frame.
            if self.streams.should_update_max_streams_bidi() ||
                should_retransmit_max_streams
            {
                let frame = frame::Frame::MaxStreamsBidi {
                    max: self.streams.max_streams_bidi_next(),
                };

                if push_frame_to_pkt!(b, frames, frame, left) {
                    self.streams.update_max_streams_bidi();

                    ack_eliciting = true;
                    in_flight = true;
                }
            }

            // Create MAX_STREAMS_UNI frame.
            if self.streams.should_update_max_streams_uni() ||
                should_retransmit_max_streams
            {
                let frame = frame::Frame::MaxStreamsUni {
                    max: self.streams.max_streams_uni_next(),
                };

                if push_frame_to_pkt!(b, frames, frame, left) {
                    self.streams.update_max_streams_uni();

                    ack_eliciting = true;
                    in_flight = true;
                }
            }

            // Create DATA_BLOCKED frame.
            if let Some(limit) = self.blocked_limit {
                let frame = frame::Frame::DataBlocked { limit };

                if push_frame_to_pkt!(b, frames, frame, left) {
                    self.blocked_limit = None;
                    self.data_blocked_sent_count =
                        self.data_blocked_sent_count.saturating_add(1);

                    ack_eliciting = true;
                    in_flight = true;
                }
            }

            // Create MAX_STREAM_DATA frames as needed.
            for stream_id in self.streams.almost_full() {
                let stream = match self.streams.get_mut(stream_id) {
                    Some(v) => v,

                    None => {
                        // The stream doesn't exist anymore, so remove it from
                        // the almost full set.
                        self.streams.remove_almost_full(stream_id);
                        continue;
                    },
                };

                // Autotune the stream window size, but only if this is not a
                // retransmission (on a retransmit the stream will be in
                // `self.streams.almost_full()` but it's `almost_full()`
                // method returns false.
                if stream.recv.almost_full() {
                    stream.recv.autotune_window(now, path.recovery.rtt());
                }

                let frame = frame::Frame::MaxStreamData {
                    stream_id,
                    max: stream.recv.max_data_next(),
                };

                if push_frame_to_pkt!(b, frames, frame, left) {
                    let recv_win = stream.recv.window();

                    stream.recv.update_max_data(now);

                    self.streams.remove_almost_full(stream_id);

                    ack_eliciting = true;
                    in_flight = true;

                    // Make sure the connection window always has some
                    // room compared to the stream window.
                    flow_control.ensure_window_lower_bound(
                        (recv_win as f64 * CONNECTION_WINDOW_FACTOR) as u64,
                    );
                }
            }

            // Create MAX_DATA frame as needed.
            if flow_control.should_update_max_data() &&
                flow_control.max_data() < flow_control.max_data_next()
            {
                // Autotune the connection window size. We only tune the window
                // if we are sending an "organic" update, not on retransmits.
                flow_control.autotune_window(now, path.recovery.rtt());
                self.should_send_max_data = true;
            }

            if self.should_send_max_data {
                let frame = frame::Frame::MaxData {
                    max: flow_control.max_data_next(),
                };

                if push_frame_to_pkt!(b, frames, frame, left) {
                    self.should_send_max_data = false;

                    // Commits the new max_rx_data limit.
                    flow_control.update_max_data(now);

                    ack_eliciting = true;
                    in_flight = true;
                }
            }

            // Create STOP_SENDING frames as needed.
            for (stream_id, error_code) in self
                .streams
                .stopped()
                .map(|(&k, &v)| (k, v))
                .collect::<Vec<(u64, u64)>>()
            {
                let frame = frame::Frame::StopSending {
                    stream_id,
                    error_code,
                };

                if push_frame_to_pkt!(b, frames, frame, left) {
                    self.streams.remove_stopped(stream_id);

                    ack_eliciting = true;
                    in_flight = true;
                }
            }

            // Create RESET_STREAM frames as needed.
            for (stream_id, (error_code, final_size)) in self
                .streams
                .reset()
                .map(|(&k, &v)| (k, v))
                .collect::<Vec<(u64, (u64, u64))>>()
            {
                let frame = frame::Frame::ResetStream {
                    stream_id,
                    error_code,
                    final_size,
                };

                if push_frame_to_pkt!(b, frames, frame, left) {
                    self.streams.remove_reset(stream_id);

                    ack_eliciting = true;
                    in_flight = true;
                }
            }

            // Create STREAM_DATA_BLOCKED frames as needed.
            for (stream_id, limit) in self
                .streams
                .blocked()
                .map(|(&k, &v)| (k, v))
                .collect::<Vec<(u64, u64)>>()
            {
                let frame = frame::Frame::StreamDataBlocked { stream_id, limit };

                if push_frame_to_pkt!(b, frames, frame, left) {
                    self.streams.remove_blocked(stream_id);
                    self.stream_data_blocked_sent_count =
                        self.stream_data_blocked_sent_count.saturating_add(1);

                    ack_eliciting = true;
                    in_flight = true;
                }
            }

            // Create RETIRE_CONNECTION_ID frames as needed.
            let retire_dcid_seqs = self.ids.retire_dcid_seqs();

            for seq_num in retire_dcid_seqs {
                // The sequence number specified in a RETIRE_CONNECTION_ID frame
                // MUST NOT refer to the Destination Connection ID field of the
                // packet in which the frame is contained.
                let dcid_seq = path.active_dcid_seq.ok_or(Error::InvalidState)?;

                if seq_num == dcid_seq {
                    continue;
                }

                let frame = frame::Frame::RetireConnectionId { seq_num };

                if push_frame_to_pkt!(b, frames, frame, left) {
                    self.ids.mark_retire_dcid_seq(seq_num, false)?;

                    ack_eliciting = true;
                    in_flight = true;
                } else {
                    break;
                }
            }
        }

        // Create CONNECTION_CLOSE frame. Try to send this only on the active
        // path, unless it is the last one available.
        if path.active() || n_paths == 1 {
            if let Some(conn_err) = self.local_error.as_ref() {
                if conn_err.is_app {
                    // Create ApplicationClose frame.
                    if pkt_type == Type::Short {
                        let frame = frame::Frame::ApplicationClose {
                            error_code: conn_err.error_code,
                            reason: conn_err.reason.clone(),
                        };

                        if push_frame_to_pkt!(b, frames, frame, left) {
                            let pto = path.recovery.pto();
                            self.draining_timer = Some(now + (pto * 3));

                            ack_eliciting = true;
                            in_flight = true;
                        }
                    }
                } else {
                    // Create ConnectionClose frame.
                    let frame = frame::Frame::ConnectionClose {
                        error_code: conn_err.error_code,
                        frame_type: 0,
                        reason: conn_err.reason.clone(),
                    };

                    if push_frame_to_pkt!(b, frames, frame, left) {
                        let pto = path.recovery.pto();
                        self.draining_timer = Some(now + (pto * 3));

                        ack_eliciting = true;
                        in_flight = true;
                    }
                }
            }
        }

        // Create CRYPTO frame.
        if crypto_ctx.crypto_stream.is_flushable() &&
            left > frame::MAX_CRYPTO_OVERHEAD &&
            !ctx.is_closing &&
            path.active()
        {
            let crypto_off = crypto_ctx.crypto_stream.send.off_front();

            // Encode the frame.
            //
            // Instead of creating a `frame::Frame` object, encode the frame
            // directly into the packet buffer.
            //
            // First we reserve some space in the output buffer for writing the
            // frame header (we assume the length field is always a 2-byte
            // varint as we don't know the value yet).
            //
            // Then we emit the data from the crypto stream's send buffer.
            //
            // Finally we go back and encode the frame header with the now
            // available information.
            let hdr_off = b.off();
            let hdr_len = 1 + // frame type
                octets::varint_len(crypto_off) + // offset
                2; // length, always encode as 2-byte varint

            if let Some(max_len) = left.checked_sub(hdr_len) {
                let (mut crypto_hdr, mut crypto_payload) =
                    b.split_at(hdr_off + hdr_len)?;

                // Write stream data into the packet buffer.
                let (len, _) = crypto_ctx
                    .crypto_stream
                    .send
                    .emit(&mut crypto_payload.as_mut()[..max_len])?;

                // Encode the frame's header.
                //
                // Due to how `OctetsMut::split_at()` works, `crypto_hdr` starts
                // from the initial offset of `b` (rather than the current
                // offset), so it needs to be advanced to the
                // initial frame offset.
                crypto_hdr.skip(hdr_off)?;

                frame::encode_crypto_header(
                    crypto_off,
                    len as u64,
                    &mut crypto_hdr,
                )?;

                // Advance the packet buffer's offset.
                b.skip(hdr_len + len)?;

                let frame = frame::Frame::CryptoHeader {
                    offset: crypto_off,
                    length: len,
                };

                if push_frame_to_pkt!(b, frames, frame, left) {
                    ack_eliciting = true;
                    in_flight = true;
                    has_data = true;
                }
            }
        }

        // The preference of data-bearing frame to include in a packet
        // is managed by `self.emit_dgram`. However, whether any frames
        // can be sent depends on the state of their buffers. In the case
        // where one type is preferred but its buffer is empty, fall back
        // to the other type in order not to waste this function call.
        let mut dgram_emitted = false;
        let dgrams_to_emit = max_dgram_len.is_some();
        let stream_to_emit = self.streams.has_flushable();

        let mut do_dgram = self.emit_dgram && dgrams_to_emit;
        let do_stream = !self.emit_dgram && stream_to_emit;

        if !do_stream && dgrams_to_emit {
            do_dgram = true;
        }

        // Create DATAGRAM frame.
        if (pkt_type == Type::Short || pkt_type == Type::ZeroRTT) &&
            left > frame::MAX_DGRAM_OVERHEAD &&
            !ctx.is_closing &&
            path.active() &&
            do_dgram
        {
            if let Some(max_dgram_payload) = max_dgram_len {
                while let Some(len) = self.dgram_send_queue.peek_front_len() {
                    let hdr_off = b.off();
                    let hdr_len = 1 + // frame type
                        2; // length, always encode as 2-byte varint

                    if (hdr_len + len) <= left {
                        // Front of the queue fits this packet, send it.
                        match self.dgram_send_queue.pop() {
                            Some(data) => {
                                // Encode the frame.
                                //
                                // Instead of creating a `frame::Frame` object,
                                // encode the frame directly into the packet
                                // buffer.
                                //
                                // First we reserve some space in the output
                                // buffer for writing the frame header (we
                                // assume the length field is always a 2-byte
                                // varint as we don't know the value yet).
                                //
                                // Then we emit the data from the DATAGRAM's
                                // buffer.
                                //
                                // Finally we go back and encode the frame
                                // header with the now available information.
                                let (mut dgram_hdr, mut dgram_payload) =
                                    b.split_at(hdr_off + hdr_len)?;

                                dgram_payload.as_mut()[..len]
                                    .copy_from_slice(&data);

                                // Encode the frame's header.
                                //
                                // Due to how `OctetsMut::split_at()` works,
                                // `dgram_hdr` starts from the initial offset
                                // of `b` (rather than the current offset), so
                                // it needs to be advanced to the initial frame
                                // offset.
                                dgram_hdr.skip(hdr_off)?;

                                frame::encode_dgram_header(
                                    len as u64,
                                    &mut dgram_hdr,
                                )?;

                                // Advance the packet buffer's offset.
                                b.skip(hdr_len + len)?;

                                let frame =
                                    frame::Frame::DatagramHeader { length: len };

                                if push_frame_to_pkt!(b, frames, frame, left) {
                                    ack_eliciting = true;
                                    in_flight = true;
                                    dgram_emitted = true;
                                    self.dgram_sent_count =
                                        self.dgram_sent_count.saturating_add(1);
                                    path.dgram_sent_count =
                                        path.dgram_sent_count.saturating_add(1);
                                }
                            },

                            None => continue,
                        };
                    } else if len > max_dgram_payload {
                        // This dgram frame will never fit. Let's purge it.
                        self.dgram_send_queue.pop();
                    } else {
                        break;
                    }
                }
            }
        }

        // Create a single STREAM frame for the first stream that is flushable.
        if (pkt_type == Type::Short || pkt_type == Type::ZeroRTT) &&
            left > frame::MAX_STREAM_OVERHEAD &&
            !ctx.is_closing &&
            path.active() &&
            !dgram_emitted
        {
            while let Some(priority_key) = self.streams.peek_flushable() {
                let stream_id = priority_key.id;
                let stream = match self.streams.get_mut(stream_id) {
                    // Avoid sending frames for streams that were already stopped.
                    //
                    // This might happen if stream data was buffered but not yet
                    // flushed on the wire when a STOP_SENDING frame is received.
                    Some(v) if !v.send.is_stopped() => v,
                    _ => {
                        self.streams.remove_flushable(&priority_key);
                        continue;
                    },
                };

                let stream_off = stream.send.off_front();

                // Encode the frame.
                //
                // Instead of creating a `frame::Frame` object, encode the frame
                // directly into the packet buffer.
                //
                // First we reserve some space in the output buffer for writing
                // the frame header (we assume the length field is always a
                // 2-byte varint as we don't know the value yet).
                //
                // Then we emit the data from the stream's send buffer.
                //
                // Finally we go back and encode the frame header with the now
                // available information.
                let hdr_off = b.off();
                let hdr_len = 1 + // frame type
                    octets::varint_len(stream_id) + // stream_id
                    octets::varint_len(stream_off) + // offset
                    2; // length, always encode as 2-byte varint

                let max_len = match left.checked_sub(hdr_len) {
                    Some(v) => v,
                    None => {
                        let priority_key = Arc::clone(&stream.priority_key);
                        self.streams.remove_flushable(&priority_key);

                        continue;
                    },
                };

                let (mut stream_hdr, mut stream_payload) =
                    b.split_at(hdr_off + hdr_len)?;

                // Write stream data into the packet buffer.
                let (len, fin) =
                    stream.send.emit(&mut stream_payload.as_mut()[..max_len])?;

                // Encode the frame's header.
                //
                // Due to how `OctetsMut::split_at()` works, `stream_hdr` starts
                // from the initial offset of `b` (rather than the current
                // offset), so it needs to be advanced to the initial frame
                // offset.
                stream_hdr.skip(hdr_off)?;

                frame::encode_stream_header(
                    stream_id,
                    stream_off,
                    len as u64,
                    fin,
                    &mut stream_hdr,
                )?;

                // Advance the packet buffer's offset.
                b.skip(hdr_len + len)?;

                let frame = frame::Frame::StreamHeader {
                    stream_id,
                    offset: stream_off,
                    length: len,
                    fin,
                };

                if push_frame_to_pkt!(b, frames, frame, left) {
                    ack_eliciting = true;
                    in_flight = true;
                    has_data = true;
                }

                let priority_key = Arc::clone(&stream.priority_key);
                // If the stream is no longer flushable, remove it from the queue
                if !stream.is_flushable() {
                    self.streams.remove_flushable(&priority_key);
                } else if stream.incremental {
                    // Shuffle the incremental stream to the back of the
                    // queue.
                    self.streams.remove_flushable(&priority_key);
                    self.streams.insert_flushable(&priority_key);
                }

                #[cfg(feature = "fuzzing")]
                // Coalesce STREAM frames when fuzzing.
                if left > frame::MAX_STREAM_OVERHEAD {
                    continue;
                }

                break;
            }
        }

        // Alternate trying to send DATAGRAMs next time.
        self.emit_dgram = !dgram_emitted;

        // If no other ack-eliciting frame is sent, include a PING frame
        // - if PTO probe needed; OR
        // - if we've sent too many non ack-eliciting packets without having
        // sent an ACK eliciting one; OR
        // - the application requested an ack-eliciting frame be sent.
        if (ack_elicit_required || path.needs_ack_eliciting) &&
            !ack_eliciting &&
            left >= 1 &&
            !ctx.is_closing
        {
            let frame = frame::Frame::Ping { mtu_probe: None };

            if push_frame_to_pkt!(b, frames, frame, left) {
                ack_eliciting = true;
                in_flight = true;
            }
        }

        if ack_eliciting && !is_pmtud_probe {
            path.needs_ack_eliciting = false;
            path.recovery.ping_sent(epoch);
        }

        if !has_data &&
            !dgram_emitted &&
            cwnd_available > frame::MAX_STREAM_OVERHEAD
        {
            path.recovery.on_app_limited();
        }

        if frames.is_empty() {
            // When we reach this point we are not able to write more, so set
            // app_limited to false.
            path.recovery.update_app_limited(false);
            return Err(Error::Done);
        }

        // When coalescing a 1-RTT packet, we can't add padding in the UDP
        // datagram, so use PADDING frames instead.
        //
        // This is only needed if
        // 1) an Initial packet has already been written to the UDP datagram,
        // as Initial always requires padding.
        //
        // 2) this is a probing packet towards an unvalidated peer address.
        if (has_initial || !path.validated()) &&
            pkt_type == Type::Short &&
            left >= 1
        {
            let frame = frame::Frame::Padding { len: left };

            if push_frame_to_pkt!(b, frames, frame, left) {
                in_flight = true;
            }
        }

        // Pad payload so that it's always at least 4 bytes.
        if b.off() - payload_offset < PAYLOAD_MIN_LEN {
            let payload_len = b.off() - payload_offset;

            let frame = frame::Frame::Padding {
                len: PAYLOAD_MIN_LEN - payload_len,
            };

            #[allow(unused_assignments)]
            if push_frame_to_pkt!(b, frames, frame, left) {
                in_flight = true;
            }
        }

        let payload_len = b.off() - payload_offset;

        // Fill in payload length.
        if pkt_type != Type::Short {
            let len = pn_len + payload_len + crypto_overhead;

            let (_, mut payload_with_len) = b.split_at(header_offset)?;
            payload_with_len
                .put_varint_with_len(len as u64, PAYLOAD_LENGTH_LEN)?;
        }

        trace!(
            "{} tx pkt {} len={} pn={} {}",
            self.trace_id,
            hdr_trace.unwrap_or_default(),
            payload_len,
            pn,
            AddrTupleFmt(path.local_addr(), path.peer_addr())
        );

        #[cfg(feature = "qlog")]
        let mut qlog_frames: SmallVec<
            [qlog::events::quic::QuicFrame; 1],
        > = SmallVec::with_capacity(frames.len());

        for frame in &mut frames {
            trace!("{} tx frm {:?}", self.trace_id, frame);

            qlog_with_type!(QLOG_PACKET_TX, self.qlog, _q, {
                qlog_frames.push(frame.to_qlog());
            });
        }

        qlog_with_type!(QLOG_PACKET_TX, self.qlog, q, {
            if let Some(header) = qlog_pkt_hdr {
                // Qlog packet raw info described at
                // https://datatracker.ietf.org/doc/html/draft-ietf-quic-qlog-main-schema-00#section-5.1
                //
                // `length` includes packet headers and trailers (AEAD tag).
                let length = payload_len + payload_offset + crypto_overhead;
                let qlog_raw_info = RawInfo {
                    length: Some(length as u64),
                    payload_length: Some(payload_len as u64),
                    data: None,
                };

                let send_at_time =
                    now.duration_since(q.start_time()).as_secs_f32() * 1000.0;

                let ev_data =
                    EventData::PacketSent(qlog::events::quic::PacketSent {
                        header,
                        frames: Some(qlog_frames),
                        raw: Some(qlog_raw_info),
                        send_at_time: Some(send_at_time),
                        ..Default::default()
                    });

                q.add_event_data_with_instant(ev_data, now).ok();
            }
        });

        let aead = match crypto_ctx.crypto_seal {
            Some(ref v) => v,
            None => return Err(Error::InvalidState),
        };

        let written = packet::encrypt_pkt(
            &mut b,
            pn,
            pn_len,
            payload_len,
            payload_offset,
            None,
            aead,
        )?;

        let sent_pkt_has_data = if path.recovery.gcongestion_enabled() {
            has_data || dgram_emitted
        } else {
            has_data
        };

        let sent_pkt = recovery::Sent {
            pkt_num: pn,
            frames,
            time_sent: now,
            time_acked: None,
            time_lost: None,
            size: if ack_eliciting { written } else { 0 },
            ack_eliciting,
            in_flight,
            delivered: 0,
            delivered_time: now,
            first_sent_time: now,
            is_app_limited: false,
            tx_in_flight: 0,
            lost: 0,
            has_data: sent_pkt_has_data,
            is_pmtud_probe,
        };

        if in_flight && is_app_limited {
            path.recovery.delivery_rate_update_app_limited(true);
        }

        self.next_pkt_num += 1;

        let handshake_status = recovery::HandshakeStatus {
            has_handshake_keys: self.crypto_ctx[packet::Epoch::Handshake]
                .has_keys(),
            peer_verified_address: self.peer_verified_initial_address,
            completed: self.handshake_completed,
        };

        self.on_packet_sent(send_pid, sent_pkt, epoch, handshake_status, now)?;

        let path = self.paths.get_mut(send_pid)?;
        qlog_with_type!(QLOG_METRICS, self.qlog, q, {
            path.recovery.maybe_qlog(q, now);
        });

        // Record sent packet size if we probe the path.
        if let Some(data) = challenge_data {
            path.add_challenge_sent(data, written, now);
        }

        self.sent_count += 1;
        self.sent_bytes += written as u64;
        path.sent_count += 1;
        path.sent_bytes += written as u64;

        if self.dgram_send_queue.byte_size() > path.recovery.cwnd_available() {
            path.recovery.update_app_limited(false);
        }

        path.max_send_bytes = path.max_send_bytes.saturating_sub(written);

        // On the client, drop initial state after sending an Handshake packet.
        if !self.is_server && hdr_ty == Type::Handshake {
            self.drop_epoch_state(packet::Epoch::Initial, now);
        }

        // (Re)start the idle timer if we are sending the first ack-eliciting
        // packet since last receiving a packet.
        if ack_eliciting && !self.ack_eliciting_sent {
            if let Some(idle_timeout) = self.idle_timeout() {
                self.idle_timer = Some(now + idle_timeout);
            }
        }

        if ack_eliciting {
            self.ack_eliciting_sent = true;
        }

        Ok((pkt_type, written))
    }

    // fn bla(
    //     &mut self, ctx: &SendSingleContext, mut b: &mut octets::OctetsMut,
    //     frames: &mut SmallVec<[frame::Frame; 1]>, left: &mut usize,
    //     overhead: usize, ack_eliciting: &mut bool, in_flight: &mut bool,
    //     is_pmtud_probe: &mut bool,
    // ) -> Result<()> {
    //     if let Ok(active_path) = self.paths.get_active_mut() {
    //         let should_probe_pmtu = active_path.should_send_pmtu_probe(
    //             self.handshake_confirmed,
    //             self.handshake_completed,
    //             ctx.out_len,
    //             ctx.is_closing,
    //             frames.is_empty(),
    //         );
    //
    //         if should_probe_pmtu {
    //             if let Some(pmtud) = active_path.pmtud.as_mut() {
    //                 let probe_size = pmtud.get_probe_size();
    //                 trace!(
    //                     "{} sending pmtud probe pmtu_probe={}
    // estimated_pmtu={}",                     self.trace_id,
    //                     probe_size,
    //                     pmtud.get_current_mtu(),
    //                 );
    //
    //                 *left = probe_size;
    //
    //                 match left.checked_sub(overhead) {
    //                     Some(v) => *left = v,
    //
    //                     None => {
    //                         // We can't send more because there isn't enough
    //                         // space available
    //                         // in the output buffer.
    //                         //
    //                         // This usually happens when we try to send a new
    //                         // packet but failed
    //                         // because cwnd is almost full.
    //                         //
    //                         // In such case app_limited is set to false here
    //                         // to
    //                         // make cwnd grow when ACK
    //                         // is received.
    //                         active_path.recovery.update_app_limited(false);
    //                         return Err(Error::Done);
    //                     },
    //                 }
    //
    //                 let frame = frame::Frame::Padding {
    //                     len: probe_size - overhead - 1,
    //                 };
    //
    //                 if push_frame_to_pkt!(b, frames, frame, *left) {
    //                     let frame = frame::Frame::Ping {
    //                         mtu_probe: Some(probe_size),
    //                     };
    //
    //                     if push_frame_to_pkt!(b, frames, frame, *left) {
    //                         *ack_eliciting = true;
    //                         *in_flight = true;
    //                     }
    //                 }
    //
    //                 // Reset probe flag after sending to prevent duplicate
    //                 // probes in a single flight.
    //                 pmtud.set_in_flight(true);
    //                 *is_pmtud_probe = true;
    //             }
    //         }
    //     }
    //
    //     Ok(())
    // }
}
