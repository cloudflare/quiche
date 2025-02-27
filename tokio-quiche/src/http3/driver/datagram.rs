// Copyright (C) 2025, Cloudflare, Inc.
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

use super::InboundFrame;
use crate::buf_factory::BufFactory;
use crate::buf_factory::PooledDgram;
use crate::quic::QuicheConnection;
use quiche::h3::NameValue;
use quiche::h3::{
    self,
};

/// Extracts the DATAGRAM flow ID proxied over the given `stream_id`,
/// or `None` if this is not a proxy request.
pub(crate) fn extract_flow_id(
    stream_id: u64, headers: &[h3::Header],
) -> Option<u64> {
    let mut method = None;
    let mut datagram_flow_id: Option<u64> = None;
    let mut protocol = None;

    for header in headers {
        match header.name() {
            b":method" => method = Some(header.value()),
            b":protocol" => protocol = Some(header.value()),
            b"datagram-flow-id" =>
                datagram_flow_id = std::str::from_utf8(header.value())
                    .ok()
                    .and_then(|v| v.parse().ok()),
            _ => {},
        };

        // We have all of the information needed to get a flow_id or
        // quarter_stream_id
        if method.is_some() && (datagram_flow_id.is_some() || protocol.is_some())
        {
            break;
        }
    }

    // draft-ietf-masque-connect-udp-03 CONNECT-UDP
    if method == Some(b"CONNECT-UDP") && datagram_flow_id.is_some() {
        datagram_flow_id
    // RFC 9298 CONNECT-UDP
    } else if method == Some(b"CONNECT") && protocol.is_some() {
        // we use the quarter_stream_id for RFC 9297
        // https://www.rfc-editor.org/rfc/rfc9297.html#name-http-3-datagrams
        Some(stream_id / 4)
    } else {
        None
    }
}

/// Sends an HTTP/3 datagram over the QUIC connection with the given `flow_id`.
pub(crate) fn send_h3_dgram(
    conn: &mut QuicheConnection, flow_id: u64, mut dgram: PooledDgram,
) -> quiche::Result<()> {
    let mut prefix = [0u8; 8];
    let mut buf = octets::OctetsMut::with_slice(&mut prefix);
    let flow_id = buf.put_varint(flow_id)?;

    if dgram.add_prefix(flow_id) {
        conn.dgram_send(&dgram)
    } else {
        let mut inner = dgram.into_inner().into_vec();
        inner.splice(..0, flow_id.iter().copied());
        conn.dgram_send_vec(inner)
    }
}

/// Reads the next HTTP/3 datagram from the QUIC connection.
///
/// [`quiche::Error::Done`] is returned if there is no datagram to read.
pub(crate) fn receive_h3_dgram(
    conn: &mut QuicheConnection,
) -> quiche::Result<(u64, InboundFrame)> {
    let dgram = conn.dgram_recv_vec()?;
    let mut buf = octets::Octets::with_slice(&dgram);
    let flow_id = buf.get_varint()?;
    let advance = buf.off();
    let datagram =
        InboundFrame::Datagram(BufFactory::dgram_from_slice(&dgram[advance..]));

    Ok((flow_id, datagram))
}
