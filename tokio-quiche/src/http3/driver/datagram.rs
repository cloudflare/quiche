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

use datagram_socket::DgramBuffer;
use quiche::h3::NameValue;
use quiche::h3::{
    self,
};

use super::InboundFrame;
use crate::buf_factory::BufFactory;
use crate::quic::QuicheConnection;

/// Extracts the DATAGRAM flow ID proxied over the given `stream_id`,
/// or `None` if this is not a proxy request.
pub(crate) fn extract_quarter_stream_id(
    stream_id: u64, headers: &[h3::Header],
) -> Option<u64> {
    let mut method = None;
    let mut datagram_quarter_stream_id: Option<u64> = None;
    let mut protocol = None;

    for header in headers {
        match header.name() {
            b":method" => method = Some(header.value()),
            b":protocol" => protocol = Some(header.value()),
            b"datagram-flow-id" =>
                datagram_quarter_stream_id = std::str::from_utf8(header.value())
                    .ok()
                    .and_then(|v| v.parse().ok()),
            _ => {},
        };

        // We have all of the information needed to get a quarter_stream_id or
        // quarter_stream_id
        if method.is_some() &&
            (datagram_quarter_stream_id.is_some() || protocol.is_some())
        {
            break;
        }
    }

    // draft-ietf-masque-connect-udp-03 CONNECT-UDP
    if method == Some(b"CONNECT-UDP") && datagram_quarter_stream_id.is_some() {
        datagram_quarter_stream_id
    // RFC 9298 CONNECT-UDP
    } else if method == Some(b"CONNECT") && protocol.is_some() {
        // we use the quarter_stream_id for RFC 9297
        // https://www.rfc-editor.org/rfc/rfc9297.html#name-http-3-datagrams
        Some(stream_id / 4)
    } else {
        None
    }
}

/// Sends an HTTP/3 datagram over the QUIC connection with the given
/// `quarter_stream_id`.
#[inline]
pub(crate) fn send_h3_dgram(
    conn: &mut QuicheConnection, quarter_stream_id: u64, dgram: DgramBuffer,
) -> quiche::Result<()> {
    conn.dgram_send_buf(h3_dgram_add_quarter_stream_id(quarter_stream_id, dgram)?)
}

/// Prepend the `quarter_stream_id` to `dgram`
fn h3_dgram_add_quarter_stream_id(
    quarter_stream_id: u64, mut dgram: DgramBuffer,
) -> quiche::Result<DgramBuffer> {
    let mut prefix_buf = [0u8; 8];
    let mut enc = octets::OctetsMut::with_slice(&mut prefix_buf);
    let prefix = enc.put_varint(quarter_stream_id)?;

    if dgram.try_add_prefix(prefix).is_err() {
        // There wasn't enough room. Let's add more headroom and add the
        // prefix again. DGRAM_HEADROOM is large enough, so
        // try_add_prefix cannot fail after splice_headroom.
        debug_assert!(BufFactory::DGRAM_HEADROOM >= /* max varint len */ 8);
        dgram.splice_headroom(BufFactory::DGRAM_HEADROOM);
        dgram.try_add_prefix(prefix).unwrap();
    }
    Ok(dgram)
}

/// Strips the varint-encoded quarter stream ID from the front of `dgram` and
/// returns `(quarter_stream_id, dgram)` with the cursor advanced past the
/// prefix.
fn h3_dgram_remove_quarter_stream_id(
    mut dgram: DgramBuffer,
) -> quiche::Result<(u64, DgramBuffer)> {
    let quarter_stream_id =
        octets::Octets::with_slice(dgram.as_slice()).get_varint()?;
    let advance = octets::varint_len(quarter_stream_id);
    // Advance the cursor past the varint prefix — zero copy.
    dgram.advance(advance);
    Ok((quarter_stream_id, dgram))
}

/// Reads the next HTTP/3 datagram from the QUIC connection.
///
/// [`quiche::Error::Done`] is returned if there is no datagram to read.
#[inline]
pub(crate) fn receive_h3_dgram(
    conn: &mut QuicheConnection,
) -> quiche::Result<(u64, InboundFrame)> {
    let dgram = conn.dgram_recv_buf()?;
    let (quarter_stream_id, dgram) = h3_dgram_remove_quarter_stream_id(dgram)?;
    Ok((quarter_stream_id, InboundFrame::Datagram(dgram)))
}

#[cfg(test)]
mod tests {
    use bytes::BufMut;
    use datagram_socket::DgramBuffer;

    use super::*;

    #[test]
    fn h3_dgram_add_quarter_stream_id_enough_headroom() {
        let mut dgram = DgramBuffer::with_capacity_and_headroom(16, 8);
        dgram.put_slice(&[0xaa, 0xbb, 0xcc]);

        // 67 requires two bytes to encode
        let result = h3_dgram_add_quarter_stream_id(67, dgram).unwrap();
        assert_eq!(result.as_slice(), &[64, 67, 0xaa, 0xbb, 0xcc]);
    }

    /// When there is no headroom, splice_headroom is invoked automatically.
    #[test]
    fn h3_dgram_add_quarter_stream_id_need_more_headroom() {
        let dgram = DgramBuffer::from_slice(&[1, 2]);

        // 42 requires a single byte for encoding
        let result = h3_dgram_add_quarter_stream_id(42, dgram).unwrap();
        assert_eq!(result.as_slice(), &[42, 1, 2]);
    }

    #[test]
    fn h3_dgram_remove_quarter_stream_id_tests() {
        let dgram = DgramBuffer::from_slice(&[1, 2, 3, 4]);
        let dgram = h3_dgram_add_quarter_stream_id(67, dgram).unwrap();
        let (quarter_stream_id, rest) =
            h3_dgram_remove_quarter_stream_id(dgram).unwrap();

        assert_eq!(quarter_stream_id, 67);
        assert_eq!(rest.as_slice(), &[1, 2, 3, 4]);
    }

    /// remove_quarter_stream_id on an empty buffer returns an error (buffer too
    /// short).
    #[test]
    fn remove_quarter_stream_id_empty_buffer_errors() {
        let dgram = DgramBuffer::new();
        assert!(h3_dgram_remove_quarter_stream_id(dgram).is_err());
    }
}
