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

/// Returns `true` if the headers indicate a Capsule Protocol violation:
///
/// - RFC 9297 §3.2: capsule-protocol with Content-Length, Content-Type,
///   or Transfer-Encoding.
/// - RFC 9297 §3.2: capsule-protocol on a response with status 204, 205,
///   or 206.
/// - RFC 9297 §3.4: capsule-protocol on a response with status outside
///   2xx and != 101.
pub(crate) fn has_capsule_header_conflict(headers: &[h3::Header]) -> bool {
    let mut has_capsule_protocol = false;
    let mut capsule_protocol_count = 0u32;
    let mut has_forbidden_header = false;
    let mut status: Option<&[u8]> = None;

    for header in headers {
        match header.name() {
            b"capsule-protocol" => {
                capsule_protocol_count += 1;
                has_capsule_protocol = header
                    .value()
                    .split(|&b| b == b';')
                    .next()
                    == Some(b"?1" as &[u8]);
            },
            b"content-length" | b"content-type" | b"transfer-encoding" => {
                has_forbidden_header = true;
            },
            b":status" => {
                status = Some(header.value());
            },
            _ => {},
        }
    }

    // RFC 9297 §3.4: capsule-protocol is an Item structured field.
    // Duplicate header fields MUST be treated as if the field were absent.
    if !has_capsule_protocol || capsule_protocol_count > 1 {
        return false;
    }

    // §3.2: capsule-protocol conflicts with content headers.
    if has_forbidden_header {
        return true;
    }

    // Response-only checks (presence of :status means this is a response).
    if let Some(status) = status {
        // §3.2: 204, 205, 206 MUST NOT use Capsule Protocol.
        if status == b"204" || status == b"205" || status == b"206" {
            return true;
        }

        // §3.4: capsule-protocol MUST NOT be used on responses outside
        // 2xx and != 101.
        if status != b"101" && !status.starts_with(b"2") {
            return true;
        }
    }

    false
}

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

/// The maximum valid Quarter Stream ID value per RFC 9297 Section 2.1.
/// Quarter Stream IDs larger than 2^60-1 are invalid.
const MAX_QUARTER_STREAM_ID: u64 = (1u64 << 60) - 1;

/// Reads the next HTTP/3 datagram from the QUIC connection.
///
/// [`quiche::Error::Done`] is returned if there is no datagram to read.
///
/// Returns `quiche::Error::InvalidFrame` if the Quarter Stream ID is
/// malformed or exceeds 2^60-1 (RFC 9297 Section 2.1).
pub(crate) fn receive_h3_dgram(
    conn: &mut QuicheConnection,
) -> quiche::Result<(u64, InboundFrame)> {
    let dgram = conn.dgram_recv_vec()?;
    let mut buf = octets::Octets::with_slice(&dgram);

    // RFC 9297 Section 2.1: payload too short to parse Quarter Stream ID
    // MUST be treated as H3_DATAGRAM_ERROR.
    let flow_id = buf
        .get_varint()
        .map_err(|_| quiche::Error::InvalidFrame)?;

    // RFC 9297 Section 2.1: Quarter Stream ID > 2^60-1 MUST be treated
    // as H3_DATAGRAM_ERROR.
    if flow_id > MAX_QUARTER_STREAM_ID {
        return Err(quiche::Error::InvalidFrame);
    }

    let advance = buf.off();
    let datagram =
        InboundFrame::Datagram(BufFactory::dgram_from_slice(&dgram[advance..]));

    Ok((flow_id, datagram))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn max_quarter_stream_id_value() {
        assert_eq!(MAX_QUARTER_STREAM_ID, (1u64 << 60) - 1);
    }

    #[test]
    fn capsule_header_conflict_content_length() {
        let headers = vec![
            h3::Header::new(b"capsule-protocol", b"?1"),
            h3::Header::new(b"content-length", b"100"),
        ];
        assert!(has_capsule_header_conflict(&headers));
    }

    #[test]
    fn capsule_header_conflict_content_type() {
        let headers = vec![
            h3::Header::new(b"capsule-protocol", b"?1"),
            h3::Header::new(b"content-type", b"application/octet-stream"),
        ];
        assert!(has_capsule_header_conflict(&headers));
    }

    #[test]
    fn capsule_header_conflict_transfer_encoding() {
        let headers = vec![
            h3::Header::new(b"capsule-protocol", b"?1"),
            h3::Header::new(b"transfer-encoding", b"chunked"),
        ];
        assert!(has_capsule_header_conflict(&headers));
    }

    #[test]
    fn no_capsule_header_conflict_without_capsule_protocol() {
        let headers = vec![
            h3::Header::new(b"content-length", b"100"),
        ];
        assert!(!has_capsule_header_conflict(&headers));
    }

    #[test]
    fn no_capsule_header_conflict_capsule_disabled() {
        let headers = vec![
            h3::Header::new(b"capsule-protocol", b"?0"),
            h3::Header::new(b"content-length", b"100"),
        ];
        assert!(!has_capsule_header_conflict(&headers));
    }

    #[test]
    fn no_capsule_header_conflict_clean() {
        let headers = vec![
            h3::Header::new(b"capsule-protocol", b"?1"),
            h3::Header::new(b":method", b"CONNECT"),
        ];
        assert!(!has_capsule_header_conflict(&headers));
    }

    // RFC 9297 §3.4: any value type other than Boolean MUST be handled
    // as if the field were not present by recipients.
    #[test]
    fn no_capsule_header_conflict_non_boolean_value_true() {
        let headers = vec![
            h3::Header::new(b"capsule-protocol", b"true"),
            h3::Header::new(b"content-length", b"100"),
        ];
        // "true" is not a valid SF-Boolean (must be "?1" or "?0"),
        // so capsule-protocol is treated as absent → no conflict.
        assert!(!has_capsule_header_conflict(&headers));
    }

    #[test]
    fn no_capsule_header_conflict_non_boolean_value_one() {
        let headers = vec![
            h3::Header::new(b"capsule-protocol", b"1"),
            h3::Header::new(b"content-length", b"100"),
        ];
        assert!(!has_capsule_header_conflict(&headers));
    }

    #[test]
    fn no_capsule_header_conflict_non_boolean_empty() {
        let headers = vec![
            h3::Header::new(b"capsule-protocol", b""),
            h3::Header::new(b"content-length", b"100"),
        ];
        assert!(!has_capsule_header_conflict(&headers));
    }

    // RFC 9297 §3.2: HTTP status codes 204, 205, 206 MUST NOT be sent
    // on responses that use the Capsule Protocol.
    // A receiver that observes this MUST treat the message as malformed.
    #[test]
    fn capsule_protocol_forbidden_on_204_response() {
        let headers = vec![
            h3::Header::new(b":status", b"204"),
            h3::Header::new(b"capsule-protocol", b"?1"),
        ];
        assert!(has_capsule_header_conflict(&headers));
    }

    #[test]
    fn capsule_protocol_forbidden_on_205_response() {
        let headers = vec![
            h3::Header::new(b":status", b"205"),
            h3::Header::new(b"capsule-protocol", b"?1"),
        ];
        assert!(has_capsule_header_conflict(&headers));
    }

    #[test]
    fn capsule_protocol_forbidden_on_206_response() {
        let headers = vec![
            h3::Header::new(b":status", b"206"),
            h3::Header::new(b"capsule-protocol", b"?1"),
        ];
        assert!(has_capsule_header_conflict(&headers));
    }

    // RFC 9297 §3.4: The capsule-protocol header field MUST NOT be used
    // on HTTP responses with a status code outside 2xx or != 101.
    #[test]
    fn capsule_protocol_forbidden_on_non_2xx_response() {
        let headers = vec![
            h3::Header::new(b":status", b"403"),
            h3::Header::new(b"capsule-protocol", b"?1"),
        ];
        assert!(has_capsule_header_conflict(&headers));
    }

    #[test]
    fn capsule_protocol_allowed_on_200_response() {
        let headers = vec![
            h3::Header::new(b":status", b"200"),
            h3::Header::new(b"capsule-protocol", b"?1"),
        ];
        assert!(!has_capsule_header_conflict(&headers));
    }

    #[test]
    fn capsule_protocol_allowed_on_101_response() {
        let headers = vec![
            h3::Header::new(b":status", b"101"),
            h3::Header::new(b"capsule-protocol", b"?1"),
        ];
        assert!(!has_capsule_header_conflict(&headers));
    }

    // RFC 9297 §3.4 / RFC 8941: unknown parameters after `;` MUST be
    // ignored. `?1;foo=bar` is treated as `?1` (true).
    #[test]
    fn capsule_protocol_with_parameters() {
        let headers = vec![
            h3::Header::new(b"capsule-protocol", b"?1;foo=bar"),
            h3::Header::new(b"content-length", b"100"),
        ];
        assert!(has_capsule_header_conflict(&headers));
    }

    #[test]
    fn capsule_protocol_with_parameters_space() {
        let headers = vec![
            h3::Header::new(b"capsule-protocol", b"?1; foo=bar"),
            h3::Header::new(b"content-length", b"100"),
        ];
        assert!(has_capsule_header_conflict(&headers));
    }

    // RFC 9297 §3.4: capsule-protocol is an Item structured field.
    // Duplicate occurrences MUST be treated as if the field were absent.
    #[test]
    fn no_capsule_header_conflict_duplicate_header() {
        let headers = vec![
            h3::Header::new(b"capsule-protocol", b"?1"),
            h3::Header::new(b"capsule-protocol", b"?1"),
            h3::Header::new(b"content-length", b"100"),
        ];
        // Duplicate capsule-protocol → treated as absent → no conflict.
        assert!(!has_capsule_header_conflict(&headers));
    }
}
