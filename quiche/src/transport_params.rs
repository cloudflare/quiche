// Copyright (C) 2018-2025, Cloudflare, Inc.
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

//! Transport parameters handling as per RFC 9000 Section 7.4
//! Part of the Cryptographic and Transport Handshake

use std::collections::HashSet;
use std::mem::size_of;

use crate::ConnectionId;
use crate::Error;
use crate::Result;
use crate::MAX_STREAM_ID;

#[cfg(feature = "qlog")]
use crate::crypto;
#[cfg(feature = "qlog")]
use qlog::events::quic::TransportInitiator;
#[cfg(feature = "qlog")]
use qlog::events::EventData;

/// QUIC Unknown Transport Parameter.
///
/// A QUIC transport parameter that is not specifically recognized
/// by this implementation.
#[derive(Clone, Debug, PartialEq)]
pub struct UnknownTransportParameter<T> {
    /// The ID of the unknown transport parameter.
    pub id: u64,

    /// Original data representing the value of the unknown transport parameter.
    pub value: T,
}

impl<T> UnknownTransportParameter<T> {
    /// Checks whether an unknown Transport Parameter's ID is in the reserved
    /// space.
    ///
    /// See Section 18.1 in [RFC9000](https://datatracker.ietf.org/doc/html/rfc9000#name-reserved-transport-paramete).
    pub fn is_reserved(&self) -> bool {
        let n = (self.id - 27) / 31;
        self.id == 31 * n + 27
    }
}

#[cfg(feature = "qlog")]
impl From<UnknownTransportParameter<Vec<u8>>>
    for qlog::events::quic::UnknownTransportParameter
{
    fn from(value: UnknownTransportParameter<Vec<u8>>) -> Self {
        Self {
            id: value.id,
            value: qlog::HexSlice::maybe_string(Some(value.value.as_slice()))
                .unwrap_or_default(),
        }
    }
}

impl From<UnknownTransportParameter<&[u8]>>
    for UnknownTransportParameter<Vec<u8>>
{
    // When an instance of an UnknownTransportParameter is actually
    // stored in UnknownTransportParameters, then we make a copy
    // of the bytes if the source is an instance of an UnknownTransportParameter
    // whose value is not owned.
    fn from(value: UnknownTransportParameter<&[u8]>) -> Self {
        Self {
            id: value.id,
            value: value.value.to_vec(),
        }
    }
}

/// Track unknown transport parameters, up to a limit.
#[derive(Clone, Debug, PartialEq, Default)]
pub struct UnknownTransportParameters {
    /// The space remaining for storing unknown transport parameters.
    pub capacity: usize,
    /// The unknown transport parameters.
    pub parameters: Vec<UnknownTransportParameter<Vec<u8>>>,
}

impl UnknownTransportParameters {
    /// Pushes an unknown transport parameter into storage if there is space
    /// remaining.
    pub fn push(&mut self, new: UnknownTransportParameter<&[u8]>) -> Result<()> {
        let new_unknown_tp_size = new.value.len() + size_of::<u64>();
        if new_unknown_tp_size < self.capacity {
            self.capacity -= new_unknown_tp_size;
            self.parameters.push(new.into());
            Ok(())
        } else {
            Err(octets::BufferTooShortError.into())
        }
    }
}

/// An Iterator over unknown transport parameters.
pub struct UnknownTransportParameterIterator<'a> {
    index: usize,
    parameters: &'a Vec<UnknownTransportParameter<Vec<u8>>>,
}

impl<'a> IntoIterator for &'a UnknownTransportParameters {
    type IntoIter = UnknownTransportParameterIterator<'a>;
    type Item = &'a UnknownTransportParameter<Vec<u8>>;

    fn into_iter(self) -> Self::IntoIter {
        UnknownTransportParameterIterator {
            index: 0,
            parameters: &self.parameters,
        }
    }
}

impl<'a> Iterator for UnknownTransportParameterIterator<'a> {
    type Item = &'a UnknownTransportParameter<Vec<u8>>;

    fn next(&mut self) -> Option<Self::Item> {
        let result = self.parameters.get(self.index);
        self.index += 1;
        result
    }
}

/// QUIC Transport Parameters
#[derive(Clone, Debug, PartialEq)]
pub struct TransportParams {
    /// Value of Destination CID field from first Initial packet sent by client
    pub original_destination_connection_id: Option<ConnectionId<'static>>,
    /// The maximum idle timeout.
    pub max_idle_timeout: u64,
    /// Token used for verifying stateless resets
    pub stateless_reset_token: Option<u128>,
    /// The maximum UDP payload size.
    pub max_udp_payload_size: u64,
    /// The initial flow control maximum data for the connection.
    pub initial_max_data: u64,
    /// The initial flow control maximum data for local bidirectional streams.
    pub initial_max_stream_data_bidi_local: u64,
    /// The initial flow control maximum data for remote bidirectional streams.
    pub initial_max_stream_data_bidi_remote: u64,
    /// The initial flow control maximum data for unidirectional streams.
    pub initial_max_stream_data_uni: u64,
    /// The initial maximum bidirectional streams.
    pub initial_max_streams_bidi: u64,
    /// The initial maximum unidirectional streams.
    pub initial_max_streams_uni: u64,
    /// The ACK delay exponent.
    pub ack_delay_exponent: u64,
    /// The max ACK delay.
    pub max_ack_delay: u64,
    /// Whether active migration is disabled.
    pub disable_active_migration: bool,
    /// The active connection ID limit.
    pub active_conn_id_limit: u64,
    /// The value that the endpoint included in the Source CID field of a Retry
    /// Packet.
    pub initial_source_connection_id: Option<ConnectionId<'static>>,
    /// The value that the server included in the Source CID field of a Retry
    /// Packet.
    pub retry_source_connection_id: Option<ConnectionId<'static>>,
    /// DATAGRAM frame extension parameter, if any.
    pub max_datagram_frame_size: Option<u64>,
    /// Unknown peer transport parameters and values, if any.
    pub unknown_params: Option<UnknownTransportParameters>,
    // pub preferred_address: ...,
}

impl Default for TransportParams {
    fn default() -> TransportParams {
        TransportParams {
            original_destination_connection_id: None,
            max_idle_timeout: 0,
            stateless_reset_token: None,
            max_udp_payload_size: 65527,
            initial_max_data: 0,
            initial_max_stream_data_bidi_local: 0,
            initial_max_stream_data_bidi_remote: 0,
            initial_max_stream_data_uni: 0,
            initial_max_streams_bidi: 0,
            initial_max_streams_uni: 0,
            ack_delay_exponent: 3,
            max_ack_delay: 25,
            disable_active_migration: false,
            active_conn_id_limit: 2,
            initial_source_connection_id: None,
            retry_source_connection_id: None,
            max_datagram_frame_size: None,
            unknown_params: Default::default(),
        }
    }
}

impl TransportParams {
    pub(crate) fn decode(
        buf: &[u8], is_server: bool, unknown_size: Option<usize>,
    ) -> Result<TransportParams> {
        let mut params = octets::Octets::with_slice(buf);
        let mut seen_params = HashSet::new();

        let mut tp = TransportParams::default();

        if let Some(unknown_transport_param_tracking_size) = unknown_size {
            tp.unknown_params = Some(UnknownTransportParameters {
                capacity: unknown_transport_param_tracking_size,
                parameters: vec![],
            });
        }

        while params.cap() > 0 {
            let id = params.get_varint()?;

            if seen_params.contains(&id) {
                return Err(Error::InvalidTransportParam);
            }
            seen_params.insert(id);

            let mut val = params.get_bytes_with_varint_length()?;

            match id {
                0x0000 => {
                    if is_server {
                        return Err(Error::InvalidTransportParam);
                    }

                    tp.original_destination_connection_id =
                        Some(val.to_vec().into());
                },

                0x0001 => {
                    tp.max_idle_timeout = val.get_varint()?;
                },

                0x0002 => {
                    if is_server {
                        return Err(Error::InvalidTransportParam);
                    }

                    tp.stateless_reset_token = Some(u128::from_be_bytes(
                        val.get_bytes(16)?
                            .to_vec()
                            .try_into()
                            .map_err(|_| Error::BufferTooShort)?,
                    ));
                },

                0x0003 => {
                    tp.max_udp_payload_size = val.get_varint()?;

                    if tp.max_udp_payload_size < 1200 {
                        return Err(Error::InvalidTransportParam);
                    }
                },

                0x0004 => {
                    tp.initial_max_data = val.get_varint()?;
                },

                0x0005 => {
                    tp.initial_max_stream_data_bidi_local = val.get_varint()?;
                },

                0x0006 => {
                    tp.initial_max_stream_data_bidi_remote = val.get_varint()?;
                },

                0x0007 => {
                    tp.initial_max_stream_data_uni = val.get_varint()?;
                },

                0x0008 => {
                    let max = val.get_varint()?;

                    if max > MAX_STREAM_ID {
                        return Err(Error::InvalidTransportParam);
                    }

                    tp.initial_max_streams_bidi = max;
                },

                0x0009 => {
                    let max = val.get_varint()?;

                    if max > MAX_STREAM_ID {
                        return Err(Error::InvalidTransportParam);
                    }

                    tp.initial_max_streams_uni = max;
                },

                0x000a => {
                    let ack_delay_exponent = val.get_varint()?;

                    if ack_delay_exponent > 20 {
                        return Err(Error::InvalidTransportParam);
                    }

                    tp.ack_delay_exponent = ack_delay_exponent;
                },

                0x000b => {
                    let max_ack_delay = val.get_varint()?;

                    if max_ack_delay >= 2_u64.pow(14) {
                        return Err(Error::InvalidTransportParam);
                    }

                    tp.max_ack_delay = max_ack_delay;
                },

                0x000c => {
                    tp.disable_active_migration = true;
                },

                0x000d => {
                    if is_server {
                        return Err(Error::InvalidTransportParam);
                    }

                    // TODO: decode preferred_address
                },

                0x000e => {
                    let limit = val.get_varint()?;

                    if limit < 2 {
                        return Err(Error::InvalidTransportParam);
                    }

                    tp.active_conn_id_limit = limit;
                },

                0x000f => {
                    tp.initial_source_connection_id = Some(val.to_vec().into());
                },

                0x00010 => {
                    if is_server {
                        return Err(Error::InvalidTransportParam);
                    }

                    tp.retry_source_connection_id = Some(val.to_vec().into());
                },

                0x0020 => {
                    tp.max_datagram_frame_size = Some(val.get_varint()?);
                },

                // Track unknown transport parameters specially.
                unknown_tp_id => {
                    if let Some(unknown_params) = &mut tp.unknown_params {
                        // It is _not_ an error not to have space enough to track
                        // an unknown parameter.
                        let _ = unknown_params.push(UnknownTransportParameter {
                            id: unknown_tp_id,
                            value: val.buf(),
                        });
                    }
                },
            }
        }

        Ok(tp)
    }

    pub(crate) fn encode_param(
        b: &mut octets::OctetsMut, ty: u64, len: usize,
    ) -> Result<()> {
        b.put_varint(ty)?;
        b.put_varint(len as u64)?;

        Ok(())
    }

    pub(crate) fn encode<'a>(
        tp: &TransportParams, is_server: bool, out: &'a mut [u8],
    ) -> Result<&'a mut [u8]> {
        let mut b = octets::OctetsMut::with_slice(out);

        if is_server {
            if let Some(ref odcid) = tp.original_destination_connection_id {
                TransportParams::encode_param(&mut b, 0x0000, odcid.len())?;
                b.put_bytes(odcid)?;
            }
        };

        if tp.max_idle_timeout != 0 {
            assert!(tp.max_idle_timeout <= octets::MAX_VAR_INT);
            TransportParams::encode_param(
                &mut b,
                0x0001,
                octets::varint_len(tp.max_idle_timeout),
            )?;
            b.put_varint(tp.max_idle_timeout)?;
        }

        if is_server {
            if let Some(ref token) = tp.stateless_reset_token {
                TransportParams::encode_param(&mut b, 0x0002, 16)?;
                b.put_bytes(&token.to_be_bytes())?;
            }
        }

        if tp.max_udp_payload_size != 0 {
            assert!(tp.max_udp_payload_size <= octets::MAX_VAR_INT);
            TransportParams::encode_param(
                &mut b,
                0x0003,
                octets::varint_len(tp.max_udp_payload_size),
            )?;
            b.put_varint(tp.max_udp_payload_size)?;
        }

        if tp.initial_max_data != 0 {
            assert!(tp.initial_max_data <= octets::MAX_VAR_INT);
            TransportParams::encode_param(
                &mut b,
                0x0004,
                octets::varint_len(tp.initial_max_data),
            )?;
            b.put_varint(tp.initial_max_data)?;
        }

        if tp.initial_max_stream_data_bidi_local != 0 {
            assert!(tp.initial_max_stream_data_bidi_local <= octets::MAX_VAR_INT);
            TransportParams::encode_param(
                &mut b,
                0x0005,
                octets::varint_len(tp.initial_max_stream_data_bidi_local),
            )?;
            b.put_varint(tp.initial_max_stream_data_bidi_local)?;
        }

        if tp.initial_max_stream_data_bidi_remote != 0 {
            assert!(
                tp.initial_max_stream_data_bidi_remote <= octets::MAX_VAR_INT
            );
            TransportParams::encode_param(
                &mut b,
                0x0006,
                octets::varint_len(tp.initial_max_stream_data_bidi_remote),
            )?;
            b.put_varint(tp.initial_max_stream_data_bidi_remote)?;
        }

        if tp.initial_max_stream_data_uni != 0 {
            assert!(tp.initial_max_stream_data_uni <= octets::MAX_VAR_INT);
            TransportParams::encode_param(
                &mut b,
                0x0007,
                octets::varint_len(tp.initial_max_stream_data_uni),
            )?;
            b.put_varint(tp.initial_max_stream_data_uni)?;
        }

        if tp.initial_max_streams_bidi != 0 {
            assert!(tp.initial_max_streams_bidi <= octets::MAX_VAR_INT);
            TransportParams::encode_param(
                &mut b,
                0x0008,
                octets::varint_len(tp.initial_max_streams_bidi),
            )?;
            b.put_varint(tp.initial_max_streams_bidi)?;
        }

        if tp.initial_max_streams_uni != 0 {
            assert!(tp.initial_max_streams_uni <= octets::MAX_VAR_INT);
            TransportParams::encode_param(
                &mut b,
                0x0009,
                octets::varint_len(tp.initial_max_streams_uni),
            )?;
            b.put_varint(tp.initial_max_streams_uni)?;
        }

        if tp.ack_delay_exponent != 0 {
            assert!(tp.ack_delay_exponent <= octets::MAX_VAR_INT);
            TransportParams::encode_param(
                &mut b,
                0x000a,
                octets::varint_len(tp.ack_delay_exponent),
            )?;
            b.put_varint(tp.ack_delay_exponent)?;
        }

        if tp.max_ack_delay != 0 {
            assert!(tp.max_ack_delay <= octets::MAX_VAR_INT);
            TransportParams::encode_param(
                &mut b,
                0x000b,
                octets::varint_len(tp.max_ack_delay),
            )?;
            b.put_varint(tp.max_ack_delay)?;
        }

        if tp.disable_active_migration {
            TransportParams::encode_param(&mut b, 0x000c, 0)?;
        }

        // TODO: encode preferred_address

        if tp.active_conn_id_limit != 2 {
            assert!(tp.active_conn_id_limit <= octets::MAX_VAR_INT);
            TransportParams::encode_param(
                &mut b,
                0x000e,
                octets::varint_len(tp.active_conn_id_limit),
            )?;
            b.put_varint(tp.active_conn_id_limit)?;
        }

        if let Some(scid) = &tp.initial_source_connection_id {
            TransportParams::encode_param(&mut b, 0x000f, scid.len())?;
            b.put_bytes(scid)?;
        }

        if is_server {
            if let Some(scid) = &tp.retry_source_connection_id {
                TransportParams::encode_param(&mut b, 0x0010, scid.len())?;
                b.put_bytes(scid)?;
            }
        }

        if let Some(max_datagram_frame_size) = tp.max_datagram_frame_size {
            assert!(max_datagram_frame_size <= octets::MAX_VAR_INT);
            TransportParams::encode_param(
                &mut b,
                0x0020,
                octets::varint_len(max_datagram_frame_size),
            )?;
            b.put_varint(max_datagram_frame_size)?;
        }

        let out_len = b.off();

        Ok(&mut out[..out_len])
    }

    /// Creates a qlog event for connection transport parameters and TLS fields
    #[cfg(feature = "qlog")]
    pub fn to_qlog(
        &self, initiator: TransportInitiator, cipher: Option<crypto::Algorithm>,
    ) -> EventData {
        let original_destination_connection_id = qlog::HexSlice::maybe_string(
            self.original_destination_connection_id.as_ref(),
        );

        let stateless_reset_token = qlog::HexSlice::maybe_string(
            self.stateless_reset_token.map(|s| s.to_be_bytes()).as_ref(),
        );

        let tls_cipher: Option<String> = cipher.map(|f| format!("{f:?}"));

        EventData::ParametersSet(qlog::events::quic::ParametersSet {
            initiator: Some(initiator),
            tls_cipher,
            original_destination_connection_id,
            stateless_reset_token,
            disable_active_migration: Some(self.disable_active_migration),
            max_idle_timeout: Some(self.max_idle_timeout),
            max_udp_payload_size: Some(self.max_udp_payload_size),
            ack_delay_exponent: Some(self.ack_delay_exponent),
            max_ack_delay: Some(self.max_ack_delay),
            active_connection_id_limit: Some(self.active_conn_id_limit),

            initial_max_data: Some(self.initial_max_data),
            initial_max_stream_data_bidi_local: Some(
                self.initial_max_stream_data_bidi_local,
            ),
            initial_max_stream_data_bidi_remote: Some(
                self.initial_max_stream_data_bidi_remote,
            ),
            initial_max_stream_data_uni: Some(self.initial_max_stream_data_uni),
            initial_max_streams_bidi: Some(self.initial_max_streams_bidi),
            initial_max_streams_uni: Some(self.initial_max_streams_uni),

            unknown_parameters: self
                .unknown_params
                .as_ref()
                .map(|unknown_params| {
                    unknown_params
                            .into_iter()
                            .cloned()
                            .map(
                                Into::<
                                    qlog::events::quic::UnknownTransportParameter,
                                >::into,
                            )
                            .collect()
                })
                .unwrap_or_default(),

            ..Default::default()
        })
    }
}
