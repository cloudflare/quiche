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

use qlog::events::h3::HttpHeader;
use std::borrow::Cow;
use std::fmt::Display;

use crate::datastore::H2StreamReset;
use crate::datastore::QuicStreamReset;
use crate::datastore::QuicStreamStopSending;
use crate::datastore::RequestActor;
use crate::datastore::RequestAtClientDeltas;
use crate::datastore::RequestAtServerDeltas;
use netlog::http::headers_to_map;

pub const CLIENT_CONTENT_LENGTH: &str = "Request Content-Length";
pub const CLIENT_TRANSFERRED: &str = "Request Transferred";
pub const UPLOAD_TIME: &str = "Upload duration (ms)";
pub const UPLOAD_RATE: &str = "Upload rate (Mbps)";
pub const SERVER_RX_HDR_TX_HDR: &str = "Server Rx Hdr, Tx Hdr";
pub const SERVER_TX_HDR_TX_FIRST_HDR: &str = "Server Tx Hdr, Tx First Hdr";
pub const SERVER_TX_HDR_TX_LAST_HDR: &str = "Server Tx Hdr, Tx Last Hdr";
pub const SERVER_TX_FIRST_DATA_TX_LAST_DATA: &str =
    "Server Tx First Data, Tx Last Data (Download time)";

pub const CLIENT_PRI: &str = "Client Priority Header";
pub const SERVER_PRI: &str = "Server Priority Header";

const MAX_PATH_LENGTH: usize = 80;

#[derive(Copy, Clone, Debug, Default, PartialEq, Eq, PartialOrd, Ord)]
pub struct NaOption<T> {
    pub inner: Option<T>,
}

impl<T> NaOption<T> {
    pub fn new(value: Option<T>) -> Self {
        Self { inner: value }
    }
}

impl<T: std::fmt::Display> Display for NaOption<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.inner.as_ref() {
            Some(v) => write!(f, "{}", v),
            None => write!(f, "n/a"),
        }
    }
}

#[derive(Debug, Default)]
pub struct HttpRequestStub {
    pub request_actor: RequestActor,
    pub stream_id: u64,
    pub host: NaOption<String>,
    pub method: NaOption<String>,
    pub path: NaOption<String>,
    pub status: NaOption<String>,
    pub client_content_length: NaOption<String>,
    pub server_content_length: NaOption<String>,
    pub client_pri_hdr: NaOption<String>,
    pub server_pri_hdr: NaOption<String>,
    pub priority_updates: Vec<String>,

    pub time_discovery: Option<f32>,
    pub time_first_headers_rx: Option<f32>,
    pub time_first_headers_tx: Option<f32>,

    pub time_first_data_rx: Option<f32>,
    pub time_first_data_tx: Option<f32>,

    pub time_last_data_rx: Option<f32>,
    pub time_last_data_tx: Option<f32>,

    pub time_fin_rx: Option<f32>,

    // TODO, Option<u64>
    pub time_data_rx_set: Vec<(f32, u64)>,
    pub time_data_tx_set: Vec<(f32, u64)>,

    pub client_transferred_bytes: NaOption<u64>,
    pub server_transferred_bytes: NaOption<u64>,

    pub avg_upload_rate: NaOption<f64>,
    pub avg_download_rate_d2d: NaOption<f64>,
    pub avg_download_rate_h2d: NaOption<f64>,

    pub at_client_deltas: Option<RequestAtClientDeltas>,
    pub at_server_deltas: Option<RequestAtServerDeltas>,

    pub quic_stream_stop_sending_sent: Option<QuicStreamStopSending>,
    pub quic_stream_stop_sending_received: Option<QuicStreamStopSending>,

    pub quic_stream_reset_sent: Option<QuicStreamReset>,
    pub quic_stream_reset_received: Option<QuicStreamReset>,

    pub h2_stream_reset_sent: Option<H2StreamReset>,
    pub h2_stream_reset_receive: Option<H2StreamReset>,
}

struct ClientDeltaStrings {
    pub discovery_tx_hdr: String,
    pub tx_hdr_rx_hdr: String,
    pub tx_hdr_rx_first_data: String,
    pub tx_hdr_rx_last_data: String,
    pub download_time_d2d: String,
    pub download_time_h2d: String,
    pub upload_time: String,
}

impl Default for ClientDeltaStrings {
    fn default() -> Self {
        let na = NaOption::<u8>::new(None);

        Self {
            discovery_tx_hdr: na.to_string(),
            tx_hdr_rx_hdr: na.to_string(),
            tx_hdr_rx_first_data: na.to_string(),
            tx_hdr_rx_last_data: na.to_string(),
            download_time_d2d: na.to_string(),
            download_time_h2d: na.to_string(),
            upload_time: na.to_string(),
        }
    }
}

impl HttpRequestStub {
    fn client_deltas(&self) -> ClientDeltaStrings {
        match self.at_client_deltas {
            Some(d) => ClientDeltaStrings {
                discovery_tx_hdr: d.discover_tx_hdr.to_string(),
                tx_hdr_rx_hdr: d.tx_hdr_rx_hdr.to_string(),
                tx_hdr_rx_first_data: d.tx_hdr_rx_first_data.to_string(),
                tx_hdr_rx_last_data: d.tx_hdr_rx_last_data.to_string(),
                download_time_d2d: d.rx_first_data_rx_last_data.to_string(),
                download_time_h2d: d.tx_hdr_rx_last_data.to_string(),
                upload_time: d.tx_first_data_tx_last_data.to_string(),
            },

            None => ClientDeltaStrings::default(),
        }
    }

    fn server_deltas(&self) -> (String, String, String, String) {
        match self.at_server_deltas {
            Some(d) => (
                d.rx_hdr_tx_hdr.to_string(),
                d.rx_hdr_tx_first_data.to_string(),
                d.rx_hdr_tx_last_data.to_string(),
                d.tx_first_data_tx_last_data.to_string(),
            ),

            None => {
                let na = NaOption::<u8>::new(None);
                (
                    na.to_string(),
                    na.to_string(),
                    na.to_string(),
                    na.to_string(),
                )
            },
        }
    }
}

impl tabled::Tabled for HttpRequestStub {
    const LENGTH: usize = 28;

    fn fields(&self) -> Vec<Cow<'_, str>> {
        // truncate long paths for
        let mut path = self.path.to_string();
        if path.len() > MAX_PATH_LENGTH {
            path.truncate(MAX_PATH_LENGTH);
            path.push_str("<snip>");
        }

        let req_start = match self.request_actor {
            RequestActor::Client => self.time_first_headers_tx,
            RequestActor::Server => self.time_first_headers_rx,
        };
        let req_start = NaOption::new(req_start);

        // This one is tricky, we might never receive anything, so do a few
        // checks.
        let req_end = match self.request_actor {
            RequestActor::Client =>
                if self.time_last_data_rx.is_some() {
                    self.time_last_data_rx
                } else {
                    self.time_first_headers_rx
                },
            RequestActor::Server =>
                if self.time_last_data_tx.is_some() {
                    self.time_first_data_tx
                } else {
                    self.time_first_headers_tx
                },
        };

        let req_end = NaOption::new(req_end);

        let client_deltas = self.client_deltas();

        let (
            server_rx_hdr_tx_hdr,
            server_rx_hdr_tx_first_data,
            server_rx_hdr_tx_last_data,
            server_tx_first_data_tx_last_data,
        ) = self.server_deltas();

        let rst_stream_sent =
            match (&self.quic_stream_reset_sent, &self.h2_stream_reset_sent) {
                (Some(v), None) => v.to_string(),
                (None, Some(v)) => v.to_string(),
                _ => NaOption::<u8>::new(None).to_string(),
            };

        let rst_stream_received = match (
            &self.quic_stream_reset_received,
            &self.h2_stream_reset_receive,
        ) {
            (Some(v), None) => v.to_string(),
            (None, Some(v)) => v.to_string(),
            _ => NaOption::<u8>::new(None).to_string(),
        };

        let stop_sending_sent = match &self.quic_stream_stop_sending_sent {
            Some(v) => v.to_string(),
            None => NaOption::<u8>::new(None).to_string(),
        };

        vec![
            self.stream_id.to_string().into(),
            self.method.to_string().into(),
            self.host.to_string().into(),
            path.into(),
            self.status.to_string().into(),
            self.server_content_length.to_string().into(),
            self.server_transferred_bytes.to_string().into(),
            NaOption::new(self.time_discovery).to_string().into(),
            req_start.to_string().into(),
            req_end.to_string().into(),
            client_deltas.discovery_tx_hdr.into(),
            client_deltas.download_time_h2d.into(),
            self.avg_download_rate_h2d.to_string().into(),
            client_deltas.download_time_d2d.into(),
            self.avg_download_rate_d2d.to_string().into(),
            client_deltas.tx_hdr_rx_hdr.into(),
            client_deltas.tx_hdr_rx_first_data.into(),
            client_deltas.tx_hdr_rx_last_data.into(),
            self.client_content_length.to_string().into(),
            self.client_transferred_bytes.to_string().into(),
            client_deltas.upload_time.into(),
            self.avg_upload_rate.to_string().into(),
            server_rx_hdr_tx_hdr.into(),
            server_rx_hdr_tx_first_data.into(),
            server_rx_hdr_tx_last_data.into(),
            server_tx_first_data_tx_last_data.into(),
            self.client_pri_hdr.to_string().into(),
            self.server_pri_hdr.to_string().into(),
            rst_stream_sent.into(),
            rst_stream_received.into(),
            stop_sending_sent.into(),
        ]
    }

    fn headers() -> Vec<Cow<'static, str>> {
        vec![
            "ID".into(),
            "Method".into(),
            "Host".into(),
            "Path".into(),
            "Status".into(),
            "Response Content-Length (bytes)".into(),
            "Response Transferred (bytes)".into(),
            "Request Discovered Time".into(),
            "Request Start Time".into(),
            "Request End Time".into(),
            "Stalled duration (ms)".into(),
            "Download duration (h2d) (ms)".into(),
            "Download rate (h2d) (Mbps)".into(),
            "Download duration (d2d) (ms)".into(),
            "Download rate (d2d) (Mbps)".into(),
            "Client Tx Hdr, Rx Hdr".into(),
            "Client Tx Hdr, Rx First Data".into(),
            "Client Tx Hdr, Rx Last Data".into(),
            CLIENT_CONTENT_LENGTH.into(),
            CLIENT_TRANSFERRED.into(),
            UPLOAD_TIME.into(),
            UPLOAD_RATE.into(),
            SERVER_RX_HDR_TX_HDR.into(),
            SERVER_TX_HDR_TX_FIRST_HDR.into(),
            SERVER_TX_HDR_TX_LAST_HDR.into(),
            SERVER_TX_FIRST_DATA_TX_LAST_DATA.into(),
            CLIENT_PRI.into(),
            SERVER_PRI.into(),
            "Reset Stream Sent".into(),
            "Reset Stream Received".into(),
            "Stop Sending Sent".into(),
        ]
    }
}

pub fn find_header_value(hdrs: &[HttpHeader], name: &str) -> Option<String> {
    hdrs.iter()
        .find(|&h| h.name == name)
        .map(|h| h.value.clone())
}

impl HttpRequestStub {
    pub fn set_request_info_from_netlog(&mut self, hdrs: &[String]) {
        // TODO: case-sensitivity for HTTP/1.1
        let headers = headers_to_map(hdrs);

        self.method = NaOption::new(headers.get(":method").cloned());
        self.host = NaOption::new(headers.get(":authority").cloned());
        self.path = NaOption::new(headers.get(":path").cloned());
        self.client_pri_hdr = NaOption::new(headers.get("priority").cloned());
        self.client_content_length =
            NaOption::new(headers.get("content-length").cloned());
    }

    pub fn set_response_info_from_netlog(&mut self, hdrs: &[String]) {
        // TODO: case-sensitivity for HTTP/1.1
        let headers = headers_to_map(hdrs);

        self.status = NaOption::new(headers.get(":status").cloned());
        self.server_pri_hdr = NaOption::new(headers.get("priority").cloned());
        self.server_content_length =
            NaOption::new(headers.get("content-length").cloned());
    }

    pub fn set_request_info_from_qlog(&mut self, hdrs: &[HttpHeader]) {
        self.method = NaOption::new(find_header_value(hdrs, ":method"));
        self.host = NaOption::new(find_header_value(hdrs, ":authority"));
        self.path = NaOption::new(find_header_value(hdrs, ":path"));
        self.client_pri_hdr = NaOption::new(find_header_value(hdrs, "priority"));
        self.client_content_length =
            NaOption::new(find_header_value(hdrs, "content-lengt"));
    }

    pub fn set_response_info_from_qlog(&mut self, hdrs: &[HttpHeader]) {
        self.status = NaOption::new(find_header_value(hdrs, ":status"));
        self.server_pri_hdr = NaOption::new(find_header_value(hdrs, "priority"));
        self.server_content_length =
            NaOption::new(find_header_value(hdrs, "content-length"));
    }

    // input times in milliseconds
    fn maybe_megabits_per_second(
        start: Option<f32>, end: Option<f32>, bytes: Option<u64>,
    ) -> NaOption<f64> {
        match (end, start, bytes) {
            (Some(end), Some(start), Some(bytes)) => {
                let mut total_time = (end - start) as f64;
                // there might be only one frame, or it was sent super quick,
                // clamp to 1ms
                if total_time == 0.0 {
                    total_time = 1.0
                };

                // convert to seconds
                total_time /= 1000.0;

                let megabits = (bytes * 8) as f64 / 1000000.0;
                let avg_rate = megabits / total_time;

                NaOption::new(Some(avg_rate))
            },

            _ => NaOption::<f64>::new(None),
        }
    }

    pub fn calculate_upload_download_rate(&mut self) {
        match self.request_actor {
            RequestActor::Client => {
                self.avg_upload_rate = Self::maybe_megabits_per_second(
                    self.time_first_data_tx,
                    self.time_last_data_tx,
                    self.client_transferred_bytes.inner,
                );

                self.avg_download_rate_d2d = Self::maybe_megabits_per_second(
                    self.time_first_data_rx,
                    self.time_last_data_rx,
                    self.server_transferred_bytes.inner,
                );

                self.avg_download_rate_h2d = Self::maybe_megabits_per_second(
                    self.time_first_headers_tx,
                    self.time_last_data_rx,
                    self.server_transferred_bytes.inner,
                );
            },

            RequestActor::Server => {
                self.avg_upload_rate = Self::maybe_megabits_per_second(
                    self.time_first_data_rx,
                    self.time_last_data_rx,
                    self.client_transferred_bytes.inner,
                );

                self.avg_download_rate_d2d = Self::maybe_megabits_per_second(
                    self.time_first_data_tx,
                    self.time_last_data_tx,
                    self.server_transferred_bytes.inner,
                );
            },
        }
    }

    fn maybe_time_delta(start: Option<f32>, end: Option<f32>) -> NaOption<f32> {
        match (start, end) {
            (Some(start), Some(end)) => NaOption::new(Some(end - start)),

            _ => NaOption::<f32>::new(None),
        }
    }

    pub fn calculate_deltas(&mut self) {
        match self.request_actor {
            RequestActor::Client => {
                let discover_tx_hdr = Self::maybe_time_delta(
                    self.time_discovery,
                    self.time_first_headers_tx,
                );

                let tx_hdr_rx_hdr = Self::maybe_time_delta(
                    self.time_first_headers_tx,
                    self.time_first_headers_rx,
                );

                let tx_hdr_rx_first_data = Self::maybe_time_delta(
                    self.time_first_headers_tx,
                    self.time_first_data_rx,
                );

                let tx_hdr_rx_last_data = Self::maybe_time_delta(
                    self.time_first_headers_tx,
                    self.time_last_data_rx,
                );

                let tx_first_data_tx_last_data = Self::maybe_time_delta(
                    self.time_first_data_tx,
                    self.time_last_data_tx,
                );

                let rx_first_data_rx_last_data = Self::maybe_time_delta(
                    self.time_first_data_rx,
                    self.time_last_data_rx,
                );

                let rx_hdr_rx_last_data = Self::maybe_time_delta(
                    self.time_first_headers_rx,
                    self.time_last_data_rx,
                );

                self.at_client_deltas = Some(RequestAtClientDeltas {
                    discover_tx_hdr,
                    tx_hdr_rx_hdr,
                    tx_hdr_rx_first_data,
                    tx_hdr_rx_last_data,
                    tx_first_data_tx_last_data,
                    rx_first_data_rx_last_data,
                    rx_hdr_rx_last_data,
                });
            },

            RequestActor::Server => {
                let rx_hdr_tx_hdr = match (
                    self.time_first_headers_tx,
                    self.time_first_headers_rx,
                ) {
                    (Some(end), Some(start)) => NaOption::new(Some(end - start)),

                    _ => NaOption::<f32>::new(None),
                };

                let rx_hdr_tx_first_data =
                    match (self.time_first_data_tx, self.time_first_headers_rx) {
                        (Some(end), Some(start)) =>
                            NaOption::new(Some(end - start)),

                        _ => NaOption::<f32>::new(None),
                    };

                let rx_hdr_tx_last_data =
                    match (self.time_last_data_tx, self.time_first_headers_rx) {
                        (Some(end), Some(start)) =>
                            NaOption::new(Some(end - start)),

                        _ => NaOption::<f32>::new(None),
                    };

                let tx_first_data_tx_last_data =
                    match (self.time_last_data_tx, self.time_first_data_tx) {
                        (Some(end), Some(start)) =>
                            NaOption::new(Some(end - start)),

                        _ => NaOption::<f32>::new(None),
                    };

                self.at_server_deltas = Some(RequestAtServerDeltas {
                    rx_hdr_tx_hdr,
                    rx_hdr_tx_first_data,
                    rx_hdr_tx_last_data,
                    tx_first_data_tx_last_data,
                });
            },
        }
    }
}
