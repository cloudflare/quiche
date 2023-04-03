// Copyright (C) 2021, Cloudflare, Inc.
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

use crate::events::EventData;
use crate::events::EventImportance;
use crate::events::EventType;

/// A helper object specialized for streaming JSON-serialized qlog to a
/// [`Write`] trait.
///
/// The object is responsible for the `Qlog` object that contains the
/// provided `Trace`.
///
/// Serialization is progressively driven by method calls; once log streaming
/// is started, `event::Events` can be written using `add_event()`.
///
/// [`Write`]: https://doc.rust-lang.org/std/io/trait.Write.html
use super::*;

#[derive(PartialEq, Eq, Debug)]
pub enum StreamerState {
    Initial,
    Ready,
    Finished,
}

pub struct QlogStreamer {
    start_time: std::time::Instant,
    writer: Box<dyn std::io::Write + Send + Sync>,
    qlog: QlogSeq,
    state: StreamerState,
    log_level: EventImportance,
}

impl QlogStreamer {
    /// Creates a [QlogStreamer] object.
    ///
    /// It owns a [QlogSeq] object that contains the provided [TraceSeq]
    /// containing [Event]s.
    ///
    /// All serialization will be written to the provided [`Write`] using the
    /// JSON-SEQ format.
    ///
    /// [`Write`]: https://doc.rust-lang.org/std/io/trait.Write.html
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        qlog_version: String, title: Option<String>, description: Option<String>,
        summary: Option<String>, start_time: std::time::Instant, trace: TraceSeq,
        log_level: EventImportance,
        writer: Box<dyn std::io::Write + Send + Sync>,
    ) -> Self {
        let qlog = QlogSeq {
            qlog_version,
            qlog_format: "JSON-SEQ".to_string(),
            title,
            description,
            summary,
            trace,
        };

        QlogStreamer {
            start_time,
            writer,
            qlog,
            state: StreamerState::Initial,
            log_level,
        }
    }

    /// Starts qlog streaming serialization.
    ///
    /// This writes out the JSON-SEQ-serialized form of all initial qlog
    /// information. [Event]s are separately appended using [add_event()],
    /// [add_event_with_instant()], [add_event_now()],
    /// [add_event_data_with_instant()], or [add_event_data_now()].
    ///
    /// [add_event()]: #method.add_event
    /// [add_event_with_instant()]: #method.add_event_with_instant
    /// [add_event_now()]: #method.add_event_now
    /// [add_event_data_with_instant()]: #method.add_event_data_with_instant
    /// [add_event_data_now()]: #method.add_event_data_now
    pub fn start_log(&mut self) -> Result<()> {
        if self.state != StreamerState::Initial {
            return Err(Error::Done);
        }

        self.writer.as_mut().write_all(b"")?;
        serde_json::to_writer(self.writer.as_mut(), &self.qlog)
            .map_err(|_| Error::Done)?;
        self.writer.as_mut().write_all(b"\n")?;

        self.state = StreamerState::Ready;

        Ok(())
    }

    /// Finishes qlog streaming serialization.
    ///
    /// After this is called, no more serialization will occur.
    pub fn finish_log(&mut self) -> Result<()> {
        if self.state == StreamerState::Initial ||
            self.state == StreamerState::Finished
        {
            return Err(Error::InvalidState);
        }

        self.state = StreamerState::Finished;

        self.writer.as_mut().flush()?;

        Ok(())
    }

    /// Writes a JSON-SEQ-serialized [Event] using [std::time::Instant::now()].
    pub fn add_event_now(&mut self, event: Event) -> Result<()> {
        let now = std::time::Instant::now();

        self.add_event_with_instant(event, now)
    }

    /// Writes a JSON-SEQ-serialized [Event] using the provided
    /// [std::time::Instant].
    pub fn add_event_with_instant(
        &mut self, mut event: Event, now: std::time::Instant,
    ) -> Result<()> {
        if self.state != StreamerState::Ready {
            return Err(Error::InvalidState);
        }

        if !event.importance().is_contained_in(&self.log_level) {
            return Err(Error::Done);
        }

        let dur = if cfg!(test) {
            std::time::Duration::from_secs(0)
        } else {
            now.duration_since(self.start_time)
        };

        let rel_time = dur.as_secs_f32() * 1000.0;
        event.time = rel_time;

        self.add_event(event)
    }

    /// Writes a JSON-SEQ-serialized [Event] based on the provided [EventData]
    /// at time [std::time::Instant::now()].
    pub fn add_event_data_now(&mut self, event_data: EventData) -> Result<()> {
        let now = std::time::Instant::now();

        self.add_event_data_with_instant(event_data, now)
    }

    /// Writes a JSON-SEQ-serialized [Event] based on the provided [EventData]
    /// and [std::time::Instant].
    pub fn add_event_data_with_instant(
        &mut self, event_data: EventData, now: std::time::Instant,
    ) -> Result<()> {
        if self.state != StreamerState::Ready {
            return Err(Error::InvalidState);
        }

        let ty = EventType::from(&event_data);
        if !EventImportance::from(ty).is_contained_in(&self.log_level) {
            return Err(Error::Done);
        }

        let dur = if cfg!(test) {
            std::time::Duration::from_secs(0)
        } else {
            now.duration_since(self.start_time)
        };

        let rel_time = dur.as_secs_f32() * 1000.0;
        let event = Event::with_time(rel_time, event_data);

        self.add_event(event)
    }

    /// Writes a JSON-SEQ-serialized [Event] using the provided [Event].
    pub fn add_event(&mut self, event: Event) -> Result<()> {
        if self.state != StreamerState::Ready {
            return Err(Error::InvalidState);
        }

        if !event.importance().is_contained_in(&self.log_level) {
            return Err(Error::Done);
        }

        self.writer.as_mut().write_all(b"")?;
        serde_json::to_writer(self.writer.as_mut(), &event)
            .map_err(|_| Error::Done)?;
        self.writer.as_mut().write_all(b"\n")?;

        Ok(())
    }

    /// Returns the writer.
    #[allow(clippy::borrowed_box)]
    pub fn writer(&self) -> &Box<dyn std::io::Write + Send + Sync> {
        &self.writer
    }

    pub fn start_time(&self) -> std::time::Instant {
        self.start_time
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::events::quic;
    use crate::events::quic::QuicFrame;
    use crate::events::RawInfo;
    use smallvec::smallvec;
    use testing::*;

    #[test]
    fn serialization_states() {
        let v: Vec<u8> = Vec::new();
        let buff = std::io::Cursor::new(v);
        let writer = Box::new(buff);

        let trace = make_trace_seq();
        let pkt_hdr = make_pkt_hdr(quic::PacketType::Handshake);
        let raw = Some(RawInfo {
            length: Some(1251),
            payload_length: Some(1224),
            data: None,
        });

        let frame1 = QuicFrame::Stream {
            stream_id: 40,
            offset: 40,
            length: 400,
            fin: Some(true),
            raw: None,
        };

        let event_data1 = EventData::PacketSent(quic::PacketSent {
            header: pkt_hdr.clone(),
            frames: Some(smallvec![frame1]),
            is_coalesced: None,
            retry_token: None,
            stateless_reset_token: None,
            supported_versions: None,
            raw: raw.clone(),
            datagram_id: None,
            send_at_time: None,
            trigger: None,
        });

        let ev1 = Event::with_time(0.0, event_data1);

        let frame2 = QuicFrame::Stream {
            stream_id: 0,
            offset: 0,
            length: 100,
            fin: Some(true),
            raw: None,
        };

        let frame3 = QuicFrame::Stream {
            stream_id: 0,
            offset: 0,
            length: 100,
            fin: Some(true),
            raw: None,
        };

        let event_data2 = EventData::PacketSent(quic::PacketSent {
            header: pkt_hdr.clone(),
            frames: Some(smallvec![frame2]),
            is_coalesced: None,
            retry_token: None,
            stateless_reset_token: None,
            supported_versions: None,
            raw: raw.clone(),
            datagram_id: None,
            send_at_time: None,
            trigger: None,
        });

        let ev2 = Event::with_time(0.0, event_data2);

        let event_data3 = EventData::PacketSent(quic::PacketSent {
            header: pkt_hdr,
            frames: Some(smallvec![frame3]),
            is_coalesced: None,
            retry_token: None,
            stateless_reset_token: Some("reset_token".to_string()),
            supported_versions: None,
            raw,
            datagram_id: None,
            send_at_time: None,
            trigger: None,
        });

        let ev3 = Event::with_time(0.0, event_data3);

        let mut s = streamer::QlogStreamer::new(
            "version".to_string(),
            Some("title".to_string()),
            Some("description".to_string()),
            None,
            std::time::Instant::now(),
            trace,
            EventImportance::Base,
            writer,
        );

        // Before the log is started all other operations should fail.
        assert!(matches!(s.add_event(ev2.clone()), Err(Error::InvalidState)));
        assert!(matches!(s.finish_log(), Err(Error::InvalidState)));

        // Start log and add a simple event.
        assert!(matches!(s.start_log(), Ok(())));
        assert!(matches!(s.add_event(ev1), Ok(())));

        // Add some more events.
        assert!(matches!(s.add_event(ev2), Ok(())));
        assert!(matches!(s.add_event(ev3.clone()), Ok(())));

        // Adding an event with an external time should work too.
        // For tests, it will resolve to 0 but we care about proving the API
        // here, not timing specifics.
        let now = std::time::Instant::now();

        assert!(matches!(s.add_event_with_instant(ev3, now), Ok(())));

        assert!(matches!(s.finish_log(), Ok(())));

        let r = s.writer();
        let w: &Box<std::io::Cursor<Vec<u8>>> = unsafe { std::mem::transmute(r) };

        let log_string = r#"{"qlog_version":"version","qlog_format":"JSON-SEQ","title":"title","description":"description","trace":{"vantage_point":{"type":"server"},"title":"Quiche qlog trace","description":"Quiche qlog trace description","configuration":{"time_offset":0.0}}}
{"time":0.0,"name":"transport:packet_sent","data":{"header":{"packet_type":"handshake","packet_number":0,"version":"1","scil":8,"dcil":8,"scid":"7e37e4dcc6682da8","dcid":"36ce104eee50101c"},"raw":{"length":1251,"payload_length":1224},"frames":[{"frame_type":"stream","stream_id":40,"offset":40,"length":400,"fin":true}]}}
{"time":0.0,"name":"transport:packet_sent","data":{"header":{"packet_type":"handshake","packet_number":0,"version":"1","scil":8,"dcil":8,"scid":"7e37e4dcc6682da8","dcid":"36ce104eee50101c"},"raw":{"length":1251,"payload_length":1224},"frames":[{"frame_type":"stream","stream_id":0,"offset":0,"length":100,"fin":true}]}}
{"time":0.0,"name":"transport:packet_sent","data":{"header":{"packet_type":"handshake","packet_number":0,"version":"1","scil":8,"dcil":8,"scid":"7e37e4dcc6682da8","dcid":"36ce104eee50101c"},"stateless_reset_token":"reset_token","raw":{"length":1251,"payload_length":1224},"frames":[{"frame_type":"stream","stream_id":0,"offset":0,"length":100,"fin":true}]}}
{"time":0.0,"name":"transport:packet_sent","data":{"header":{"packet_type":"handshake","packet_number":0,"version":"1","scil":8,"dcil":8,"scid":"7e37e4dcc6682da8","dcid":"36ce104eee50101c"},"stateless_reset_token":"reset_token","raw":{"length":1251,"payload_length":1224},"frames":[{"frame_type":"stream","stream_id":0,"offset":0,"length":100,"fin":true}]}}
"#;

        let written_string = std::str::from_utf8(w.as_ref().get_ref()).unwrap();

        assert_eq!(log_string, written_string);
    }
}
