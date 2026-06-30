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
use crate::events::Eventable;
use crate::events::ExData;

/// Controls the time precisions of events.
///
/// Times are always logged in units of whole milliseconds with optional
/// precision, determining the number of decimal places output by the
/// serializer.
pub enum EventTimePrecision {
    /// Logging may contain 1 decimal place to ensure float serialization e.g.,
    /// 1.0, 2.0,
    MilliSeconds,
    /// Logged up to 3 decimal places e.g., 1.234, 2.001
    MicroSeconds,
    /// Logged up to 6 decimal places e.g., 1.234567, 2.001001
    NanoSeconds,
}

/// Converts a [`Duration`] to milliseconds as `f64` using the requested
/// precision variant.
fn duration_to_millis(
    dur: std::time::Duration, precision: &EventTimePrecision,
) -> f64 {
    match precision {
        EventTimePrecision::MilliSeconds => dur.as_millis() as f64,
        EventTimePrecision::MicroSeconds => dur.as_micros() as f64 / 1_000.0,
        EventTimePrecision::NanoSeconds => dur.as_nanos() as f64 / 1_000_000.0,
    }
}

/// Computes elapsed time in milliseconds since `start`, based on the provided
/// `precision`. In test builds, always returns 0.0 for deterministic output.
fn elapsed_millis(
    start: std::time::Instant, now: std::time::Instant,
    precision: &EventTimePrecision,
) -> f64 {
    if cfg!(test) {
        return 0.0;
    }

    let dur = now.saturating_duration_since(start);
    duration_to_millis(dur, precision)
}

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
    sink: Box<dyn crate::QlogSink>,
    qlog: QlogSeq,
    state: StreamerState,
    log_level: EventImportance,
    time_precision: EventTimePrecision,
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
        title: Option<String>, description: Option<String>,
        start_time: std::time::Instant, trace: TraceSeq,
        log_level: EventImportance, time_precision: EventTimePrecision,
        writer: Box<dyn std::io::Write + Send + Sync>,
    ) -> Self {
        Self::new_with_sink(
            title,
            description,
            start_time,
            trace,
            log_level,
            time_precision,
            Box::new(crate::QlogWriterSink::new(writer)),
        )
    }

    /// Creates a [QlogStreamer] object with a custom [QlogSink].
    ///
    /// [QlogSink]: crate::QlogSink
    #[allow(clippy::too_many_arguments)]
    pub fn new_with_sink(
        title: Option<String>, description: Option<String>,
        start_time: std::time::Instant, trace: TraceSeq,
        log_level: EventImportance, time_precision: EventTimePrecision,
        sink: Box<dyn crate::QlogSink>,
    ) -> Self {
        let qlog = QlogSeq {
            file_schema: QLOGFILESEQ_URI.to_string(),
            serialization_format: "JSON-SEQ".to_string(),
            title,
            description,
            trace,
        };

        QlogStreamer {
            start_time,
            sink,
            qlog,
            state: StreamerState::Initial,
            log_level,
            time_precision,
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

        self.sink.start_log(&self.qlog)?;

        self.state = StreamerState::Ready;

        Ok(())
    }

    /// Finishes qlog streaming serialization.
    ///
    /// After this is called, no more serialization will occur.
    ///
    /// Calling `finish_log` explicitly is optional. [`QlogStreamer`]'s
    /// [`Drop`] impl also invokes `finish_log` and discards the result,
    /// so callers that do not need to observe a finalization error can
    /// simply drop the streamer. Call `finish_log` directly only when
    /// you want to surface an [`Error`] (for example, if the underlying
    /// [`QlogSink`] performs I/O during finalization that you want to
    /// react to).
    ///
    /// Returns [`Error::InvalidState`] if the streamer has not yet been
    /// started or has already been finished.
    ///
    /// [`QlogSink`]: crate::QlogSink
    pub fn finish_log(&mut self) -> Result<()> {
        if self.state == StreamerState::Initial ||
            self.state == StreamerState::Finished
        {
            return Err(Error::InvalidState);
        }

        self.state = StreamerState::Finished;

        self.sink.finish_log()?;

        Ok(())
    }

    /// Writes a serializable to a JSON-SEQ record using
    /// [std::time::Instant::now()].
    pub fn add_event_now<E: Into<crate::QlogEvent> + Eventable>(
        &mut self, event: E,
    ) -> Result<()> {
        let now = std::time::Instant::now();

        self.add_event_with_instant(event, now)
    }

    /// Writes a serializable to a pretty-printed JSON-SEQ record using
    /// [std::time::Instant::now()].
    pub fn add_event_now_pretty<E: Into<crate::QlogEvent> + Eventable>(
        &mut self, event: E,
    ) -> Result<()> {
        let now = std::time::Instant::now();

        self.add_event_with_instant_pretty(event, now)
    }

    /// Writes a serializable to a JSON-SEQ record using the provided
    /// [std::time::Instant].
    pub fn add_event_with_instant<E: Into<crate::QlogEvent> + Eventable>(
        &mut self, event: E, now: std::time::Instant,
    ) -> Result<()> {
        self.event_with_instant(event, now, false)
    }

    /// Writes a serializable to a pretty-printed JSON-SEQ record using the
    /// provided [std::time::Instant].
    pub fn add_event_with_instant_pretty<
        E: Into<crate::QlogEvent> + Eventable,
    >(
        &mut self, event: E, now: std::time::Instant,
    ) -> Result<()> {
        self.event_with_instant(event, now, true)
    }

    fn event_with_instant<E: Into<crate::QlogEvent> + Eventable>(
        &mut self, mut event: E, now: std::time::Instant, pretty: bool,
    ) -> Result<()> {
        if self.state != StreamerState::Ready {
            return Err(Error::InvalidState);
        }

        if !event.importance().is_contained_in(&self.log_level) {
            return Err(Error::Done);
        }

        event.set_time(elapsed_millis(
            self.start_time,
            now,
            &self.time_precision,
        ));

        if pretty {
            self.add_event_pretty(event)
        } else {
            self.add_event(event)
        }
    }

    /// Writes an [Event] based on the provided [EventData] to a JSON-SEQ record
    /// at time [std::time::Instant::now()].
    pub fn add_event_data_now(&mut self, event_data: EventData) -> Result<()> {
        self.add_event_data_ex_now(event_data, Default::default())
    }

    /// Writes an [Event] based on the provided [EventData] to a pretty-printed
    /// JSON-SEQ record at time [std::time::Instant::now()].
    pub fn add_event_data_now_pretty(
        &mut self, event_data: EventData,
    ) -> Result<()> {
        self.add_event_data_ex_now_pretty(event_data, Default::default())
    }

    /// Writes an [Event] based on the provided [EventData] and [ExData] to a
    /// JSON-SEQ record at time [std::time::Instant::now()].
    pub fn add_event_data_ex_now(
        &mut self, event_data: EventData, ex_data: ExData,
    ) -> Result<()> {
        let now = std::time::Instant::now();

        self.add_event_data_ex_with_instant(event_data, ex_data, now)
    }

    /// Writes an [Event] based on the provided [EventData] and [ExData] to a
    /// pretty-printed JSON-SEQ record at time [std::time::Instant::now()].
    pub fn add_event_data_ex_now_pretty(
        &mut self, event_data: EventData, ex_data: ExData,
    ) -> Result<()> {
        let now = std::time::Instant::now();

        self.add_event_data_ex_with_instant_pretty(event_data, ex_data, now)
    }

    /// Writes an [Event] based on the provided [EventData] and
    /// [std::time::Instant] to a JSON-SEQ record.
    pub fn add_event_data_with_instant(
        &mut self, event_data: EventData, now: std::time::Instant,
    ) -> Result<()> {
        self.add_event_data_ex_with_instant(event_data, Default::default(), now)
    }

    /// Writes an [Event] based on the provided [EventData] and
    /// [std::time::Instant] to a pretty-printed JSON-SEQ record.
    pub fn add_event_data_with_instant_pretty(
        &mut self, event_data: EventData, now: std::time::Instant,
    ) -> Result<()> {
        self.add_event_data_ex_with_instant_pretty(
            event_data,
            Default::default(),
            now,
        )
    }

    /// Writes an [Event] based on the provided [EventData], [ExData], and
    /// [std::time::Instant] to a JSON-SEQ record.
    pub fn add_event_data_ex_with_instant(
        &mut self, event_data: EventData, ex_data: ExData,
        now: std::time::Instant,
    ) -> Result<()> {
        self.event_data_ex_with_instant(event_data, ex_data, now, false)
    }

    // Writes an [Event] based on the provided [EventData], [ExData], and
    /// [std::time::Instant] to a pretty-printed JSON-SEQ record.
    pub fn add_event_data_ex_with_instant_pretty(
        &mut self, event_data: EventData, ex_data: ExData,
        now: std::time::Instant,
    ) -> Result<()> {
        self.event_data_ex_with_instant(event_data, ex_data, now, true)
    }

    fn event_data_ex_with_instant(
        &mut self, event_data: EventData, ex_data: ExData,
        now: std::time::Instant, pretty: bool,
    ) -> Result<()> {
        if self.state != StreamerState::Ready {
            return Err(Error::InvalidState);
        }

        let ty = EventType::from(&event_data);
        if !EventImportance::from(ty).is_contained_in(&self.log_level) {
            return Err(Error::Done);
        }
        if !self.sink.should_log(ty) {
            return Err(Error::Done);
        }

        let event = Event::with_time_ex(
            elapsed_millis(self.start_time, now, &self.time_precision),
            event_data,
            ex_data,
        );

        if pretty {
            self.add_event_pretty(event)
        } else {
            self.add_event(event)
        }
    }

    /// Writes a JSON-SEQ-serialized [Event] using the provided [Event].
    pub fn add_event<E: Into<crate::QlogEvent> + Eventable>(
        &mut self, event: E,
    ) -> Result<()> {
        self.write_event(event, false)
    }

    /// Writes a pretty-printed JSON-SEQ-serialized [Event] using the provided
    /// [Event].
    pub fn add_event_pretty<E: Into<crate::QlogEvent> + Eventable>(
        &mut self, event: E,
    ) -> Result<()> {
        self.write_event(event, true)
    }

    /// Writes a JSON-SEQ-serialized [Event] using the provided [Event].
    ///
    /// For native [`crate::events::Event`] payloads, both the
    /// `EventImportance` filter and [`crate::QlogSink::should_log`] are
    /// honored. [`crate::events::JsonEvent`] payloads only respect the
    /// `EventImportance` filter because they do not carry an
    /// [`EventType`].
    fn write_event<E: Into<crate::QlogEvent> + Eventable>(
        &mut self, event: E, pretty: bool,
    ) -> Result<()> {
        if self.state != StreamerState::Ready {
            return Err(Error::InvalidState);
        }

        if !event.importance().is_contained_in(&self.log_level) {
            return Err(Error::Done);
        }

        match event.into() {
            crate::QlogEvent::Event(event) => {
                let ty = EventType::from(&event.data);
                if !self.sink.should_log(ty) {
                    return Err(Error::Done);
                }
                if pretty {
                    self.sink.add_event_pretty(event)?;
                } else {
                    self.sink.add_event(event)?;
                }
            },

            crate::QlogEvent::JsonEvent(event) if pretty =>
                self.sink.add_json_event_pretty(event)?,
            crate::QlogEvent::JsonEvent(event) =>
                self.sink.add_json_event(event)?,
        }

        Ok(())
    }

    /// Returns a reference to the underlying [`QlogSink`].
    pub fn sink(&self) -> &dyn crate::QlogSink {
        self.sink.as_ref()
    }

    pub fn start_time(&self) -> std::time::Instant {
        self.start_time
    }

    /// Returns whether an event type should be logged.
    pub fn should_log(&self, event_type: EventType) -> bool {
        EventImportance::from(event_type).is_contained_in(&self.log_level) &&
            self.sink.should_log(event_type)
    }
}

impl Drop for QlogStreamer {
    fn drop(&mut self) {
        let _ = self.finish_log();
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use super::*;
    use crate::events::quic;
    use crate::events::quic::QuicFrame;
    use crate::events::RawInfo;
    use testing::*;

    use serde_json::json;

    #[test]
    fn serialization_states() {
        let writer = crate::testing::SharedWriter::new();

        let trace = make_trace_seq();
        let pkt_hdr = make_pkt_hdr(quic::PacketType::Handshake);
        let raw = Some(RawInfo {
            length: Some(1251),
            payload_length: Some(1224),
            data: None,
        });

        let frame1 = QuicFrame::Stream {
            stream_id: 40,
            offset: Some(40),
            raw: Some(Box::new(RawInfo {
                length: None,
                payload_length: Some(400),
                data: None,
            })),
            fin: Some(true),
        };

        let event_data1 = EventData::QuicPacketSent(quic::PacketSent {
            header: pkt_hdr.clone(),
            frames: Some(vec![frame1]),
            raw: raw.clone(),
            ..Default::default()
        });

        let ev1 = Event::with_time(0.0, event_data1);

        let frame2 = QuicFrame::Stream {
            stream_id: 0,
            offset: Some(0),
            raw: Some(Box::new(RawInfo {
                length: None,
                payload_length: Some(100),
                data: None,
            })),
            fin: Some(true),
        };

        let frame3 = QuicFrame::Stream {
            stream_id: 0,
            offset: Some(0),
            raw: Some(Box::new(RawInfo {
                length: None,
                payload_length: Some(100),
                data: None,
            })),
            fin: Some(true),
        };

        let event_data2 = EventData::QuicPacketSent(quic::PacketSent {
            header: pkt_hdr.clone(),
            frames: Some(vec![frame2]),
            raw: raw.clone(),
            ..Default::default()
        });

        let ev2 = Event::with_time(0.0, event_data2);

        let event_data3 = EventData::QuicPacketSent(quic::PacketSent {
            header: pkt_hdr,
            frames: Some(vec![frame3]),
            stateless_reset_token: Some(Box::new("reset_token".to_string())),
            raw,
            ..Default::default()
        });

        let ev3 = Event::with_time(0.0, event_data3);

        let mut s = streamer::QlogStreamer::new(
            Some("title".to_string()),
            Some("description".to_string()),
            std::time::Instant::now(),
            trace,
            EventImportance::Base,
            EventTimePrecision::NanoSeconds,
            Box::new(writer.clone()),
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

        let log_string = r#"{"file_schema":"urn:ietf:params:qlog:file:sequential","serialization_format":"JSON-SEQ","title":"title","description":"description","trace":{"title":"Quiche qlog trace","description":"Quiche qlog trace description","vantage_point":{"type":"server"},"event_schemas":[]}}
{"time":0.0,"name":"quic:packet_sent","data":{"header":{"packet_type":"handshake","packet_number":0,"version":"1","scil":8,"dcil":8,"scid":"7e37e4dcc6682da8","dcid":"36ce104eee50101c"},"raw":{"length":1251,"payload_length":1224},"frames":[{"frame_type":"stream","stream_id":40,"offset":40,"fin":true,"raw":{"payload_length":400}}]}}
{"time":0.0,"name":"quic:packet_sent","data":{"header":{"packet_type":"handshake","packet_number":0,"version":"1","scil":8,"dcil":8,"scid":"7e37e4dcc6682da8","dcid":"36ce104eee50101c"},"raw":{"length":1251,"payload_length":1224},"frames":[{"frame_type":"stream","stream_id":0,"offset":0,"fin":true,"raw":{"payload_length":100}}]}}
{"time":0.0,"name":"quic:packet_sent","data":{"header":{"packet_type":"handshake","packet_number":0,"version":"1","scil":8,"dcil":8,"scid":"7e37e4dcc6682da8","dcid":"36ce104eee50101c"},"stateless_reset_token":"reset_token","raw":{"length":1251,"payload_length":1224},"frames":[{"frame_type":"stream","stream_id":0,"offset":0,"fin":true,"raw":{"payload_length":100}}]}}
{"time":0.0,"name":"quic:packet_sent","data":{"header":{"packet_type":"handshake","packet_number":0,"version":"1","scil":8,"dcil":8,"scid":"7e37e4dcc6682da8","dcid":"36ce104eee50101c"},"stateless_reset_token":"reset_token","raw":{"length":1251,"payload_length":1224},"frames":[{"frame_type":"stream","stream_id":0,"offset":0,"fin":true,"raw":{"payload_length":100}}]}}
"#;

        pretty_assertions::assert_eq!(log_string, writer.as_string());
    }

    #[test]
    fn stream_json_event() {
        let data = json!({"foo": "Bar", "hello": 123});
        let ev = events::JsonEvent {
            time: 0.0,
            importance: events::EventImportance::Core,
            name: "jsonevent:sample".into(),
            data,
        };

        let writer = crate::testing::SharedWriter::new();

        let trace = make_trace_seq();

        let mut s = streamer::QlogStreamer::new(
            Some("title".to_string()),
            Some("description".to_string()),
            std::time::Instant::now(),
            trace,
            EventImportance::Base,
            EventTimePrecision::NanoSeconds,
            Box::new(writer.clone()),
        );

        assert!(matches!(s.start_log(), Ok(())));
        assert!(matches!(s.add_event(ev), Ok(())));
        assert!(matches!(s.finish_log(), Ok(())));

        let log_string = r#"{"file_schema":"urn:ietf:params:qlog:file:sequential","serialization_format":"JSON-SEQ","title":"title","description":"description","trace":{"title":"Quiche qlog trace","description":"Quiche qlog trace description","vantage_point":{"type":"server"},"event_schemas":[]}}
{"time":0.0,"name":"jsonevent:sample","data":{"foo":"Bar","hello":123}}
"#;

        pretty_assertions::assert_eq!(log_string, writer.as_string());
    }

    #[test]
    fn stream_data_ex() {
        let writer = crate::testing::SharedWriter::new();

        let trace = make_trace_seq();
        let pkt_hdr = make_pkt_hdr(quic::PacketType::Handshake);
        let raw = Some(RawInfo {
            length: Some(1251),
            payload_length: Some(1224),
            data: None,
        });

        let frame1 = QuicFrame::Stream {
            stream_id: 40,
            offset: Some(40),
            raw: Some(Box::new(RawInfo {
                length: None,
                payload_length: Some(400),
                data: None,
            })),
            fin: Some(true),
        };

        let event_data1 = EventData::QuicPacketSent(quic::PacketSent {
            header: pkt_hdr.clone(),
            frames: Some(vec![frame1]),
            raw: raw.clone(),
            ..Default::default()
        });
        let j1 = json!({"foo": "Bar", "hello": 123});
        let j2 = json!({"baz": [1,2,3,4]});
        let mut ex_data = BTreeMap::new();
        ex_data.insert("first".to_string(), j1);
        ex_data.insert("second".to_string(), j2);

        let ev1 = Event::with_time_ex(0.0, event_data1, ex_data);

        let frame2 = QuicFrame::Stream {
            stream_id: 1,
            offset: Some(0),
            raw: Some(Box::new(RawInfo {
                length: None,
                payload_length: Some(100),
                data: None,
            })),
            fin: Some(true),
        };

        let event_data2 = EventData::QuicPacketSent(quic::PacketSent {
            header: pkt_hdr.clone(),
            frames: Some(vec![frame2]),
            raw: raw.clone(),
            ..Default::default()
        });

        let ev2 = Event::with_time(0.0, event_data2);

        let mut s = streamer::QlogStreamer::new(
            Some("title".to_string()),
            Some("description".to_string()),
            std::time::Instant::now(),
            trace,
            EventImportance::Base,
            EventTimePrecision::NanoSeconds,
            Box::new(writer.clone()),
        );

        assert!(matches!(s.start_log(), Ok(())));
        assert!(matches!(s.add_event(ev1), Ok(())));
        assert!(matches!(s.add_event(ev2), Ok(())));
        assert!(matches!(s.finish_log(), Ok(())));

        let log_string = r#"{"file_schema":"urn:ietf:params:qlog:file:sequential","serialization_format":"JSON-SEQ","title":"title","description":"description","trace":{"title":"Quiche qlog trace","description":"Quiche qlog trace description","vantage_point":{"type":"server"},"event_schemas":[]}}
{"time":0.0,"name":"quic:packet_sent","data":{"header":{"packet_type":"handshake","packet_number":0,"version":"1","scil":8,"dcil":8,"scid":"7e37e4dcc6682da8","dcid":"36ce104eee50101c"},"raw":{"length":1251,"payload_length":1224},"frames":[{"frame_type":"stream","stream_id":40,"offset":40,"fin":true,"raw":{"payload_length":400}}]},"first":{"foo":"Bar","hello":123},"second":{"baz":[1,2,3,4]}}
{"time":0.0,"name":"quic:packet_sent","data":{"header":{"packet_type":"handshake","packet_number":0,"version":"1","scil":8,"dcil":8,"scid":"7e37e4dcc6682da8","dcid":"36ce104eee50101c"},"raw":{"length":1251,"payload_length":1224},"frames":[{"frame_type":"stream","stream_id":1,"offset":0,"fin":true,"raw":{"payload_length":100}}]}}
"#;

        pretty_assertions::assert_eq!(log_string, writer.as_string());
    }

    struct FilteringSink;

    impl crate::QlogSink for FilteringSink {
        fn start_log(&mut self, _qlog: &QlogSeq) -> Result<()> {
            Ok(())
        }

        fn add_event(&mut self, _event: Event) -> Result<()> {
            Ok(())
        }

        fn add_json_event(&mut self, _event: events::JsonEvent) -> Result<()> {
            Ok(())
        }

        fn finish_log(&mut self) -> Result<()> {
            Ok(())
        }

        fn should_log(&self, event_type: EventType) -> bool {
            event_type !=
                EventType::QuicEventType(quic::QuicEventType::PacketSent)
        }
    }

    #[test]
    fn streamer_should_log_combines_importance_and_sink_filter() {
        let streamer = streamer::QlogStreamer::new_with_sink(
            Some("title".to_string()),
            Some("description".to_string()),
            std::time::Instant::now(),
            make_trace_seq(),
            EventImportance::Base,
            EventTimePrecision::NanoSeconds,
            Box::new(FilteringSink),
        );

        assert!(!streamer.should_log(EventType::QuicEventType(
            quic::QuicEventType::PacketSent,
        )));
        assert!(streamer.should_log(EventType::QuicEventType(
            quic::QuicEventType::ConnectionClosed,
        )));
        assert!(!streamer.should_log(EventType::QuicEventType(
            quic::QuicEventType::ServerListening,
        )));
    }

    /// Sink that rejects [`PacketSent`] events and counts every event
    /// actually delivered to its `add_event` method. Used to prove
    /// that [`QlogStreamer`]'s public event-writing methods honor
    /// [`QlogSink::should_log`].
    struct CountingFilterSink {
        delivered: std::sync::Arc<std::sync::atomic::AtomicUsize>,
    }

    impl crate::QlogSink for CountingFilterSink {
        fn start_log(&mut self, _qlog: &QlogSeq) -> Result<()> {
            Ok(())
        }

        fn add_event(&mut self, _event: Event) -> Result<()> {
            self.delivered
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            Ok(())
        }

        fn add_json_event(&mut self, _event: events::JsonEvent) -> Result<()> {
            Ok(())
        }

        fn finish_log(&mut self) -> Result<()> {
            Ok(())
        }

        fn should_log(&self, event_type: EventType) -> bool {
            event_type !=
                EventType::QuicEventType(quic::QuicEventType::PacketSent)
        }
    }

    #[test]
    fn add_event_paths_honor_sink_should_log() {
        let delivered =
            std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let sink = CountingFilterSink {
            delivered: delivered.clone(),
        };

        let mut s = streamer::QlogStreamer::new_with_sink(
            Some("title".to_string()),
            Some("description".to_string()),
            std::time::Instant::now(),
            make_trace_seq(),
            EventImportance::Base,
            EventTimePrecision::NanoSeconds,
            Box::new(sink),
        );
        s.start_log().unwrap();

        let pkt_hdr = make_pkt_hdr(quic::PacketType::Handshake);

        // Rejected: PacketSent event delivered via add_event_data_now.
        let rejected = EventData::QuicPacketSent(quic::PacketSent {
            header: pkt_hdr.clone(),
            ..Default::default()
        });
        let res = s.add_event_data_now(rejected);
        assert!(matches!(res, Err(Error::Done)));

        // Rejected: PacketSent event delivered via add_event.
        let rejected_event = Event::with_time(
            0.0,
            EventData::QuicPacketSent(quic::PacketSent {
                header: pkt_hdr.clone(),
                ..Default::default()
            }),
        );
        let res = s.add_event(rejected_event);
        assert!(matches!(res, Err(Error::Done)));

        // Accepted: ConnectionClosed event delivered via add_event_data_now.
        let accepted = EventData::QuicConnectionClosed(quic::ConnectionClosed {
            initiator: None,
            connection_error: None,
            application_error: None,
            error_code: None,
            internal_code: None,
            reason: None,
            trigger: None,
        });
        let res = s.add_event_data_now(accepted);
        assert!(matches!(res, Ok(())));

        assert_eq!(
            delivered.load(std::sync::atomic::Ordering::SeqCst),
            1,
            "only ConnectionClosed should have reached the sink"
        );
    }

    #[test]
    fn elapsed_millis_precision() {
        let dur = std::time::Duration::from_nanos(1_234_567);
        assert_eq!(
            duration_to_millis(dur, &EventTimePrecision::MilliSeconds),
            1.0
        );
        assert_eq!(
            duration_to_millis(dur, &EventTimePrecision::MicroSeconds),
            1.234000
        );
        assert_eq!(
            duration_to_millis(dur, &EventTimePrecision::NanoSeconds),
            1.234567
        );
    }

    #[test]
    fn elapsed_millis_zero_duration_all_precisions() {
        let dur = std::time::Duration::from_secs(0);
        assert_eq!(
            duration_to_millis(dur, &EventTimePrecision::MilliSeconds),
            0.0
        );
        assert_eq!(
            duration_to_millis(dur, &EventTimePrecision::MicroSeconds),
            0.0
        );
        assert_eq!(
            duration_to_millis(dur, &EventTimePrecision::NanoSeconds),
            0.0
        );
    }
}
