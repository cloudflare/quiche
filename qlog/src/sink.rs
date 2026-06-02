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

use std::io::Write;

use crate::events;
use crate::Error;
use crate::QlogSeq;
use crate::Result;

/// An event that can be delivered to a [`QlogSink`].
pub enum QlogEvent {
    /// A native qlog event.
    Event(events::Event),

    /// An extended JSON event.
    JsonEvent(events::JsonEvent),
}

impl From<events::Event> for QlogEvent {
    fn from(event: events::Event) -> Self {
        Self::Event(event)
    }
}

impl From<events::JsonEvent> for QlogEvent {
    fn from(event: events::JsonEvent) -> Self {
        Self::JsonEvent(event)
    }
}

/// A destination for sequential qlog events.
pub trait QlogSink: Send + Sync {
    /// Start a qlog stream by writing or otherwise recording the stream header.
    fn start_log(&mut self, qlog: &QlogSeq) -> Result<()>;

    /// Add a native qlog event to the stream.
    fn add_event(&mut self, event: events::Event) -> Result<()>;

    /// Add a pretty-printed native qlog event to the stream.
    fn add_event_pretty(&mut self, event: events::Event) -> Result<()> {
        self.add_event(event)
    }

    /// Add an extended JSON qlog event to the stream.
    fn add_json_event(&mut self, event: events::JsonEvent) -> Result<()>;

    /// Add a pretty-printed extended JSON qlog event to the stream.
    fn add_json_event_pretty(&mut self, event: events::JsonEvent) -> Result<()> {
        self.add_json_event(event)
    }

    /// Finish the stream.
    fn finish_log(&mut self) -> Result<()>;

    /// Returns whether this sink wants events of `event_type`.
    fn should_log(&self, _event_type: events::EventType) -> bool {
        true
    }
}

/// A [`QlogSink`] that writes JSON-SEQ qlog records to a [`Write`].
pub struct QlogWriterSink<W: Write + Send + Sync> {
    writer: W,
}

impl<W: Write + Send + Sync> QlogWriterSink<W> {
    /// Creates a new writer-backed sink.
    pub fn new(writer: W) -> Self {
        Self { writer }
    }
}

impl<W: Write + Send + Sync> QlogSink for QlogWriterSink<W> {
    fn start_log(&mut self, qlog: &QlogSeq) -> Result<()> {
        self.writer.write_all(b"\x1e")?;
        serde_json::to_writer(&mut self.writer, qlog).map_err(|_| Error::Done)?;
        self.writer.write_all(b"\n")?;

        Ok(())
    }

    fn add_event(&mut self, event: events::Event) -> Result<()> {
        self.writer.write_all(b"\x1e")?;
        serde_json::to_writer(&mut self.writer, &event)
            .map_err(|_| Error::Done)?;
        self.writer.write_all(b"\n")?;

        Ok(())
    }

    fn add_event_pretty(&mut self, event: events::Event) -> Result<()> {
        self.writer.write_all(b"\x1e")?;
        serde_json::to_writer_pretty(&mut self.writer, &event)
            .map_err(|_| Error::Done)?;
        self.writer.write_all(b"\n")?;

        Ok(())
    }

    fn add_json_event(&mut self, event: events::JsonEvent) -> Result<()> {
        self.writer.write_all(b"\x1e")?;
        serde_json::to_writer(&mut self.writer, &event)
            .map_err(|_| Error::Done)?;
        self.writer.write_all(b"\n")?;

        Ok(())
    }

    fn add_json_event_pretty(&mut self, event: events::JsonEvent) -> Result<()> {
        self.writer.write_all(b"\x1e")?;
        serde_json::to_writer_pretty(&mut self.writer, &event)
            .map_err(|_| Error::Done)?;
        self.writer.write_all(b"\n")?;

        Ok(())
    }

    fn finish_log(&mut self) -> Result<()> {
        self.writer.flush()?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::io;
    use std::io::Write;
    use std::sync::Arc;
    use std::sync::Mutex;

    use crate::events::quic;
    use crate::events::quic::QuicEventType;
    use crate::events::Event;
    use crate::events::EventData;
    use crate::events::EventImportance;
    use crate::events::EventType;
    use crate::events::JsonEvent;
    use crate::events::RawInfo;
    use crate::sink::QlogSink;
    use crate::sink::QlogWriterSink;
    use crate::testing;
    use crate::QlogSeq;
    use crate::QLOGFILESEQ_URI;

    #[derive(Clone, Default)]
    struct SharedWriter {
        bytes: Arc<Mutex<Vec<u8>>>,
    }

    impl SharedWriter {
        fn bytes(&self) -> Vec<u8> {
            self.bytes.lock().unwrap().clone()
        }
    }

    impl Write for SharedWriter {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            self.bytes.lock().unwrap().extend_from_slice(buf);
            Ok(buf.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    fn make_qlog() -> QlogSeq {
        QlogSeq {
            file_schema: QLOGFILESEQ_URI.to_string(),
            serialization_format: "JSON-SEQ".to_string(),
            title: Some("title".to_string()),
            description: Some("description".to_string()),
            trace: testing::make_trace_seq(),
        }
    }

    fn make_event() -> Event {
        let event_data = EventData::QuicPacketSent(quic::PacketSent {
            header: testing::make_pkt_hdr(quic::PacketType::Handshake),
            raw: Some(RawInfo {
                length: Some(1251),
                payload_length: Some(1224),
                data: None,
            }),
            ..Default::default()
        });

        Event::with_time(0.0, event_data)
    }

    #[test]
    fn writer_sink_writes_json_seq_header_and_native_event() {
        let writer = SharedWriter::default();
        let bytes = writer.clone();
        let mut sink = QlogWriterSink::new(writer);

        sink.start_log(&make_qlog()).unwrap();
        sink.add_event(make_event()).unwrap();
        sink.finish_log().unwrap();

        let written = String::from_utf8(bytes.bytes()).unwrap();
        let expected = r#"{"file_schema":"urn:ietf:params:qlog:file:sequential","serialization_format":"JSON-SEQ","title":"title","description":"description","trace":{"title":"Quiche qlog trace","description":"Quiche qlog trace description","vantage_point":{"type":"server"},"event_schemas":[]}}
{"time":0.0,"name":"quic:packet_sent","data":{"header":{"packet_type":"handshake","packet_number":0,"version":"1","scil":8,"dcil":8,"scid":"7e37e4dcc6682da8","dcid":"36ce104eee50101c"},"raw":{"length":1251,"payload_length":1224}}}
"#;

        pretty_assertions::assert_eq!(expected, written);
    }

    #[test]
    fn writer_sink_writes_json_event() {
        let writer = SharedWriter::default();
        let bytes = writer.clone();
        let mut sink = QlogWriterSink::new(writer);

        let event = JsonEvent {
            time: 0.0,
            importance: EventImportance::Core,
            name: "jsonevent:sample".to_string(),
            data: serde_json::json!({"foo":"bar"}),
        };

        sink.start_log(&make_qlog()).unwrap();
        sink.add_json_event(event).unwrap();
        sink.finish_log().unwrap();

        let written = String::from_utf8(bytes.bytes()).unwrap();
        assert!(written.contains(r#""name":"jsonevent:sample""#));
        assert!(written.contains(r#""foo":"bar""#));
    }

    #[test]
    fn writer_sink_defaults_to_logging_all_event_types() {
        let writer = SharedWriter::default();
        let sink = QlogWriterSink::new(writer);

        assert!(
            sink.should_log(EventType::QuicEventType(QuicEventType::PacketSent))
        );
    }
}
