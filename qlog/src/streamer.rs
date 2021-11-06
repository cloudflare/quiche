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

use crate::events::quic::QuicFrame;
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
/// is started, `event::Events` can be written using `add_event()`. Some
/// events can contain an array of `QuicFrame`s, when writing such an event,
/// the streamer enters a frame-serialization mode where frames are be
/// progressively written using `add_frame()`. This mode is concluded using
/// `finished_frames()`. While serializing frames, any attempts to log
/// additional events are ignored.
///
/// [`Write`]: https://doc.rust-lang.org/std/io/trait.Write.html
use super::*;

#[derive(PartialEq, Debug)]
pub enum StreamerState {
    Initial,
    Ready,
    WritingFrames,
    Finished,
}

pub struct QlogStreamer {
    start_time: std::time::Instant,
    writer: Box<dyn std::io::Write + Send + Sync>,
    qlog: QlogSeq,
    state: StreamerState,
    log_level: EventImportance,
    first_frame: bool,
}

impl QlogStreamer {
    /// Creates a QlogStreamer object.
    ///
    /// It owns a `Qlog` object that contains the provided `Trace` containing
    /// `Events`.
    ///
    /// All serialization will be written to the provided `Write` using the
    /// JSON-SEQ format.
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
            first_frame: false,
        }
    }

    /// Starts qlog streaming serialization.
    ///
    /// This writes out the JSON-serialized form of all initial qlog information
    /// `Event`s are separately appended using `add_event()` and
    /// `add_event_with_instant()`.
    pub fn start_log(&mut self) -> Result<()> {
        if self.state != StreamerState::Initial {
            return Err(Error::Done);
        }

        // The `QlogSeq` contains a simple `TraceSeq`, so we can write
        // it out directly as a standalone item.
        match serde_json::to_string(&self.qlog) {
            Ok(out) => {
                let out = format!("{}\n", out);
                self.writer.as_mut().write_all(out.as_bytes())?;

                self.state = StreamerState::Ready;
            },

            _ => return Err(Error::Done),
        }

        Ok(())
    }

    /// Finishes qlog streaming serialization.
    ///
    /// The JSON-serialized output has remaining close delimiters added.
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

    /// Writes a JSON-serialized `Event` using `std::time::Instant::now()`.
    ///
    /// Some qlog events can contain `QuicFrames`. If this is detected `true` is
    /// returned and the streamer enters a frame-serialization mode that is only
    /// concluded by `finish_frames()`. In this mode, attempts to log additional
    /// events are ignored.
    ///
    /// If the event contains no array of `QuicFrames` return `false`.
    pub fn add_event_now(&mut self, event: Event) -> Result<bool> {
        let now = std::time::Instant::now();

        self.add_event_with_instant(event, now)
    }

    /// Writes a JSON-serialized `Event` using the provided EventData and
    /// Instant.
    ///
    /// Some qlog events can contain `QuicFrames`. If this is detected `true` is
    /// returned and the streamer enters a frame-serialization mode that is only
    /// concluded by `finish_frames()`. In this mode, attempts to log additional
    /// events are ignored.
    ///
    /// If the event contains no array of `QuicFrames` return `false`.
    pub fn add_event_with_instant(
        &mut self, mut event: Event, now: std::time::Instant,
    ) -> Result<bool> {
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

    /// Writes a JSON-serialized `Event` using the provided Instant.
    ///
    /// Some qlog events can contain `QuicFrames`. If this is detected `true` is
    /// returned and the streamer enters a frame-serialization mode that is only
    /// concluded by `finish_frames()`. In this mode, attempts to log additional
    /// events are ignored.
    ///
    /// If the event contains no array of `QuicFrames` return `false`.
    pub fn add_event_data_with_instant(
        &mut self, event_data: EventData, now: std::time::Instant,
    ) -> Result<bool> {
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

    /// Writes a JSON-serialized `Event` using the provided Event.
    ///
    /// Some qlog events can contain `QuicFrames`. If this is detected `true` is
    /// returned and the streamer enters a frame-serialization mode that is only
    /// concluded by `finish_frames()`. In this mode, attempts to log additional
    /// events are ignored.
    ///
    /// If the event contains no array of `QuicFrames` return `false`.
    pub fn add_event(&mut self, event: Event) -> Result<bool> {
        if self.state != StreamerState::Ready {
            return Err(Error::InvalidState);
        }

        if !event.importance().is_contained_in(&self.log_level) {
            return Err(Error::Done);
        }

        let (ev, contains_frames) = match serde_json::to_string(&event) {
            Ok(mut ev_out) =>
                if let Some(f) = event.data.contains_quic_frames() {
                    ev_out.truncate(ev_out.len() - 3);

                    if f == 0 {
                        self.first_frame = true;
                    }

                    (ev_out, true)
                } else {
                    (ev_out, false)
                },

            _ => return Err(Error::Done),
        };

        // TraceSeq events are written line-by-line

        let maybe_newline = if contains_frames { "" } else { "\n" };

        let out = format!("{}{}", ev, maybe_newline);
        self.writer.as_mut().write_all(out.as_bytes())?;

        if contains_frames {
            self.state = StreamerState::WritingFrames
        } else {
            self.state = StreamerState::Ready
        };

        Ok(contains_frames)
    }

    /// Writes a JSON-serialized `QuicFrame`.
    ///
    /// Only valid while in the frame-serialization mode.
    pub fn add_frame(&mut self, frame: QuicFrame, last: bool) -> Result<()> {
        if self.state != StreamerState::WritingFrames {
            return Err(Error::InvalidState);
        }

        match serde_json::to_string(&frame) {
            Ok(mut out) => {
                if !self.first_frame {
                    out.insert(0, ',');
                } else {
                    self.first_frame = false;
                }

                self.writer.as_mut().write_all(out.as_bytes())?;

                if last {
                    self.finish_frames()?;
                }
            },

            _ => return Err(Error::Done),
        }

        Ok(())
    }

    /// Concludes `QuicFrame` streaming serialization.
    ///
    /// Only valid while in the frame-serialization mode.
    pub fn finish_frames(&mut self) -> Result<()> {
        if self.state != StreamerState::WritingFrames {
            return Err(Error::InvalidState);
        }

        self.writer.as_mut().write_all(b"]}}\n")?;

        self.state = StreamerState::Ready;

        Ok(())
    }

    /// Returns the writer.
    #[allow(clippy::borrowed_box)]
    pub fn writer(&self) -> &Box<dyn std::io::Write + Send + Sync> {
        &self.writer
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::events::quic;
    use crate::events::RawInfo;
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
            frames: Some(vec![frame1]),
            is_coalesced: None,
            retry_token: None,
            stateless_reset_token: None,
            supported_versions: None,
            raw: raw.clone(),
            datagram_id: None,
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
            frames: Some(vec![]),
            is_coalesced: None,
            retry_token: None,
            stateless_reset_token: None,
            supported_versions: None,
            raw: raw.clone(),
            datagram_id: None,
        });

        let ev2 = Event::with_time(0.0, event_data2);

        let event_data3 = EventData::PacketSent(quic::PacketSent {
            header: pkt_hdr,
            frames: Some(vec![]),
            is_coalesced: None,
            retry_token: None,
            stateless_reset_token: Some("reset_token".to_string()),
            supported_versions: None,
            raw: raw.clone(),
            datagram_id: None,
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
        assert!(matches!(
            s.add_frame(frame2.clone(), false),
            Err(Error::InvalidState)
        ));
        assert!(matches!(s.finish_frames(), Err(Error::InvalidState)));
        assert!(matches!(s.finish_log(), Err(Error::InvalidState)));

        // Once a log is started, can't write frames before an event.
        assert!(matches!(s.start_log(), Ok(())));
        assert!(matches!(
            s.add_frame(frame2.clone(), false),
            Err(Error::InvalidState)
        ));
        assert!(matches!(s.finish_frames(), Err(Error::InvalidState)));

        // Initiate log with simple event.
        assert!(matches!(s.add_event(ev1), Ok(true)));
        assert!(matches!(s.finish_frames(), Ok(())));

        // Some events hold frames; can't write any more events until frame
        // writing is concluded.
        assert!(matches!(s.add_event(ev2.clone()), Ok(true)));
        assert!(matches!(s.add_event(ev2.clone()), Err(Error::InvalidState)));

        // While writing frames, can't write events.
        assert!(matches!(s.add_frame(frame2.clone(), false), Ok(())));
        assert!(matches!(s.add_event(ev2.clone()), Err(Error::InvalidState)));
        assert!(matches!(s.finish_frames(), Ok(())));

        // Adding an event that includes both frames and raw data should
        // be allowed.
        assert!(matches!(s.add_event(ev3.clone()), Ok(true)));
        assert!(matches!(s.add_frame(frame3.clone(), false), Ok(())));
        assert!(matches!(s.finish_frames(), Ok(())));

        // Adding an event with an external time should work too.
        // For tests, it will resolve to 0 but we care about proving the API
        // here, not timing specifics.
        let now = std::time::Instant::now();

        assert!(matches!(
            s.add_event_with_instant(ev3.clone(), now),
            Ok(true)
        ));
        assert!(matches!(s.add_frame(frame3.clone(), false), Ok(())));
        assert!(matches!(s.finish_frames(), Ok(())));

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
