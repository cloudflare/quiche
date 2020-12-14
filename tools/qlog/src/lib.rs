// Copyright (C) 2019, Cloudflare, Inc.
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

//! The qlog crate is an implementation of the [qlog main schema] and [qlog QUIC
//! and HTTP/3 events] that attempts to closely follow the format of the qlog
//! [TypeScript schema]. This is just a data model and no support is provided
//! for logging IO, applications can decide themselves the most appropriate
//! method.
//!
//! The crate uses Serde for conversion between Rust and JSON.
//!
//! [qlog main schema]: https://tools.ietf.org/html/draft-marx-qlog-main-schema
//! [qlog QUIC and HTTP/3 events]:
//! https://quiclog.github.io/internet-drafts/draft-marx-qlog-event-definitions-quic-h3
//! [TypeScript schema]:
//! https://github.com/quiclog/qlog/blob/master/TypeScript/draft-01/QLog.ts
//!
//! Overview
//! ---------------
//! qlog is a hierarchical logging format, with a rough structure of:
//!
//! * Log
//!   * Trace(s)
//!     * Event(s)
//!
//! In practice, a single QUIC connection maps to a single Trace file with one
//! or more Events. Applications can decide whether to combine Traces from
//! different connections into the same Log.
//!
//! ## Traces
//!
//! A [`Trace`] contains metadata such as the [`VantagePoint`] of capture and
//! the [`Configuration`] of the `Trace`.
//!
//! A very important part of the `Trace` is the definition of `event_fields`. A
//! qlog Event is a vector of [`EventField`]; this provides great flexibility to
//! log events with any number of `EventFields` in any order. The `event_fields`
//! property describes the format of event logging and it is important that
//! events comply with that format. Failing to do so it going to cause problems
//! for qlog analysis tools. For information is available at
//! https://tools.ietf.org/html/draft-marx-qlog-main-schema-01#section-3.3.4
//!
//! In order to make using qlog a bit easier, this crate expects a qlog Event to
//! consist of the following EventFields in the following order:
//! [`EventField::RelativeTime`], [`EventField::Category`],
//! [`EventField::Event`] and [`EventField::Data`]. A set of methods are
//! provided to assist in creating a Trace and appending events to it in this
//! format.
//!
//! ## Writing out logs
//! As events occur during the connection, the application appends them to the
//! trace. The qlog crate supports two modes of writing logs: the buffered mode
//! stores everything in memory and requires the application to serialize and
//! write the output, the streaming mode progressively writes serialized JSON
//! output to a writer designated by the application.
//!
//! ### Creating a Trace
//!
//! A typical application needs a single qlog [`Trace`] that it appends QUIC
//! and/or HTTP/3 events to:
//!
//! ```
//! let mut trace = qlog::Trace::new(
//!     qlog::VantagePoint {
//!         name: Some("Example client".to_string()),
//!         ty: qlog::VantagePointType::Client,
//!         flow: None,
//!     },
//!     Some("Example qlog trace".to_string()),
//!     Some("Example qlog trace description".to_string()),
//!     Some(qlog::Configuration {
//!         time_offset: Some("0".to_string()),
//!         time_units: Some(qlog::TimeUnits::Ms),
//!         original_uris: None,
//!     }),
//!     None,
//! );
//! ```
//!
//! ## Adding events
//!
//! Qlog Events are added to [`qlog::Trace.events`].
//!
//! It is recommended to use the provided utility methods to append semantically
//! valid events to a trace. However, there is nothing preventing you from
//! creating the events manually.
//!
//! The following example demonstrates how to log a QUIC packet
//! containing a single Crypto frame. It uses the [`QuicFrame::crypto()`],
//! [`packet_sent_min()`] and [`push_event()`] methods to create and log a
//! PacketSent event and its EventData.
//!
//! ```
//! # let mut trace = qlog::Trace::new (
//! #     qlog::VantagePoint {
//! #         name: Some("Example client".to_string()),
//! #         ty: qlog::VantagePointType::Client,
//! #         flow: None,
//! #     },
//! #     Some("Example qlog trace".to_string()),
//! #     Some("Example qlog trace description".to_string()),
//! #     Some(qlog::Configuration {
//! #         time_offset: Some("0".to_string()),
//! #         time_units: Some(qlog::TimeUnits::Ms),
//! #         original_uris: None,
//! #     }),
//! #     None
//! # );
//!
//! let scid = [0x7e, 0x37, 0xe4, 0xdc, 0xc6, 0x68, 0x2d, 0xa8];
//! let dcid = [0x36, 0xce, 0x10, 0x4e, 0xee, 0x50, 0x10, 0x1c];
//!
//! let pkt_hdr = qlog::PacketHeader::new(
//!     0,
//!     Some(1251),
//!     Some(1224),
//!     Some(0xff00001b),
//!     Some(b"7e37e4dcc6682da8"),
//!     Some(&dcid),
//! );
//!
//! let frames =
//!     vec![qlog::QuicFrame::crypto("0".to_string(), "1000".to_string())];
//!
//! let event = qlog::event::Event::packet_sent_min(
//!     qlog::PacketType::Initial,
//!     pkt_hdr,
//!     Some(frames),
//! );
//!
//! trace.push_event(std::time::Duration::new(0, 0), event);
//! ```
//!
//! ### Serializing
//!
//! The qlog crate has only been tested with `serde_json`, however
//! other serializer targets might work.
//!
//! For example, serializing the trace created above:
//!
//! ```
//! # let mut trace = qlog::Trace::new (
//! #     qlog::VantagePoint {
//! #         name: Some("Example client".to_string()),
//! #         ty: qlog::VantagePointType::Client,
//! #         flow: None,
//! #     },
//! #     Some("Example qlog trace".to_string()),
//! #     Some("Example qlog trace description".to_string()),
//! #     Some(qlog::Configuration {
//! #         time_offset: Some("0".to_string()),
//! #         time_units: Some(qlog::TimeUnits::Ms),
//! #         original_uris: None,
//! #     }),
//! #     None
//! # );
//! serde_json::to_string_pretty(&trace).unwrap();
//! ```
//!
//! which would generate the following:
//!
//! ```ignore
//! {
//!   "vantage_point": {
//!     "name": "Example client",
//!     "type": "client"
//!   },
//!   "title": "Example qlog trace",
//!   "description": "Example qlog trace description",
//!   "configuration": {
//!     "time_units": "ms",
//!     "time_offset": "0"
//!   },
//!   "event_fields": [
//!     "relative_time",
//!     "category",
//!     "event",
//!     "data"
//!   ],
//!   "events": [
//!     [
//!       "0",
//!       "transport",
//!       "packet_sent",
//!       {
//!         "packet_type": "initial",
//!         "header": {
//!           "packet_number": "0",
//!           "packet_size": 1251,
//!           "payload_length": 1224,
//!           "version": "ff00001b",
//!           "scil": "8",
//!           "dcil": "8",
//!           "scid": "7e37e4dcc6682da8",
//!           "dcid": "36ce104eee50101c"
//!         },
//!         "frames": [
//!           {
//!             "frame_type": "crypto",
//!             "offset": "0",
//!             "length": "100",
//!           }
//!         ]
//!       }
//!     ]
//!   ]
//! }
//! ```
//!
//! Streaming Mode
//! --------------
//!
//! Create the trace:
//!
//! ```
//! let mut trace = qlog::Trace::new(
//!     qlog::VantagePoint {
//!         name: Some("Example client".to_string()),
//!         ty: qlog::VantagePointType::Client,
//!         flow: None,
//!     },
//!     Some("Example qlog trace".to_string()),
//!     Some("Example qlog trace description".to_string()),
//!     Some(qlog::Configuration {
//!         time_offset: Some("0".to_string()),
//!         time_units: Some(qlog::TimeUnits::Ms),
//!         original_uris: None,
//!     }),
//!     None,
//! );
//! ```
//! Create an object with the [`Write`] trait:
//!
//! ```
//! let mut file = std::fs::File::create("foo.qlog").unwrap();
//! ```
//!
//! Create a [`QlogStreamer`] and start serialization to foo.qlog
//! using [`start_log()`]:
//!
//! ```
//! # let mut trace = qlog::Trace::new(
//! #    qlog::VantagePoint {
//! #        name: Some("Example client".to_string()),
//! #        ty: qlog::VantagePointType::Client,
//! #        flow: None,
//! #    },
//! #    Some("Example qlog trace".to_string()),
//! #    Some("Example qlog trace description".to_string()),
//! #    Some(qlog::Configuration {
//! #        time_offset: Some("0".to_string()),
//! #        time_units: Some(qlog::TimeUnits::Ms),
//! #        original_uris: None,
//! #    }),
//! #    None,
//! # );
//! # let mut file = std::fs::File::create("foo.qlog").unwrap();
//! let mut streamer = qlog::QlogStreamer::new(
//!     qlog::QLOG_VERSION.to_string(),
//!     Some("Example qlog".to_string()),
//!     Some("Example qlog description".to_string()),
//!     None,
//!     std::time::Instant::now(),
//!     trace,
//!     Box::new(file),
//! );
//!
//! streamer.start_log().ok();
//! ```
//!
//! ### Adding simple events
//!
//! Once logging has started you can stream events. Simple events
//! can be written in one step using [`add_event()`]:
//!
//! ```
//! # let mut trace = qlog::Trace::new(
//! #    qlog::VantagePoint {
//! #        name: Some("Example client".to_string()),
//! #        ty: qlog::VantagePointType::Client,
//! #        flow: None,
//! #    },
//! #    Some("Example qlog trace".to_string()),
//! #    Some("Example qlog trace description".to_string()),
//! #    Some(qlog::Configuration {
//! #        time_offset: Some("0".to_string()),
//! #        time_units: Some(qlog::TimeUnits::Ms),
//! #        original_uris: None,
//! #    }),
//! #    None,
//! # );
//! # let mut file = std::fs::File::create("foo.qlog").unwrap();
//! # let mut streamer = qlog::QlogStreamer::new(
//! #     qlog::QLOG_VERSION.to_string(),
//! #     Some("Example qlog".to_string()),
//! #     Some("Example qlog description".to_string()),
//! #     None,
//! #     std::time::Instant::now(),
//! #     trace,
//! #     Box::new(file),
//! # );
//! let event = qlog::event::Event::metrics_updated_min();
//! streamer.add_event(event).ok();
//! ```
//!
//! ### Adding events with frames
//! Some events contain optional arrays of QUIC frames. If the
//! event has `Some(Vec<QuicFrame>)`, even if it is empty, the
//! streamer enters a frame serializing mode that must be
//! finalized before other events can be logged.
//!
//! In this example, a `PacketSent` event is created with an
//! empty frame array and frames are written out later:
//!
//! ```
//! # let mut trace = qlog::Trace::new(
//! #    qlog::VantagePoint {
//! #        name: Some("Example client".to_string()),
//! #        ty: qlog::VantagePointType::Client,
//! #        flow: None,
//! #    },
//! #    Some("Example qlog trace".to_string()),
//! #    Some("Example qlog trace description".to_string()),
//! #    Some(qlog::Configuration {
//! #        time_offset: Some("0".to_string()),
//! #        time_units: Some(qlog::TimeUnits::Ms),
//! #        original_uris: None,
//! #    }),
//! #    None,
//! # );
//! # let mut file = std::fs::File::create("foo.qlog").unwrap();
//! # let mut streamer = qlog::QlogStreamer::new(
//! #     qlog::QLOG_VERSION.to_string(),
//! #     Some("Example qlog".to_string()),
//! #     Some("Example qlog description".to_string()),
//! #     None,
//! #     std::time::Instant::now(),
//! #     trace,
//! #     Box::new(file),
//! # );
//! let qlog_pkt_hdr = qlog::PacketHeader::with_type(
//!     qlog::PacketType::OneRtt,
//!     0,
//!     Some(1251),
//!     Some(1224),
//!     Some(0xff00001b),
//!     Some(b"7e37e4dcc6682da8"),
//!     Some(b"36ce104eee50101c"),
//! );
//!
//! let event = qlog::event::Event::packet_sent_min(
//!     qlog::PacketType::OneRtt,
//!     qlog_pkt_hdr,
//!     Some(Vec::new()),
//! );
//!
//! streamer.add_event(event).ok();
//! ```
//!
//! In this example, the frames contained in the QUIC packet
//! are PING and PADDING. Each frame is written using the
//! [`add_frame()`] method. Frame writing is concluded with
//! [`finish_frames()`].
//!
//! ```
//! # let mut trace = qlog::Trace::new(
//! #    qlog::VantagePoint {
//! #        name: Some("Example client".to_string()),
//! #        ty: qlog::VantagePointType::Client,
//! #        flow: None,
//! #    },
//! #    Some("Example qlog trace".to_string()),
//! #    Some("Example qlog trace description".to_string()),
//! #    Some(qlog::Configuration {
//! #        time_offset: Some("0".to_string()),
//! #        time_units: Some(qlog::TimeUnits::Ms),
//! #        original_uris: None,
//! #    }),
//! #    None,
//! # );
//! # let mut file = std::fs::File::create("foo.qlog").unwrap();
//! # let mut streamer = qlog::QlogStreamer::new(
//! #     qlog::QLOG_VERSION.to_string(),
//! #     Some("Example qlog".to_string()),
//! #     Some("Example qlog description".to_string()),
//! #     None,
//! #     std::time::Instant::now(),
//! #     trace,
//! #     Box::new(file),
//! # );
//!
//! let ping = qlog::QuicFrame::ping();
//! let padding = qlog::QuicFrame::padding();
//!
//! streamer.add_frame(ping, false).ok();
//! streamer.add_frame(padding, false).ok();
//!
//! streamer.finish_frames().ok();
//! ```
//!
//! Once all events have have been written, the log
//! can be finalized with [`finish_log()`]:
//!
//! ```
//! # let mut trace = qlog::Trace::new(
//! #    qlog::VantagePoint {
//! #        name: Some("Example client".to_string()),
//! #        ty: qlog::VantagePointType::Client,
//! #        flow: None,
//! #    },
//! #    Some("Example qlog trace".to_string()),
//! #    Some("Example qlog trace description".to_string()),
//! #    Some(qlog::Configuration {
//! #        time_offset: Some("0".to_string()),
//! #        time_units: Some(qlog::TimeUnits::Ms),
//! #        original_uris: None,
//! #    }),
//! #    None,
//! # );
//! # let mut file = std::fs::File::create("foo.qlog").unwrap();
//! # let mut streamer = qlog::QlogStreamer::new(
//! #     qlog::QLOG_VERSION.to_string(),
//! #     Some("Example qlog".to_string()),
//! #     Some("Example qlog description".to_string()),
//! #     None,
//! #     std::time::Instant::now(),
//! #     trace,
//! #     Box::new(file),
//! # );
//! streamer.finish_log().ok();
//! ```
//!
//! ### Serializing
//!
//! Serialization to JSON occurs as methods on the [`QlogStreamer`]
//! are called. No additional steps are required.
//!
//! [`Trace`]: struct.Trace.html
//! [`VantagePoint`]: struct.VantagePoint.html
//! [`Configuration`]: struct.Configuration.html
//! [`EventField`]: enum.EventField.html
//! [`EventField::RelativeTime`]: enum.EventField.html#variant.RelativeTime
//! [`EventField::Category`]: enum.EventField.html#variant.Category
//! [`EventField::Type`]: enum.EventField.html#variant.Type
//! [`EventField::Data`]: enum.EventField.html#variant.Data
//! [`qlog::Trace.events`]: struct.Trace.html#structfield.events
//! [`push_event()`]: struct.Trace.html#method.push_event
//! [`packet_sent_min()`]: event/struct.Event.html#method.packet_sent_min
//! [`QuicFrame::crypto()`]: enum.QuicFrame.html#variant.Crypto
//! [`QlogStreamer`]: struct.QlogStreamer.html
//! [`Write`]: https://doc.rust-lang.org/std/io/trait.Write.html
//! [`start_log()`]: struct.QlogStreamer.html#method.start_log
//! [`add_event()`]: struct.QlogStreamer.html#method.add_event
//! [`add_frame()`]: struct.QlogStreamer.html#method.add_frame
//! [`finish_frames()`]: struct.QlogStreamer.html#method.finish_frames
//! [`finish_log()`]: struct.QlogStreamer.html#method.finish_log

use serde::Serialize;

/// A quiche qlog error.
#[derive(Debug)]
pub enum Error {
    /// There is no more work to do.
    Done,

    /// The operation cannot be completed because it was attempted
    /// in an invalid state.
    InvalidState,

    /// I/O error.
    IoError(std::io::Error),
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "{:?}", self)
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        None
    }
}

impl std::convert::From<std::io::Error> for Error {
    fn from(err: std::io::Error) -> Self {
        Error::IoError(err)
    }
}

pub const QLOG_VERSION: &str = "draft-02-wip";

/// A specialized [`Result`] type for quiche qlog operations.
///
/// This type is used throughout the public API for any operation that
/// can produce an error.
///
/// [`Result`]: https://doc.rust-lang.org/std/result/enum.Result.html
pub type Result<T> = std::result::Result<T, Error>;

#[serde_with::skip_serializing_none]
#[derive(Serialize, Clone)]
pub struct Qlog {
    pub qlog_version: String,
    pub title: Option<String>,
    pub description: Option<String>,
    pub summary: Option<String>,

    pub traces: Vec<Trace>,
}

impl Default for Qlog {
    fn default() -> Self {
        Qlog {
            qlog_version: QLOG_VERSION.to_string(),
            title: Some("Default qlog title".to_string()),
            description: Some("Default qlog description".to_string()),
            summary: Some("Default qlog title".to_string()),
            traces: Vec::new(),
        }
    }
}

#[derive(PartialEq)]
pub enum StreamerState {
    Initial,
    Ready,
    WritingFrames,
    Finished,
}

/// A helper object specialized for streaming JSON-serialized qlog to a
/// [`Write`] trait.
///
/// The object is responsible for the `Qlog` object that contains the provided
/// `Trace`.
///
/// Serialization is progressively driven by method calls; once log streaming is
/// started, `event::Events` can be written using `add_event()`. Some events
/// can contain an array of `QuicFrame`s, when writing such an event, the
/// streamer enters a frame-serialization mode where frames are be progressively
/// written using `add_frame()`. This mode is concluded using
/// `finished_frames()`. While serializing frames, any attempts to log
/// additional events are ignored.
///
/// [`Write`]: https://doc.rust-lang.org/std/io/trait.Write.html
pub struct QlogStreamer {
    start_time: std::time::Instant,
    writer: Box<dyn std::io::Write + Send + Sync>,
    qlog: Qlog,
    state: StreamerState,
    first_event: bool,
    first_frame: bool,
}

impl QlogStreamer {
    /// Creates a QlogStreamer object.
    ///
    /// It owns a `Qlog` object that contains the provided `Trace`, which must
    /// have the following ordered-set of names EventFields:
    ///
    /// ["relative_time", "category", "event".to_string(), "data"]
    ///
    /// All serialization will be written to the provided `Write`.
    pub fn new(
        qlog_version: String, title: Option<String>, description: Option<String>,
        summary: Option<String>, start_time: std::time::Instant, trace: Trace,
        writer: Box<dyn std::io::Write + Send + Sync>,
    ) -> Self {
        let qlog = Qlog {
            qlog_version,
            title,
            description,
            summary,
            traces: vec![trace],
        };

        QlogStreamer {
            start_time,
            writer,
            qlog,
            state: StreamerState::Initial,
            first_event: true,
            first_frame: false,
        }
    }

    /// Starts qlog streaming serialization.
    ///
    /// This writes out the JSON-serialized form of all information up to qlog
    /// `Trace`'s array of `EventField`s. EventFields are separately appended
    /// using functions that accept and `event::Event`.
    pub fn start_log(&mut self) -> Result<()> {
        if self.state != StreamerState::Initial {
            return Err(Error::Done);
        }

        // A qlog contains a trace holding a vector of events that we want to
        // serialize in a streaming manner. So at the start of serialization,
        // take off all closing delimiters, and leave us in a state to accept
        // new events.
        match serde_json::to_string(&self.qlog) {
            Ok(mut out) => {
                out.truncate(out.len() - 4);

                self.writer.as_mut().write_all(out.as_bytes())?;

                self.state = StreamerState::Ready;

                self.first_event = self.qlog.traces[0].events.is_empty();
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

        self.writer.as_mut().write_all(b"]}]}")?;

        self.state = StreamerState::Finished;

        self.writer.as_mut().flush()?;

        Ok(())
    }

    /// Writes a JSON-serialized `EventField`s.
    ///
    /// Some qlog events can contain `QuicFrames`. If this is detected `true` is
    /// returned and the streamer enters a frame-serialization mode that is only
    /// concluded by `finish_frames()`. In this mode, attempts to log additional
    /// events are ignored.
    ///
    /// If the event contains no array of `QuicFrames` return `false`.
    pub fn add_event(&mut self, event: event::Event) -> Result<bool> {
        if self.state != StreamerState::Ready {
            return Err(Error::InvalidState);
        }

        let event_time = if cfg!(test) {
            std::time::Duration::from_secs(0)
        } else {
            self.start_time.elapsed()
        };

        let rel = match &self.qlog.traces[0].configuration {
            Some(conf) => match conf.time_units {
                Some(TimeUnits::Ms) => event_time.as_millis().to_string(),

                Some(TimeUnits::Us) => event_time.as_micros().to_string(),

                None => String::from(""),
            },

            None => String::from(""),
        };

        let (ev_data, contains_frames) = match serde_json::to_string(&event.data)
        {
            Ok(mut ev_data_out) =>
                if let Some(f) = event.data.contains_quic_frames() {
                    ev_data_out.truncate(ev_data_out.len() - 2);

                    if f == 0 {
                        self.first_frame = true;
                    }

                    (ev_data_out, true)
                } else {
                    (ev_data_out, false)
                },

            _ => return Err(Error::Done),
        };

        let maybe_comma = if self.first_event {
            self.first_event = false;
            ""
        } else {
            ","
        };

        let maybe_terminate = if contains_frames { "" } else { "]" };

        let ev_time = serde_json::to_string(&EventField::RelativeTime(rel)).ok();
        let ev_cat =
            serde_json::to_string(&EventField::Category(event.category)).ok();
        let ev_ty = serde_json::to_string(&EventField::Event(event.ty)).ok();

        if let (Some(ev_time), Some(ev_cat), Some(ev_ty)) =
            (ev_time, ev_cat, ev_ty)
        {
            let out = format!(
                "{}[{},{},{},{}{}",
                maybe_comma, ev_time, ev_cat, ev_ty, ev_data, maybe_terminate
            );

            self.writer.as_mut().write_all(out.as_bytes())?;

            if contains_frames {
                self.state = StreamerState::WritingFrames
            } else {
                self.state = StreamerState::Ready
            };

            return Ok(contains_frames);
        }

        Err(Error::Done)
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

        self.writer.as_mut().write_all(b"]}]")?;
        self.state = StreamerState::Ready;

        Ok(())
    }

    /// Returns the writer.
    #[allow(clippy::borrowed_box)]
    pub fn writer(&self) -> &Box<dyn std::io::Write + Send + Sync> {
        &self.writer
    }
}

#[serde_with::skip_serializing_none]
#[derive(Serialize, Clone)]
pub struct Trace {
    pub vantage_point: VantagePoint,
    pub title: Option<String>,
    pub description: Option<String>,

    pub configuration: Option<Configuration>,

    pub common_fields: Option<CommonFields>,
    pub event_fields: Vec<String>,

    pub events: Vec<Vec<EventField>>,
}

/// Helper functions for using a qlog trace.
impl Trace {
    /// Creates a new qlog trace with the hard-coded event_fields
    /// ["relative_time", "category", "event", "data"]
    pub fn new(
        vantage_point: VantagePoint, title: Option<String>,
        description: Option<String>, configuration: Option<Configuration>,
        common_fields: Option<CommonFields>,
    ) -> Self {
        Trace {
            vantage_point,
            title,
            description,
            configuration,
            common_fields,
            event_fields: vec![
                "relative_time".to_string(),
                "category".to_string(),
                "event".to_string(),
                "data".to_string(),
            ],
            events: Vec::new(),
        }
    }

    pub fn push_event(
        &mut self, relative_time: std::time::Duration, event: crate::event::Event,
    ) {
        let rel = match &self.configuration {
            Some(conf) => match conf.time_units {
                Some(TimeUnits::Ms) => relative_time.as_millis().to_string(),

                Some(TimeUnits::Us) => relative_time.as_micros().to_string(),

                None => String::from(""),
            },

            None => String::from(""),
        };

        self.events.push(vec![
            EventField::RelativeTime(rel),
            EventField::Category(event.category),
            EventField::Event(event.ty),
            EventField::Data(event.data),
        ]);
    }
}

#[serde_with::skip_serializing_none]
#[derive(Serialize, Clone)]
pub struct VantagePoint {
    pub name: Option<String>,

    #[serde(rename = "type")]
    pub ty: VantagePointType,

    pub flow: Option<VantagePointType>,
}

#[derive(Serialize, Clone)]
#[serde(rename_all = "snake_case")]
pub enum VantagePointType {
    Client,
    Server,
    Network,
    Unknown,
}

#[derive(Serialize, Clone)]
#[serde(rename_all = "snake_case")]
pub enum TimeUnits {
    Ms,
    Us,
}

#[serde_with::skip_serializing_none]
#[derive(Serialize, Clone)]
pub struct Configuration {
    pub time_units: Option<TimeUnits>,
    pub time_offset: Option<String>,

    pub original_uris: Option<Vec<String>>,
    /* TODO
     * additionalUserSpecifiedProperty */
}

impl Default for Configuration {
    fn default() -> Self {
        Configuration {
            time_units: Some(TimeUnits::Ms),
            time_offset: Some("0".to_string()),
            original_uris: None,
        }
    }
}

#[serde_with::skip_serializing_none]
#[derive(Serialize, Clone, Default)]
pub struct CommonFields {
    pub group_id: Option<String>,
    pub protocol_type: Option<String>,

    pub reference_time: Option<String>,
    /* TODO
     * additionalUserSpecifiedProperty */
}

#[derive(Serialize, Clone)]
#[serde(untagged)]
pub enum EventType {
    ConnectivityEventType(ConnectivityEventType),

    TransportEventType(TransportEventType),

    SecurityEventType(SecurityEventType),

    RecoveryEventType(RecoveryEventType),

    Http3EventType(Http3EventType),

    QpackEventType(QpackEventType),

    GenericEventType(GenericEventType),
}

#[derive(Serialize, Clone)]
#[serde(untagged)]
#[allow(clippy::large_enum_variant)]
pub enum EventField {
    RelativeTime(String),

    Category(EventCategory),

    Event(EventType),

    Data(EventData),
}

#[derive(Serialize, Clone)]
#[serde(rename_all = "snake_case")]
pub enum EventCategory {
    Connectivity,
    Security,
    Transport,
    Recovery,
    Http,
    Qpack,

    Error,
    Warning,
    Info,
    Debug,
    Verbose,
    Simulation,
}

#[derive(Serialize, Clone)]
#[serde(rename_all = "snake_case")]
pub enum ConnectivityEventType {
    ServerListening,
    ConnectionStarted,
    ConnectionIdUpdated,
    SpinBitUpdated,
    ConnectionStateUpdated,
}

#[derive(Serialize, Clone)]
#[serde(rename_all = "snake_case")]
pub enum TransportEventType {
    ParametersSet,

    DatagramsSent,
    DatagramsReceived,
    DatagramDropped,

    PacketSent,
    PacketReceived,
    PacketDropped,
    PacketBuffered,

    FramesProcessed,

    StreamStateUpdated,
}

#[derive(Serialize, Clone)]
#[serde(rename_all = "snake_case")]
pub enum TransportEventTrigger {
    Line,
    Retransmit,
    KeysUnavailable,
}

#[derive(Serialize, Clone)]
#[serde(rename_all = "snake_case")]
pub enum SecurityEventType {
    KeyUpdated,
    KeyRetired,
}

#[derive(Serialize, Clone)]
#[serde(rename_all = "snake_case")]
pub enum SecurityEventTrigger {
    Tls,
    Implicit,
    RemoteUpdate,
    LocalUpdate,
}

#[derive(Serialize, Clone)]
#[serde(rename_all = "snake_case")]
pub enum RecoveryEventType {
    ParametersSet,
    MetricsUpdated,
    CongestionStateUpdated,
    LossTimerSet,
    LossTimerTriggered,
    PacketLost,
    MarkedForRetransmit,
}

#[derive(Serialize, Clone)]
#[serde(rename_all = "snake_case")]
pub enum RecoveryEventTrigger {
    AckReceived,
    PacketSent,
    Alarm,
    Unknown,
}

// ================================================================== //

#[derive(Serialize, Clone)]
#[serde(rename_all = "snake_case")]
pub enum KeyType {
    ServerInitialSecret,
    ClientInitialSecret,

    ServerHandshakeSecret,
    ClientHandshakeSecret,

    Server0RttSecret,
    Client0RttSecret,

    Server1RttSecret,
    Client1RttSecret,
}

#[derive(Serialize, Clone)]
#[serde(rename_all = "snake_case")]
pub enum ConnectionState {
    Attempted,
    Reset,
    Handshake,
    Active,
    Keepalive,
    Draining,
    Closed,
}

#[derive(Serialize, Clone)]
#[serde(rename_all = "snake_case")]
pub enum TransportOwner {
    Local,
    Remote,
}

#[derive(Serialize, Clone)]
pub struct PreferredAddress {
    pub ip_v4: String,
    pub ip_v6: String,

    pub port_v4: u64,
    pub port_v6: u64,

    pub connection_id: String,
    pub stateless_reset_token: String,
}

#[derive(Serialize, Clone)]
#[serde(rename_all = "snake_case")]
pub enum StreamSide {
    Sending,
    Receiving,
}

#[derive(Serialize, Clone)]
#[serde(rename_all = "snake_case")]
pub enum StreamState {
    // bidirectional stream states, draft-23 3.4.
    Idle,
    Open,
    HalfClosedLocal,
    HalfClosedRemote,
    Closed,

    // sending-side stream states, draft-23 3.1.
    Ready,
    Send,
    DataSent,
    ResetSent,
    ResetReceived,

    // receive-side stream states, draft-23 3.2.
    Receive,
    SizeKnown,
    DataRead,
    ResetRead,

    // both-side states
    DataReceived,

    // qlog-defined
    Destroyed,
}

#[derive(Serialize, Clone)]
#[serde(rename_all = "snake_case")]
pub enum TimerType {
    Ack,
    Pto,
}

#[derive(Serialize, Clone)]
#[serde(rename_all = "snake_case")]
pub enum H3Owner {
    Local,
    Remote,
}

#[derive(Serialize, Clone)]
#[serde(rename_all = "snake_case")]
pub enum H3StreamType {
    Data,
    Control,
    Push,
    Reserved,
    QpackEncode,
    QpackDecode,
}

#[derive(Serialize, Clone)]
#[serde(rename_all = "snake_case")]
pub enum H3DataRecipient {
    Application,
    Transport,
}

#[derive(Serialize, Clone)]
#[serde(rename_all = "snake_case")]
pub enum H3PushDecision {
    Claimed,
    Abandoned,
}

#[derive(Serialize, Clone)]
#[serde(rename_all = "snake_case")]
pub enum QpackOwner {
    Local,
    Remote,
}

#[derive(Serialize, Clone)]
#[serde(rename_all = "snake_case")]
pub enum QpackStreamState {
    Blocked,
    Unblocked,
}

#[derive(Serialize, Clone)]
#[serde(rename_all = "snake_case")]
pub enum QpackUpdateType {
    Added,
    Evicted,
}

#[derive(Serialize, Clone)]
pub struct QpackDynamicTableEntry {
    pub index: u64,
    pub name: Option<String>,
    pub value: Option<String>,
}

#[derive(Serialize, Clone)]
pub struct QpackHeaderBlockPrefix {
    pub required_insert_count: u64,
    pub sign_bit: bool,
    pub delta_base: u64,
}

#[serde_with::skip_serializing_none]
#[derive(Serialize, Clone)]
#[serde(untagged)]
#[allow(clippy::large_enum_variant)]
pub enum EventData {
    // ================================================================== //
    // CONNECTIVITY
    ServerListening {
        ip_v4: Option<String>,
        ip_v6: Option<String>,
        port_v4: u64,
        port_v6: u64,

        quic_versions: Option<Vec<String>>,
        alpn_values: Option<Vec<String>>,

        stateless_reset_required: Option<bool>,
    },

    ConnectionStarted {
        ip_version: String,
        src_ip: String,
        dst_ip: String,

        protocol: Option<String>,
        src_port: u64,
        dst_port: u64,

        quic_version: Option<String>,
        src_cid: Option<String>,
        dst_cid: Option<String>,
    },

    ConnectionIdUpdated {
        src_old: Option<String>,
        src_new: Option<String>,

        dst_old: Option<String>,
        dst_new: Option<String>,
    },

    SpinBitUpdated {
        state: bool,
    },

    ConnectionStateUpdated {
        old: Option<ConnectionState>,
        new: ConnectionState,
    },

    // ================================================================== //
    // SECURITY
    KeyUpdated {
        key_type: KeyType,
        old: Option<String>,
        new: String,
        generation: Option<u64>,
    },

    KeyRetired {
        key_type: KeyType,
        key: Option<String>,
        generation: Option<u64>,
    },

    // ================================================================== //
    // TRANSPORT
    TransportParametersSet {
        owner: Option<TransportOwner>,

        resumption_allowed: Option<bool>,
        early_data_enabled: Option<bool>,
        alpn: Option<String>,
        version: Option<String>,
        tls_cipher: Option<String>,

        original_connection_id: Option<String>,
        stateless_reset_token: Option<String>,
        disable_active_migration: Option<bool>,

        idle_timeout: Option<u64>,
        max_packet_size: Option<u64>,
        ack_delay_exponent: Option<u64>,
        max_ack_delay: Option<u64>,
        active_connection_id_limit: Option<u64>,

        initial_max_data: Option<String>,
        initial_max_stream_data_bidi_local: Option<String>,
        initial_max_stream_data_bidi_remote: Option<String>,
        initial_max_stream_data_uni: Option<String>,
        initial_max_streams_bidi: Option<String>,
        initial_max_streams_uni: Option<String>,

        preferred_address: Option<PreferredAddress>,
    },

    DatagramsReceived {
        count: Option<u64>,
        byte_length: Option<u64>,
    },

    DatagramsSent {
        count: Option<u64>,
        byte_length: Option<u64>,
    },

    DatagramDropped {
        byte_length: Option<u64>,
    },

    PacketReceived {
        packet_type: PacketType,
        header: PacketHeader,
        // `frames` is defined here in the QLog schema specification. However,
        // our streaming serializer requires serde to put the object at the end,
        // so we define it there and depend on serde's preserve_order feature.
        is_coalesced: Option<bool>,

        raw_encrypted: Option<String>,
        raw_decrypted: Option<String>,
        frames: Option<Vec<QuicFrame>>,
    },

    PacketSent {
        packet_type: PacketType,
        header: PacketHeader,
        // `frames` is defined here in the QLog schema specification. However,
        // our streaming serializer requires serde to put the object at the end,
        // so we define it there and depend on serde's preserve_order feature.
        is_coalesced: Option<bool>,

        raw_encrypted: Option<String>,
        raw_decrypted: Option<String>,
        frames: Option<Vec<QuicFrame>>,
    },

    PacketDropped {
        packet_type: Option<PacketType>,
        packet_size: Option<u64>,

        raw: Option<String>,
    },

    PacketBuffered {
        packet_type: PacketType,
        packet_number: String,
    },

    StreamStateUpdated {
        stream_id: String,
        stream_type: Option<StreamType>,

        old: Option<StreamState>,
        new: StreamState,

        stream_side: Option<StreamSide>,
    },

    FramesProcessed {
        frames: Vec<QuicFrame>,
    },

    // ================================================================== //
    // RECOVERY
    RecoveryParametersSet {
        reordering_threshold: Option<u64>,
        time_threshold: Option<u64>,
        timer_granularity: Option<u64>,
        initial_rtt: Option<u64>,

        max_datagram_size: Option<u64>,
        initial_congestion_window: Option<u64>,
        minimum_congestion_window: Option<u64>,
        loss_reduction_factor: Option<u64>,
        persistent_congestion_threshold: Option<u64>,
    },

    MetricsUpdated {
        min_rtt: Option<u64>,
        smoothed_rtt: Option<u64>,
        latest_rtt: Option<u64>,
        rtt_variance: Option<u64>,

        max_ack_delay: Option<u64>,
        pto_count: Option<u64>,

        congestion_window: Option<u64>,
        bytes_in_flight: Option<u64>,

        ssthresh: Option<u64>,

        // qlog defined
        packets_in_flight: Option<u64>,
        in_recovery: Option<bool>,

        pacing_rate: Option<u64>,
    },

    CongestionStateUpdated {
        old: Option<String>,
        new: String,
    },

    LossTimerSet {
        timer_type: Option<TimerType>,
        timeout: Option<String>,
    },

    PacketLost {
        packet_type: PacketType,
        packet_number: String,

        header: Option<PacketHeader>,
        frames: Vec<QuicFrame>,
    },

    MarkedForRetransmit {
        frames: Vec<QuicFrame>,
    },

    // ================================================================== //
    // HTTP/3
    H3ParametersSet {
        owner: Option<H3Owner>,

        max_header_list_size: Option<u64>,
        max_table_capacity: Option<u64>,
        blocked_streams_count: Option<u64>,

        push_allowed: Option<bool>,

        waits_for_settings: Option<bool>,
    },

    H3StreamTypeSet {
        stream_id: String,
        owner: Option<H3Owner>,

        old: Option<H3StreamType>,
        new: H3StreamType,
    },

    H3FrameCreated {
        stream_id: String,
        frame: Http3Frame,
        byte_length: Option<String>,

        raw: Option<String>,
    },

    H3FrameParsed {
        stream_id: String,
        frame: Http3Frame,
        byte_length: Option<String>,

        raw: Option<String>,
    },

    H3DataMoved {
        stream_id: String,
        offset: Option<String>,
        length: Option<u64>,

        from: Option<H3DataRecipient>,
        to: Option<H3DataRecipient>,

        raw: Option<String>,
    },

    H3PushResolved {
        push_id: Option<String>,
        stream_id: Option<String>,

        decision: Option<H3PushDecision>,
    },

    // ================================================================== //
    // QPACK
    QpackStateUpdated {
        owner: Option<QpackOwner>,

        dynamic_table_capacity: Option<u64>,
        dynamic_table_size: Option<u64>,

        known_received_count: Option<u64>,
        current_insert_count: Option<u64>,
    },

    QpackStreamStateUpdated {
        stream_id: String,

        state: QpackStreamState,
    },

    QpackDynamicTableUpdated {
        update_type: QpackUpdateType,

        entries: Vec<QpackDynamicTableEntry>,
    },

    QpackHeadersEncoded {
        stream_id: Option<String>,

        headers: Option<HttpHeader>,

        block_prefix: QpackHeaderBlockPrefix,
        header_block: Vec<QpackHeaderBlockRepresentation>,

        raw: Option<String>,
    },

    QpackHeadersDecoded {
        stream_id: Option<String>,

        headers: Option<HttpHeader>,

        block_prefix: QpackHeaderBlockPrefix,
        header_block: Vec<QpackHeaderBlockRepresentation>,

        raw: Option<String>,
    },

    QpackInstructionSent {
        instruction: QPackInstruction,
        byte_length: Option<String>,

        raw: Option<String>,
    },

    QpackInstructionReceived {
        instruction: QPackInstruction,
        byte_length: Option<String>,

        raw: Option<String>,
    },

    // ================================================================== //
    // Generic
    ConnectionError {
        code: Option<ConnectionErrorCode>,
        description: Option<String>,
    },

    ApplicationError {
        code: Option<ApplicationErrorCode>,
        description: Option<String>,
    },

    InternalError {
        code: Option<u64>,
        description: Option<String>,
    },

    InternalWarning {
        code: Option<u64>,
        description: Option<String>,
    },

    Message {
        message: String,
    },

    Marker {
        marker_type: String,
        message: Option<String>,
    },
}

impl EventData {
    /// Returns size of `EventData` array of `QuicFrame`s if it exists.
    pub fn contains_quic_frames(&self) -> Option<usize> {
        // For some EventData variants, the frame array is optional
        // but for others it is mandatory.
        match self {
            EventData::PacketSent { frames, .. } |
            EventData::PacketReceived { frames, .. } =>
                if let Some(f) = frames {
                    Some(f.len())
                } else {
                    None
                },

            EventData::PacketLost { frames, .. } |
            EventData::MarkedForRetransmit { frames } |
            EventData::FramesProcessed { frames } => Some(frames.len()),

            _ => None,
        }
    }
}

#[derive(Serialize, Clone)]
#[serde(rename_all = "snake_case")]
pub enum PacketType {
    Initial,
    Handshake,

    #[serde(rename = "0RTT")]
    ZeroRtt,

    #[serde(rename = "1RTT")]
    OneRtt,

    Retry,
    VersionNegotiation,
    Unknown,
}

#[derive(Serialize, Clone)]
#[serde(rename_all = "snake_case")]
pub enum Http3EventType {
    ParametersSet,
    StreamTypeSet,
    FrameCreated,
    FrameParsed,
    DataMoved,
    PushResolved,
}

#[derive(Serialize, Clone)]
#[serde(rename_all = "snake_case")]
pub enum QpackEventType {
    StateUpdated,
    StreamStateUpdated,
    DynamicTableUpdated,
    HeadersEncoded,
    HeadersDecoded,
    InstructionSent,
    InstructionReceived,
}

#[derive(Serialize, Clone)]
#[serde(rename_all = "snake_case")]
pub enum QuicFrameTypeName {
    Padding,
    Ping,
    Ack,
    ResetStream,
    StopSending,
    Crypto,
    NewToken,
    Stream,
    MaxData,
    MaxStreamData,
    MaxStreams,
    DataBlocked,
    StreamDataBlocked,
    StreamsBlocked,
    NewConnectionId,
    RetireConnectionId,
    PathChallenge,
    PathResponse,
    ConnectionClose,
    ApplicationClose,
    HandshakeDone,
    Datagram,
    Unknown,
}

// TODO: search for pub enum Error { to see how best to encode errors in qlog.
#[serde_with::skip_serializing_none]
#[derive(Clone, Serialize)]
pub struct PacketHeader {
    pub packet_number: String,
    pub packet_size: Option<u64>,
    pub payload_length: Option<u64>,
    pub version: Option<String>,
    pub scil: Option<String>,
    pub dcil: Option<String>,
    pub scid: Option<String>,
    pub dcid: Option<String>,
}

impl PacketHeader {
    /// Creates a new PacketHeader.
    pub fn new(
        packet_number: u64, packet_size: Option<u64>,
        payload_length: Option<u64>, version: Option<u32>, scid: Option<&[u8]>,
        dcid: Option<&[u8]>,
    ) -> Self {
        let (scil, scid) = match scid {
            Some(cid) => (
                Some(cid.len().to_string()),
                Some(format!("{}", HexSlice::new(&cid))),
            ),

            None => (None, None),
        };

        let (dcil, dcid) = match dcid {
            Some(cid) => (
                Some(cid.len().to_string()),
                Some(format!("{}", HexSlice::new(&cid))),
            ),

            None => (None, None),
        };

        let version = match version {
            Some(v) => Some(format!("{:x?}", v)),

            None => None,
        };

        PacketHeader {
            packet_number: packet_number.to_string(),
            packet_size,
            payload_length,
            version,
            scil,
            dcil,
            scid,
            dcid,
        }
    }

    /// Creates a new PacketHeader.
    ///
    /// Once a QUIC connection has formed, version, dcid and scid are stable, so
    /// there are space benefits to not logging them in every packet, especially
    /// PacketType::OneRtt.
    pub fn with_type(
        ty: PacketType, packet_number: u64, packet_size: Option<u64>,
        payload_length: Option<u64>, version: Option<u32>, scid: Option<&[u8]>,
        dcid: Option<&[u8]>,
    ) -> Self {
        match ty {
            PacketType::OneRtt => PacketHeader::new(
                packet_number,
                packet_size,
                payload_length,
                None,
                None,
                None,
            ),

            _ => PacketHeader::new(
                packet_number,
                packet_size,
                payload_length,
                version,
                scid,
                dcid,
            ),
        }
    }
}

#[derive(Serialize, Clone)]
#[serde(rename_all = "snake_case")]
pub enum StreamType {
    Bidirectional,
    Unidirectional,
}

#[derive(Serialize, Clone)]
#[serde(rename_all = "snake_case")]
pub enum ErrorSpace {
    TransportError,
    ApplicationError,
}

#[derive(Serialize, Clone)]
#[serde(rename_all = "snake_case")]
pub enum GenericEventType {
    ConnectionError,
    ApplicationError,
    InternalError,
    InternalWarning,

    Message,
    Marker,
}

#[derive(Serialize, Clone)]
#[serde(untagged)]
pub enum ConnectionErrorCode {
    TransportError(TransportError),
    CryptoError(CryptoError),
    Value(u64),
}

#[derive(Serialize, Clone)]
#[serde(untagged)]
pub enum ApplicationErrorCode {
    ApplicationError(ApplicationError),
    Value(u64),
}

#[derive(Serialize, Clone)]
#[serde(rename_all = "snake_case")]
pub enum TransportError {
    NoError,
    InternalError,
    ServerBusy,
    FlowControlError,
    StreamLimitError,
    StreamStateError,
    FinalSizeError,
    FrameEncodingError,
    TransportParameterError,
    ProtocolViolation,
    InvalidMigration,
    CryptoBufferExceeded,
    Unknown,
}

// TODO
#[derive(Serialize, Clone)]
#[serde(rename_all = "snake_case")]
pub enum CryptoError {
    Prefix,
}

#[derive(Serialize, Clone)]
#[serde(rename_all = "snake_case")]
pub enum ApplicationError {
    HttpNoError,
    HttpGeneralProtocolError,
    HttpInternalError,
    HttpRequestCancelled,
    HttpIncompleteRequest,
    HttpConnectError,
    HttpFrameError,
    HttpExcessiveLoad,
    HttpVersionFallback,
    HttpIdError,
    HttpStreamCreationError,
    HttpClosedCriticalStream,
    HttpEarlyResponse,
    HttpMissingSettings,
    HttpUnexpectedFrame,
    HttpRequestRejection,
    HttpSettingsError,
    Unknown,
}

#[serde_with::skip_serializing_none]
#[derive(Serialize, Clone)]
#[serde(untagged)]
pub enum QuicFrame {
    Padding {
        frame_type: QuicFrameTypeName,
    },

    Ping {
        frame_type: QuicFrameTypeName,
    },

    Ack {
        frame_type: QuicFrameTypeName,
        ack_delay: Option<String>,
        acked_ranges: Option<Vec<(u64, u64)>>,

        ect1: Option<String>,

        ect0: Option<String>,

        ce: Option<String>,
    },

    ResetStream {
        frame_type: QuicFrameTypeName,
        stream_id: String,
        error_code: u64,
        final_size: String,
    },

    StopSending {
        frame_type: QuicFrameTypeName,
        stream_id: String,
        error_code: u64,
    },

    Crypto {
        frame_type: QuicFrameTypeName,
        offset: String,
        length: String,
    },

    NewToken {
        frame_type: QuicFrameTypeName,
        length: String,
        token: String,
    },

    Stream {
        frame_type: QuicFrameTypeName,
        stream_id: String,
        offset: String,
        length: String,
        fin: bool,

        raw: Option<String>,
    },

    MaxData {
        frame_type: QuicFrameTypeName,
        maximum: String,
    },

    MaxStreamData {
        frame_type: QuicFrameTypeName,
        stream_id: String,
        maximum: String,
    },

    MaxStreams {
        frame_type: QuicFrameTypeName,
        stream_type: StreamType,
        maximum: String,
    },

    DataBlocked {
        frame_type: QuicFrameTypeName,
        limit: String,
    },

    StreamDataBlocked {
        frame_type: QuicFrameTypeName,
        stream_id: String,
        limit: String,
    },

    StreamsBlocked {
        frame_type: QuicFrameTypeName,
        stream_type: StreamType,
        limit: String,
    },

    NewConnectionId {
        frame_type: QuicFrameTypeName,
        sequence_number: String,
        retire_prior_to: String,
        length: u64,
        connection_id: String,
        reset_token: String,
    },

    RetireConnectionId {
        frame_type: QuicFrameTypeName,
        sequence_number: String,
    },

    PathChallenge {
        frame_type: QuicFrameTypeName,

        data: Option<String>,
    },

    PathResponse {
        frame_type: QuicFrameTypeName,

        data: Option<String>,
    },

    ConnectionClose {
        frame_type: QuicFrameTypeName,
        error_space: ErrorSpace,
        error_code: u64,
        raw_error_code: u64,
        reason: String,

        trigger_frame_type: Option<String>,
    },

    HandshakeDone {
        frame_type: QuicFrameTypeName,
    },

    Datagram {
        frame_type: QuicFrameTypeName,
        length: String,

        raw: Option<String>,
    },

    Unknown {
        frame_type: QuicFrameTypeName,
        raw_frame_type: u64,
    },
}

impl QuicFrame {
    pub fn padding() -> Self {
        QuicFrame::Padding {
            frame_type: QuicFrameTypeName::Padding,
        }
    }

    pub fn ping() -> Self {
        QuicFrame::Ping {
            frame_type: QuicFrameTypeName::Ping,
        }
    }

    pub fn ack(
        ack_delay: Option<String>, acked_ranges: Option<Vec<(u64, u64)>>,
        ect1: Option<String>, ect0: Option<String>, ce: Option<String>,
    ) -> Self {
        QuicFrame::Ack {
            frame_type: QuicFrameTypeName::Ack,
            ack_delay,
            acked_ranges,
            ect1,
            ect0,
            ce,
        }
    }

    pub fn reset_stream(
        stream_id: String, error_code: u64, final_size: String,
    ) -> Self {
        QuicFrame::ResetStream {
            frame_type: QuicFrameTypeName::ResetStream,
            stream_id,
            error_code,
            final_size,
        }
    }

    pub fn stop_sending(stream_id: String, error_code: u64) -> Self {
        QuicFrame::StopSending {
            frame_type: QuicFrameTypeName::StopSending,
            stream_id,
            error_code,
        }
    }

    pub fn crypto(offset: String, length: String) -> Self {
        QuicFrame::Crypto {
            frame_type: QuicFrameTypeName::Crypto,
            offset,
            length,
        }
    }

    pub fn new_token(length: String, token: String) -> Self {
        QuicFrame::NewToken {
            frame_type: QuicFrameTypeName::NewToken,
            length,
            token,
        }
    }

    pub fn stream(
        stream_id: String, offset: String, length: String, fin: bool,
        raw: Option<String>,
    ) -> Self {
        QuicFrame::Stream {
            frame_type: QuicFrameTypeName::Stream,
            stream_id,
            offset,
            length,
            fin,
            raw,
        }
    }

    pub fn max_data(maximum: String) -> Self {
        QuicFrame::MaxData {
            frame_type: QuicFrameTypeName::MaxData,
            maximum,
        }
    }

    pub fn max_stream_data(stream_id: String, maximum: String) -> Self {
        QuicFrame::MaxStreamData {
            frame_type: QuicFrameTypeName::MaxStreamData,
            stream_id,
            maximum,
        }
    }

    pub fn max_streams(stream_type: StreamType, maximum: String) -> Self {
        QuicFrame::MaxStreams {
            frame_type: QuicFrameTypeName::MaxStreams,
            stream_type,
            maximum,
        }
    }

    pub fn data_blocked(limit: String) -> Self {
        QuicFrame::DataBlocked {
            frame_type: QuicFrameTypeName::DataBlocked,
            limit,
        }
    }

    pub fn stream_data_blocked(stream_id: String, limit: String) -> Self {
        QuicFrame::StreamDataBlocked {
            frame_type: QuicFrameTypeName::StreamDataBlocked,
            stream_id,
            limit,
        }
    }

    pub fn streams_blocked(stream_type: StreamType, limit: String) -> Self {
        QuicFrame::StreamsBlocked {
            frame_type: QuicFrameTypeName::StreamsBlocked,
            stream_type,
            limit,
        }
    }

    pub fn new_connection_id(
        sequence_number: String, retire_prior_to: String, length: u64,
        connection_id: String, reset_token: String,
    ) -> Self {
        QuicFrame::NewConnectionId {
            frame_type: QuicFrameTypeName::NewConnectionId,
            sequence_number,
            retire_prior_to,
            length,
            connection_id,
            reset_token,
        }
    }

    pub fn retire_connection_id(sequence_number: String) -> Self {
        QuicFrame::RetireConnectionId {
            frame_type: QuicFrameTypeName::RetireConnectionId,
            sequence_number,
        }
    }

    pub fn path_challenge(data: Option<String>) -> Self {
        QuicFrame::PathChallenge {
            frame_type: QuicFrameTypeName::PathChallenge,
            data,
        }
    }

    pub fn path_response(data: Option<String>) -> Self {
        QuicFrame::PathResponse {
            frame_type: QuicFrameTypeName::PathResponse,
            data,
        }
    }

    pub fn connection_close(
        error_space: ErrorSpace, error_code: u64, raw_error_code: u64,
        reason: String, trigger_frame_type: Option<String>,
    ) -> Self {
        QuicFrame::ConnectionClose {
            frame_type: QuicFrameTypeName::ConnectionClose,
            error_space,
            error_code,
            raw_error_code,
            reason,
            trigger_frame_type,
        }
    }

    pub fn handshake_done() -> Self {
        QuicFrame::HandshakeDone {
            frame_type: QuicFrameTypeName::HandshakeDone,
        }
    }

    pub fn datagram(length: String, raw: Option<String>) -> Self {
        QuicFrame::Datagram {
            frame_type: QuicFrameTypeName::Datagram,
            length,
            raw,
        }
    }

    pub fn unknown(raw_frame_type: u64) -> Self {
        QuicFrame::Unknown {
            frame_type: QuicFrameTypeName::Unknown,
            raw_frame_type,
        }
    }
}

// ================================================================== //
#[derive(Serialize, Clone)]
#[serde(rename_all = "snake_case")]
pub enum Http3FrameTypeName {
    Data,
    Headers,
    CancelPush,
    Settings,
    PushPromise,
    Goaway,
    MaxPushId,
    DuplicatePush,
    Reserved,
    Unknown,
}

#[derive(Serialize, Clone)]
pub struct HttpHeader {
    pub name: String,
    pub value: String,
}

#[derive(Serialize, Clone)]
pub struct Setting {
    pub name: String,
    pub value: String,
}

#[derive(Serialize, Clone)]
pub enum Http3Frame {
    Data {
        frame_type: Http3FrameTypeName,

        raw: Option<String>,
    },

    Headers {
        frame_type: Http3FrameTypeName,
        headers: Vec<HttpHeader>,
    },

    CancelPush {
        frame_type: Http3FrameTypeName,
        push_id: String,
    },

    Settings {
        frame_type: Http3FrameTypeName,
        settings: Vec<Setting>,
    },

    PushPromise {
        frame_type: Http3FrameTypeName,
        push_id: String,
        headers: Vec<HttpHeader>,
    },

    Goaway {
        frame_type: Http3FrameTypeName,
        stream_id: String,
    },

    MaxPushId {
        frame_type: Http3FrameTypeName,
        push_id: String,
    },

    DuplicatePush {
        frame_type: Http3FrameTypeName,
        push_id: String,
    },

    Reserved {
        frame_type: Http3FrameTypeName,
    },

    Unknown {
        frame_type: Http3FrameTypeName,
    },
}

impl Http3Frame {
    pub fn data(raw: Option<String>) -> Self {
        Http3Frame::Data {
            frame_type: Http3FrameTypeName::Data,
            raw,
        }
    }

    pub fn headers(headers: Vec<HttpHeader>) -> Self {
        Http3Frame::Headers {
            frame_type: Http3FrameTypeName::Headers,
            headers,
        }
    }

    pub fn cancel_push(push_id: String) -> Self {
        Http3Frame::CancelPush {
            frame_type: Http3FrameTypeName::CancelPush,
            push_id,
        }
    }

    pub fn settings(settings: Vec<Setting>) -> Self {
        Http3Frame::Settings {
            frame_type: Http3FrameTypeName::Settings,
            settings,
        }
    }

    pub fn push_promise(push_id: String, headers: Vec<HttpHeader>) -> Self {
        Http3Frame::PushPromise {
            frame_type: Http3FrameTypeName::PushPromise,
            push_id,
            headers,
        }
    }

    pub fn goaway(stream_id: String) -> Self {
        Http3Frame::Goaway {
            frame_type: Http3FrameTypeName::Goaway,
            stream_id,
        }
    }

    pub fn max_push_id(push_id: String) -> Self {
        Http3Frame::MaxPushId {
            frame_type: Http3FrameTypeName::MaxPushId,
            push_id,
        }
    }

    pub fn duplicate_push(push_id: String) -> Self {
        Http3Frame::DuplicatePush {
            frame_type: Http3FrameTypeName::DuplicatePush,
            push_id,
        }
    }

    pub fn reserved() -> Self {
        Http3Frame::Reserved {
            frame_type: Http3FrameTypeName::Reserved,
        }
    }

    pub fn unknown() -> Self {
        Http3Frame::Unknown {
            frame_type: Http3FrameTypeName::Unknown,
        }
    }
}

#[derive(Serialize, Clone)]
#[serde(rename_all = "snake_case")]
pub enum QpackInstructionTypeName {
    SetDynamicTableCapacityInstruction,
    InsertWithNameReferenceInstruction,
    InsertWithoutNameReferenceInstruction,
    DuplicateInstruction,
    HeaderAcknowledgementInstruction,
    StreamCancellationInstruction,
    InsertCountIncrementInstruction,
}

#[derive(Serialize, Clone)]
#[serde(rename_all = "snake_case")]
pub enum QpackTableType {
    Static,
    Dynamic,
}

#[derive(Serialize, Clone)]
pub enum QPackInstruction {
    SetDynamicTableCapacityInstruction {
        instruction_type: QpackInstructionTypeName,

        capacity: u64,
    },

    InsertWithNameReferenceInstruction {
        instruction_type: QpackInstructionTypeName,

        table_type: QpackTableType,

        name_index: u64,

        huffman_encoded_value: bool,
        value_length: u64,
        value: String,
    },

    InsertWithoutNameReferenceInstruction {
        instruction_type: QpackInstructionTypeName,

        huffman_encoded_name: bool,
        name_length: u64,
        name: String,

        huffman_encoded_value: bool,
        value_length: u64,
        value: String,
    },

    DuplicateInstruction {
        instruction_type: QpackInstructionTypeName,

        index: u64,
    },

    HeaderAcknowledgementInstruction {
        instruction_type: QpackInstructionTypeName,

        stream_id: String,
    },

    StreamCancellationInstruction {
        instruction_type: QpackInstructionTypeName,

        stream_id: String,
    },

    InsertCountIncrementInstruction {
        instruction_type: QpackInstructionTypeName,

        increment: u64,
    },
}

#[derive(Serialize, Clone)]
#[serde(rename_all = "snake_case")]
pub enum QpackHeaderBlockRepresentationTypeName {
    IndexedHeaderField,
    LiteralHeaderFieldWithName,
    LiteralHeaderFieldWithoutName,
}

#[derive(Serialize, Clone)]
pub enum QpackHeaderBlockRepresentation {
    IndexedHeaderField {
        header_field_type: QpackHeaderBlockRepresentationTypeName,

        table_type: QpackTableType,
        index: u64,

        is_post_base: Option<bool>,
    },

    LiteralHeaderFieldWithName {
        header_field_type: QpackHeaderBlockRepresentationTypeName,

        preserve_literal: bool,
        table_type: QpackTableType,
        name_index: u64,

        huffman_encoded_value: bool,
        value_length: u64,
        value: String,

        is_post_base: Option<bool>,
    },

    LiteralHeaderFieldWithoutName {
        header_field_type: QpackHeaderBlockRepresentationTypeName,

        preserve_literal: bool,
        table_type: QpackTableType,
        name_index: u64,

        huffman_encoded_name: bool,
        name_length: u64,
        name: String,

        huffman_encoded_value: bool,
        value_length: u64,
        value: String,

        is_post_base: Option<bool>,
    },
}

pub struct HexSlice<'a>(&'a [u8]);

impl<'a> HexSlice<'a> {
    pub fn new<T>(data: &'a T) -> HexSlice<'a>
    where
        T: ?Sized + AsRef<[u8]> + 'a,
    {
        HexSlice(data.as_ref())
    }

    pub fn maybe_string<T>(data: Option<&'a T>) -> Option<String>
    where
        T: ?Sized + AsRef<[u8]> + 'a,
    {
        match data {
            Some(d) => Some(format!("{}", HexSlice::new(d))),

            None => None,
        }
    }
}

impl<'a> std::fmt::Display for HexSlice<'a> {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        for byte in self.0 {
            write!(f, "{:02x}", byte)?;
        }
        Ok(())
    }
}

#[doc(hidden)]
pub mod testing {
    use super::*;

    pub fn make_pkt_hdr() -> PacketHeader {
        let scid = [0x7e, 0x37, 0xe4, 0xdc, 0xc6, 0x68, 0x2d, 0xa8];
        let dcid = [0x36, 0xce, 0x10, 0x4e, 0xee, 0x50, 0x10, 0x1c];

        PacketHeader::new(
            0,
            Some(1251),
            Some(1224),
            Some(0xff00_0018),
            Some(&scid),
            Some(&dcid),
        )
    }

    pub fn make_trace() -> Trace {
        Trace::new(
            VantagePoint {
                name: None,
                ty: VantagePointType::Server,
                flow: None,
            },
            Some("Quiche qlog trace".to_string()),
            Some("Quiche qlog trace description".to_string()),
            Some(Configuration {
                time_offset: Some("0".to_string()),
                time_units: Some(TimeUnits::Ms),
                original_uris: None,
            }),
            None,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use testing::*;

    #[test]
    fn packet_header() {
        let pkt_hdr = make_pkt_hdr();

        let log_string = r#"{
  "packet_number": "0",
  "packet_size": 1251,
  "payload_length": 1224,
  "version": "ff000018",
  "scil": "8",
  "dcil": "8",
  "scid": "7e37e4dcc6682da8",
  "dcid": "36ce104eee50101c"
}"#;

        assert_eq!(serde_json::to_string_pretty(&pkt_hdr).unwrap(), log_string);
    }

    #[test]
    fn packet_sent_event_no_frames() {
        let log_string = r#"{
  "packet_type": "initial",
  "header": {
    "packet_number": "0",
    "packet_size": 1251,
    "payload_length": 1224,
    "version": "ff00001b",
    "scil": "8",
    "dcil": "8",
    "scid": "7e37e4dcc6682da8",
    "dcid": "36ce104eee50101c"
  }
}"#;

        let scid = [0x7e, 0x37, 0xe4, 0xdc, 0xc6, 0x68, 0x2d, 0xa8];
        let dcid = [0x36, 0xce, 0x10, 0x4e, 0xee, 0x50, 0x10, 0x1c];
        let pkt_hdr = PacketHeader::new(
            0,
            Some(1251),
            Some(1224),
            Some(0xff00001b),
            Some(&scid),
            Some(&dcid),
        );

        let pkt_sent_evt = EventData::PacketSent {
            raw_encrypted: None,
            raw_decrypted: None,
            packet_type: PacketType::Initial,
            header: pkt_hdr.clone(),
            frames: None,
            is_coalesced: None,
        };

        assert_eq!(
            serde_json::to_string_pretty(&pkt_sent_evt).unwrap(),
            log_string
        );
    }

    #[test]
    fn packet_sent_event_some_frames() {
        let log_string = r#"{
  "packet_type": "initial",
  "header": {
    "packet_number": "0",
    "packet_size": 1251,
    "payload_length": 1224,
    "version": "ff000018",
    "scil": "8",
    "dcil": "8",
    "scid": "7e37e4dcc6682da8",
    "dcid": "36ce104eee50101c"
  },
  "frames": [
    {
      "frame_type": "padding"
    },
    {
      "frame_type": "ping"
    },
    {
      "frame_type": "stream",
      "stream_id": "0",
      "offset": "0",
      "length": "100",
      "fin": true
    }
  ]
}"#;

        let pkt_hdr = make_pkt_hdr();

        let mut frames = Vec::new();
        frames.push(QuicFrame::padding());

        frames.push(QuicFrame::ping());

        frames.push(QuicFrame::stream(
            "0".to_string(),
            "0".to_string(),
            "100".to_string(),
            true,
            None,
        ));

        let pkt_sent_evt = EventData::PacketSent {
            raw_encrypted: None,
            raw_decrypted: None,
            packet_type: PacketType::Initial,
            header: pkt_hdr.clone(),
            frames: Some(frames),
            is_coalesced: None,
        };

        assert_eq!(
            serde_json::to_string_pretty(&pkt_sent_evt).unwrap(),
            log_string
        );
    }

    #[test]
    fn trace_no_events() {
        let log_string = r#"{
  "vantage_point": {
    "type": "server"
  },
  "title": "Quiche qlog trace",
  "description": "Quiche qlog trace description",
  "configuration": {
    "time_units": "ms",
    "time_offset": "0"
  },
  "event_fields": [
    "relative_time",
    "category",
    "event",
    "data"
  ],
  "events": []
}"#;

        let trace = make_trace();

        assert_eq!(serde_json::to_string_pretty(&trace).unwrap(), log_string);
    }

    #[test]
    fn trace_single_transport_event() {
        let log_string = r#"{
  "vantage_point": {
    "type": "server"
  },
  "title": "Quiche qlog trace",
  "description": "Quiche qlog trace description",
  "configuration": {
    "time_units": "ms",
    "time_offset": "0"
  },
  "event_fields": [
    "relative_time",
    "category",
    "event",
    "data"
  ],
  "events": [
    [
      "0",
      "transport",
      "packet_sent",
      {
        "packet_type": "initial",
        "header": {
          "packet_number": "0",
          "packet_size": 1251,
          "payload_length": 1224,
          "version": "ff000018",
          "scil": "8",
          "dcil": "8",
          "scid": "7e37e4dcc6682da8",
          "dcid": "36ce104eee50101c"
        },
        "frames": [
          {
            "frame_type": "stream",
            "stream_id": "0",
            "offset": "0",
            "length": "100",
            "fin": true
          }
        ]
      }
    ]
  ]
}"#;

        let mut trace = make_trace();

        let pkt_hdr = make_pkt_hdr();

        let frames = vec![QuicFrame::stream(
            "0".to_string(),
            "0".to_string(),
            "100".to_string(),
            true,
            None,
        )];
        let event = event::Event::packet_sent_min(
            PacketType::Initial,
            pkt_hdr,
            Some(frames),
        );

        trace.push_event(std::time::Duration::new(0, 0), event);

        assert_eq!(serde_json::to_string_pretty(&trace).unwrap(), log_string);
    }

    #[test]
    fn test_event_validity() {
        // Test a single event in each category

        let ev = event::Event::server_listening_min(443, 443);
        assert!(ev.is_valid());

        let ev = event::Event::transport_parameters_set_min();
        assert!(ev.is_valid());

        let ev = event::Event::recovery_parameters_set_min();
        assert!(ev.is_valid());

        let ev = event::Event::h3_parameters_set_min();
        assert!(ev.is_valid());

        let ev = event::Event::qpack_state_updated_min();
        assert!(ev.is_valid());

        let ev = event::Event {
            category: EventCategory::Error,
            ty: EventType::GenericEventType(GenericEventType::ConnectionError),
            data: EventData::ConnectionError {
                code: None,
                description: None,
            },
        };

        assert!(ev.is_valid());
    }

    #[test]
    fn bogus_event_validity() {
        // Test a single event in each category

        let mut ev = event::Event::server_listening_min(443, 443);
        ev.category = EventCategory::Simulation;
        assert!(!ev.is_valid());

        let mut ev = event::Event::transport_parameters_set_min();
        ev.category = EventCategory::Simulation;
        assert!(!ev.is_valid());

        let mut ev = event::Event::recovery_parameters_set_min();
        ev.category = EventCategory::Simulation;
        assert!(!ev.is_valid());

        let mut ev = event::Event::h3_parameters_set_min();
        ev.category = EventCategory::Simulation;
        assert!(!ev.is_valid());

        let mut ev = event::Event::qpack_state_updated_min();
        ev.category = EventCategory::Simulation;
        assert!(!ev.is_valid());

        let ev = event::Event {
            category: EventCategory::Error,
            ty: EventType::GenericEventType(GenericEventType::ConnectionError),
            data: EventData::FramesProcessed { frames: Vec::new() },
        };

        assert!(!ev.is_valid());
    }

    #[test]
    fn serialization_states() {
        let v: Vec<u8> = Vec::new();
        let buff = std::io::Cursor::new(v);
        let writer = Box::new(buff);

        let mut trace = make_trace();
        let pkt_hdr = make_pkt_hdr();

        let frame1 = QuicFrame::stream(
            "40".to_string(),
            "40".to_string(),
            "400".to_string(),
            true,
            None,
        );

        let event1 = event::Event::packet_sent_min(
            PacketType::Handshake,
            pkt_hdr.clone(),
            Some(vec![frame1]),
        );

        trace.push_event(std::time::Duration::new(0, 0), event1);

        let frame2 = QuicFrame::stream(
            "0".to_string(),
            "0".to_string(),
            "100".to_string(),
            true,
            None,
        );

        let frame3 = QuicFrame::stream(
            "0".to_string(),
            "0".to_string(),
            "100".to_string(),
            true,
            None,
        );

        let event2 = event::Event::packet_sent_min(
            PacketType::Initial,
            pkt_hdr.clone(),
            Some(Vec::new()),
        );

        let event3 = event::Event::packet_sent(
            PacketType::Initial,
            pkt_hdr,
            Some(Vec::new()),
            None,
            Some("encrypted_foo".to_string()),
            Some("decrypted_foo".to_string()),
        );

        let mut s = QlogStreamer::new(
            "version".to_string(),
            Some("title".to_string()),
            Some("description".to_string()),
            None,
            std::time::Instant::now(),
            trace,
            writer,
        );

        // Before the log is started all other operations should fail.
        assert!(match s.add_event(event2.clone()) {
            Err(Error::InvalidState) => true,
            _ => false,
        });
        assert!(match s.add_frame(frame2.clone(), false) {
            Err(Error::InvalidState) => true,
            _ => false,
        });
        assert!(match s.finish_frames() {
            Err(Error::InvalidState) => true,
            _ => false,
        });
        assert!(match s.finish_log() {
            Err(Error::InvalidState) => true,
            _ => false,
        });

        // Once a log is started, can't write frames before an event.
        assert!(match s.start_log() {
            Ok(()) => true,
            _ => false,
        });
        assert!(match s.add_frame(frame2.clone(), true) {
            Err(Error::InvalidState) => true,
            _ => false,
        });
        assert!(match s.finish_frames() {
            Err(Error::InvalidState) => true,
            _ => false,
        });

        // Some events hold frames; can't write any more events until frame
        // writing is concluded.
        assert!(match s.add_event(event2.clone()) {
            Ok(true) => true,
            _ => false,
        });
        assert!(match s.add_event(event2.clone()) {
            Err(Error::InvalidState) => true,
            _ => false,
        });

        // While writing frames, can't write events.
        assert!(match s.add_frame(frame2.clone(), false) {
            Ok(()) => true,
            _ => false,
        });

        assert!(match s.add_event(event2.clone()) {
            Err(Error::InvalidState) => true,
            _ => false,
        });
        assert!(match s.finish_frames() {
            Ok(()) => true,
            _ => false,
        });

        // Adding an event that includes both frames and raw data should
        // be allowed.
        assert!(match s.add_event(event3.clone()) {
            Ok(true) => true,
            _ => false,
        });
        assert!(match s.add_frame(frame3.clone(), false) {
            Ok(()) => true,
            _ => false,
        });
        assert!(match s.finish_frames() {
            Ok(()) => true,
            _ => false,
        });

        assert!(match s.finish_log() {
            Ok(()) => true,
            _ => false,
        });

        let r = s.writer();
        let w: &Box<std::io::Cursor<Vec<u8>>> = unsafe { std::mem::transmute(r) };

        let log_string = r#"{"qlog_version":"version","title":"title","description":"description","traces":[{"vantage_point":{"type":"server"},"title":"Quiche qlog trace","description":"Quiche qlog trace description","configuration":{"time_units":"ms","time_offset":"0"},"event_fields":["relative_time","category","event","data"],"events":[["0","transport","packet_sent",{"packet_type":"handshake","header":{"packet_number":"0","packet_size":1251,"payload_length":1224,"version":"ff000018","scil":"8","dcil":"8","scid":"7e37e4dcc6682da8","dcid":"36ce104eee50101c"},"frames":[{"frame_type":"stream","stream_id":"40","offset":"40","length":"400","fin":true}]}],["0","transport","packet_sent",{"packet_type":"initial","header":{"packet_number":"0","packet_size":1251,"payload_length":1224,"version":"ff000018","scil":"8","dcil":"8","scid":"7e37e4dcc6682da8","dcid":"36ce104eee50101c"},"frames":[{"frame_type":"stream","stream_id":"0","offset":"0","length":"100","fin":true}]}],["0","transport","packet_sent",{"packet_type":"initial","header":{"packet_number":"0","packet_size":1251,"payload_length":1224,"version":"ff000018","scil":"8","dcil":"8","scid":"7e37e4dcc6682da8","dcid":"36ce104eee50101c"},"raw_encrypted":"encrypted_foo","raw_decrypted":"decrypted_foo","frames":[{"frame_type":"stream","stream_id":"0","offset":"0","length":"100","fin":true}]}]]}]}"#;

        let written_string = std::str::from_utf8(w.as_ref().get_ref()).unwrap();

        assert_eq!(log_string, written_string);
    }
}

pub mod event;
