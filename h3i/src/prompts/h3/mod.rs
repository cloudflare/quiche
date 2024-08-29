// Copyright (C) 2024, Cloudflare, Inc.
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

//! A collection of interactive CLI prompts for HTTP/3 based on [inquire].

use inquire::error::CustomUserError;
use inquire::error::InquireResult;
use inquire::validator::ErrorMessage;
use inquire::validator::Validation;
use inquire::InquireError;
use inquire::Select;
use inquire::Text;
use qlog::events::quic::ErrorSpace;
use quiche::ConnectionError;

use crate::actions::h3::Action;
use crate::config::Config;
use crate::prompts::h3;
use crate::prompts::h3::headers::prompt_push_promise;
use crate::StreamIdAllocator;

use std::cell::RefCell;

use quiche;

use self::stream::prompt_fin_stream;
use self::wait::prompt_wait;

/// An error indicating that the provided buffer is not big enough.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    InternalError,
    BufferTooShort,
}

impl std::convert::From<octets::BufferTooShortError> for Error {
    fn from(_err: octets::BufferTooShortError) -> Self {
        Error::BufferTooShort
    }
}

/// A specialized [`Result`] type for prompt operations.
///
/// [`Result`]: https://doc.rust-lang.org/std/result/enum.Result.html
pub type Result<T> = std::result::Result<T, Error>;

/// A specialized [`Result`] type for internal prompt suggestion.
///
/// [`Result`]: https://doc.rust-lang.org/std/result/enum.Result.html
type SuggestionResult<T> = std::result::Result<T, CustomUserError>;

/// A tuple of stream ID and quiche HTTP/3 frame.
pub type PromptedFrame = (u64, quiche::h3::frame::Frame);

thread_local! {static CONNECTION_IDLE_TIMEOUT: RefCell<u64> = const { RefCell::new(0) }}

// TODO(erittenhouse): exploring generating prompts at compile-time
const HEADERS: &str = "headers";
const HEADERS_NO_PSEUDO: &str = "headers_no_pseudo";
const DATA: &str = "data";
const SETTINGS: &str = "settings";
const PUSH_PROMISE: &str = "push_promise";
const CANCEL_PUSH: &str = "cancel_push";
const GOAWAY: &str = "goaway";
const MAX_PUSH_ID: &str = "max_push_id";
const PRIORITY_UPDATE: &str = "priority_update";
const GREASE: &str = "grease";
const EXTENSION: &str = "extension_frame";
const OPEN_UNI_STREAM: &str = "open_uni_stream";
const RESET_STREAM: &str = "reset_stream";
const STOP_SENDING: &str = "stop_sending";
const CONNECTION_CLOSE: &str = "connection_close";
const STREAM_BYTES: &str = "stream_bytes";

const COMMIT: &str = "commit";
const FLUSH_PACKETS: &str = "flush_packets";
const WAIT: &str = "wait";
const QUIT: &str = "quit";

const YES: &str = "Yes";
const NO: &str = "No";

const ESC_TO_RET: &str = "ESC to return to actions";
const STREAM_ID_PROMPT: &str = "stream ID:";
const EMPTY_PICKS: &str = "empty picks next available ID";
const AUTO_PICK: &str = "autopick StreamID";
const PUSH_ID_PROMPT: &str = "push ID:";

enum PromptOutcome {
    Action(Action),
    Repeat,
    Commit,
    Clear,
}

/// The main prompter interface and state management.
pub struct Prompter {
    host_port: String,
    bidi_sid_alloc: StreamIdAllocator,
    uni_sid_alloc: StreamIdAllocator,
}

impl Prompter {
    /// Construct a prompter with the provided `config`.
    pub fn with_config(config: &Config) -> Self {
        CONNECTION_IDLE_TIMEOUT.with(|v| *v.borrow_mut() = config.idle_timeout);

        Self {
            host_port: config.host_port.clone(),
            bidi_sid_alloc: StreamIdAllocator { id: 0 },
            uni_sid_alloc: StreamIdAllocator { id: 2 },
        }
    }

    fn handle_action(&mut self, action: &str) -> PromptOutcome {
        let res = match action {
            HEADERS | HEADERS_NO_PSEUDO => {
                let raw = action == HEADERS_NO_PSEUDO;
                headers::prompt_headers(
                    &mut self.bidi_sid_alloc,
                    &self.host_port,
                    raw,
                )
            },

            DATA => prompt_data(),
            SETTINGS => settings::prompt_settings(),
            OPEN_UNI_STREAM =>
                stream::prompt_open_uni_stream(&mut self.uni_sid_alloc),
            RESET_STREAM => stream::prompt_reset_stream(),
            STOP_SENDING => stream::prompt_stop_sending(),
            GREASE => prompt_grease(),
            EXTENSION => prompt_extension(),
            GOAWAY => prompt_goaway(),
            MAX_PUSH_ID => prompt_max_push_id(),
            CANCEL_PUSH => prompt_cancel_push(),
            PUSH_PROMISE => prompt_push_promise(),
            PRIORITY_UPDATE => priority::prompt_priority(),
            CONNECTION_CLOSE => prompt_connection_close(),
            STREAM_BYTES => prompt_stream_bytes(),
            FLUSH_PACKETS => return PromptOutcome::Action(Action::FlushPackets),
            COMMIT => return PromptOutcome::Commit,
            WAIT => prompt_wait(),
            QUIT => return PromptOutcome::Clear,

            _ => {
                println!("error: unknown action {}", action);
                return PromptOutcome::Repeat;
            },
        };

        match res {
            Ok(action) => PromptOutcome::Action(action),
            Err(e) =>
                if handle_action_loop_error(e) {
                    PromptOutcome::Commit
                } else {
                    PromptOutcome::Repeat
                },
        }
    }

    /// Start the prompt loop.
    ///
    /// This continues to prompt for actions until a terminal choice is
    /// made.
    ///
    /// Returns an ordered list of [Action]s, which may be empty.
    pub fn prompt(&mut self) -> Vec<Action> {
        let mut actions = vec![];

        loop {
            println!();

            let action = match prompt_action() {
                Ok(v) => v,
                Err(inquire::InquireError::OperationCanceled) |
                Err(inquire::InquireError::OperationInterrupted) =>
                    return actions,
                Err(e) => {
                    println!("Unexpected error while determining action: {}", e);
                    return actions;
                },
            };

            match self.handle_action(&action) {
                PromptOutcome::Action(action) => actions.push(action),
                PromptOutcome::Repeat => continue,
                PromptOutcome::Commit => return actions,
                PromptOutcome::Clear => return vec![],
            }
        }
    }
}

fn handle_action_loop_error(err: InquireError) -> bool {
    match err {
        inquire::InquireError::OperationCanceled |
        inquire::InquireError::OperationInterrupted => false,

        _ => {
            println!("Unexpected error: {}", err);
            true
        },
    }
}

fn prompt_action() -> InquireResult<String> {
    let name = Text::new(
        "Select an action to queue. `Commit` ends selection and flushes queue.",
    )
    .with_autocomplete(&action_suggester)
    .with_page_size(18)
    .prompt();

    name
}

fn action_suggester(val: &str) -> SuggestionResult<Vec<String>> {
    // TODO: make this an enum to automatically pick up new actions
    let suggestions = [
        HEADERS,
        HEADERS_NO_PSEUDO,
        DATA,
        SETTINGS,
        GOAWAY,
        PRIORITY_UPDATE,
        PUSH_PROMISE,
        CANCEL_PUSH,
        MAX_PUSH_ID,
        GREASE,
        EXTENSION,
        OPEN_UNI_STREAM,
        RESET_STREAM,
        STOP_SENDING,
        CONNECTION_CLOSE,
        STREAM_BYTES,
        FLUSH_PACKETS,
        COMMIT,
        WAIT,
        QUIT,
    ];

    squish_suggester(&suggestions, val)
}

fn squish_suggester(
    suggestions: &[&str], val: &str,
) -> SuggestionResult<Vec<String>> {
    let val_lower = val.to_lowercase();

    Ok(suggestions
        .iter()
        .filter(|s| s.to_lowercase().contains(&val_lower))
        .map(|s| String::from(*s))
        .collect())
}

fn validate_varint(id: &str) -> SuggestionResult<Validation> {
    let x = id.parse::<u64>();

    match x {
        Ok(v) =>
            if v >= u64::pow(2, 62) {
                return Ok(Validation::Invalid(ErrorMessage::Default));
            },

        Err(_) => {
            return Ok(Validation::Invalid(ErrorMessage::Default));
        },
    }

    Ok(Validation::Valid)
}

fn prompt_stream_id() -> InquireResult<u64> {
    prompt_varint(STREAM_ID_PROMPT)
}

fn prompt_control_stream_id() -> InquireResult<u64> {
    let id = Text::new(STREAM_ID_PROMPT)
        .with_validator(h3::validate_varint)
        .with_autocomplete(&control_stream_suggestor)
        .with_help_message(ESC_TO_RET)
        .prompt()?;

    // id is already validated so unwrap always succeeds
    Ok(id.parse::<u64>().unwrap())
}

fn prompt_varint(str: &str) -> InquireResult<u64> {
    let id = Text::new(str)
        .with_validator(h3::validate_varint)
        .with_placeholder("Integer <= 2^62 -1")
        .with_help_message(ESC_TO_RET)
        .prompt()?;

    // id is already validated so unwrap always succeeds
    Ok(id.parse::<u64>().unwrap())
}

fn control_stream_suggestor(val: &str) -> SuggestionResult<Vec<String>> {
    let suggestions = ["2"];

    squish_suggester(&suggestions, val)
}

fn prompt_data() -> InquireResult<Action> {
    let stream_id = h3::prompt_stream_id()?;

    let payload = Text::new("payload:").prompt()?;

    let fin_stream = prompt_fin_stream()?;

    let action = Action::SendFrame {
        stream_id,
        fin_stream,
        frame: quiche::h3::frame::Frame::Data {
            payload: payload.into(),
        },
    };

    Ok(action)
}

fn prompt_max_push_id() -> InquireResult<Action> {
    let stream_id = h3::prompt_stream_id()?;
    let push_id = h3::prompt_varint(PUSH_ID_PROMPT)?;

    let fin_stream = prompt_fin_stream()?;

    let action = Action::SendFrame {
        stream_id,
        fin_stream,
        frame: quiche::h3::frame::Frame::MaxPushId { push_id },
    };

    Ok(action)
}

fn prompt_cancel_push() -> InquireResult<Action> {
    let stream_id = h3::prompt_stream_id()?;
    let push_id = h3::prompt_varint(PUSH_ID_PROMPT)?;

    let fin_stream = prompt_fin_stream()?;

    let action = Action::SendFrame {
        stream_id,
        fin_stream,
        frame: quiche::h3::frame::Frame::CancelPush { push_id },
    };

    Ok(action)
}

fn prompt_goaway() -> InquireResult<Action> {
    let stream_id = h3::prompt_stream_id()?;
    let id = h3::prompt_varint("ID:")?;

    let fin_stream = prompt_fin_stream()?;

    let action = Action::SendFrame {
        stream_id,
        fin_stream,
        frame: quiche::h3::frame::Frame::GoAway { id },
    };

    Ok(action)
}

fn prompt_grease() -> InquireResult<Action> {
    let stream_id = h3::prompt_control_stream_id()?;
    let raw_type = quiche::h3::grease_value();
    let payload = Text::new("payload:")
        .prompt()
        .expect("An error happened when asking for payload, try again later.");

    let fin_stream = prompt_fin_stream()?;

    let action = Action::SendFrame {
        stream_id,
        fin_stream,
        frame: quiche::h3::frame::Frame::Unknown {
            raw_type,
            payload: payload.into(),
        },
    };

    Ok(action)
}

fn prompt_extension() -> InquireResult<Action> {
    let stream_id = h3::prompt_control_stream_id()?;
    let raw_type = h3::prompt_varint("frame type:")?;
    let payload = Text::new("payload:")
        .with_help_message(ESC_TO_RET)
        .prompt()
        .expect("An error happened when asking for payload, try again later.");

    let fin_stream = prompt_fin_stream()?;

    let action = Action::SendFrame {
        stream_id,
        fin_stream,
        frame: quiche::h3::frame::Frame::Unknown {
            raw_type,
            payload: payload.into(),
        },
    };

    Ok(action)
}

pub fn prompt_connection_close() -> InquireResult<Action> {
    let (error_space, error_code) = errors::prompt_transport_or_app_error()?;
    let reason = Text::new("reason phrase:")
        .with_placeholder("optional reason phrase")
        .prompt()
        .unwrap_or_default();

    Ok(Action::ConnectionClose {
        error: ConnectionError {
            is_app: matches!(error_space, ErrorSpace::ApplicationError),
            error_code,
            reason: reason.as_bytes().to_vec(),
        },
    })
}

pub fn prompt_stream_bytes() -> InquireResult<Action> {
    let stream_id = h3::prompt_stream_id()?;
    let bytes = Text::new("bytes:").prompt()?;
    let fin_stream = prompt_fin_stream()?;

    Ok(Action::StreamBytes {
        stream_id,
        fin_stream,
        bytes: bytes.as_bytes().to_vec(),
    })
}

fn validate_wait_period(period: &str) -> SuggestionResult<Validation> {
    let x = period.parse::<u64>();

    match x {
        Ok(v) => {
            let local_conn_timeout =
                CONNECTION_IDLE_TIMEOUT.with(|v| *v.borrow());
            if v >= local_conn_timeout {
                return Ok(Validation::Invalid(ErrorMessage::Custom(format!(
                    "wait time >= local connection idle timeout {}",
                    local_conn_timeout
                ))));
            }
        },

        Err(_) => return Ok(Validation::Invalid(ErrorMessage::Default)),
    }

    Ok(Validation::Valid)
}

fn prompt_yes_no(msg: &str) -> InquireResult<bool> {
    let res = Select::new(msg, vec![NO, YES]).prompt()?;

    Ok(res == YES)
}

mod errors;
mod headers;
mod priority;
mod settings;
mod stream;
mod wait;
