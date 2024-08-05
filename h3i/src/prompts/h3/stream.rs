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

use inquire::error::InquireResult;
use inquire::validator::Validation;
use inquire::CustomUserError;
use inquire::Select;
use inquire::Text;

use crate::actions::h3::Action;
use crate::prompts::h3;
use crate::prompts::h3::prompt_yes_no;
use crate::StreamIdAllocator;

use super::squish_suggester;
use super::SuggestionResult;
use super::AUTO_PICK;
use super::EMPTY_PICKS;
use super::ESC_TO_RET;
use super::STREAM_ID_PROMPT;

const CONTROL_STREAM: &str = "Control Stream";
const PUSH_STREAM: &str = "Push Stream";
const QPACK_ENCODER: &str = "QPACK Encoder Stream";
const QPACK_DECODER: &str = "QPACK Decoder Stream";

const TRANSPORT: &str = "transport";
const APPLICATION: &str = "application";

const NO_ERROR: &str = "NO_ERROR";
const INTERNAL_ERROR: &str = "INTERNAL_ERROR";
const CONNECTION_REFUSED: &str = "CONNECTION_REFUSED";
const FLOW_CONTROL_ERROR: &str = "FLOW_CONTROL_ERROR";
const STREAM_LIMIT_ERROR: &str = "STREAM_LIMIT_ERROR";
const STREAM_STATE_ERROR: &str = "STREAM_STATE_ERROR";
const FINAL_SIZE_ERROR: &str = "FINAL_SIZE_ERROR";
const FRAME_ENCODING_ERROR: &str = "FRAME_ENCODING_ERROR";
const TRANSPORT_PARAMETER_ERROR: &str = "TRANSPORT_PARAMETER_ERROR";
const CONNECTION_ID_LIMIT_ERROR: &str = "CONNECTION_ID_LIMIT_ERROR";
const PROTOCOL_VIOLATION: &str = "PROTOCOL_VIOLATION";
const INVALID_TOKEN: &str = "INVALID_TOKEN";
const APPLICATION_ERROR: &str = "APPLICATION_ERROR";
const CRYPTO_BUFFER_EXCEEDED: &str = "CRYPTO_BUFFER_EXCEEDED";
const KEY_UPDATE_ERROR: &str = "KEY_UPDATE_ERROR";
const AEAD_LIMIT_REACHED: &str = "AEAD_LIMIT_REACHED";
const NO_VIABLE_PATH: &str = "NO_VIABLE_PATH";
const VERSION_NEGOTIATION_ERROR: &str = "VERSION_NEGOTIATION_ERROR";

const H3_DATAGRAM_ERROR: &str = "H3_DATAGRAM_ERROR";
const H3_NO_ERROR: &str = "H3_NO_ERROR";
const H3_GENERAL_PROTOCOL_ERROR: &str = "H3_GENERAL_PROTOCOL_ERROR";
const H3_INTERNAL_ERROR: &str = "H3_INTERNAL_ERROR";
const H3_STREAM_CREATION_ERROR: &str = "H3_STREAM_CREATION_ERROR";
const H3_CLOSED_CRITICAL_STREAM: &str = "H3_CLOSED_CRITICAL_STREAM";
const H3_FRAME_UNEXPECTED: &str = "H3_FRAME_UNEXPECTED";
const H3_FRAME_ERROR: &str = "H3_FRAME_ERROR";
const H3_EXCESSIVE_LOAD: &str = "H3_EXCESSIVE_LOAD";
const H3_ID_ERROR: &str = "H3_ID_ERROR";
const H3_SETTINGS_ERROR: &str = "H3_SETTINGS_ERROR";
const H3_MISSING_SETTINGS: &str = "H3_MISSING_SETTINGS";
const H3_REQUEST_REJECTED: &str = "H3_REQUEST_REJECTED";
const H3_REQUEST_CANCELLED: &str = "H3_REQUEST_CANCELLED";
const H3_REQUEST_INCOMPLETE: &str = "H3_REQUEST_INCOMPLETE";
const H3_MESSAGE_ERROR: &str = "H3_MESSAGE_ERROR";
const H3_CONNECT_ERROR: &str = "H3_CONNECT_ERROR";
const H3_VERSION_FALLBACK: &str = "H3_VERSION_FALLBACK";
const QPACK_DECOMPRESSION_FAILED: &str = "QPACK_DECOMPRESSION_FAILED";
const QPACK_ENCODER_STREAM_ERROR: &str = "QPACK_ENCODER_STREAM_ERROR";
const QPACK_DECODER_STREAM_ERROR: &str = "QPACK_DECODER_STREAM_ERROR";

fn validate_stream_id(id: &str) -> SuggestionResult<Validation> {
    if id.is_empty() {
        return Ok(Validation::Valid);
    }

    h3::validate_varint(id)
}

pub fn autopick_stream_id(
    sid_alloc: &mut StreamIdAllocator,
) -> InquireResult<u64> {
    let stream_id = Text::new(STREAM_ID_PROMPT)
        .with_placeholder(EMPTY_PICKS)
        .with_help_message(ESC_TO_RET)
        .with_validator(validate_stream_id)
        .prompt()?;

    Ok(match stream_id.as_str() {
        "" => {
            let id = sid_alloc.take_next_id();
            println!("{AUTO_PICK}={id}");
            id
        },

        _ => stream_id.parse::<u64>().unwrap(),
    })
}

pub fn prompt_open_uni_stream(
    sid_alloc: &mut StreamIdAllocator,
) -> InquireResult<Action> {
    let stream_id = autopick_stream_id(sid_alloc)?;
    let stream_type = Text::new("stream type:")
        .with_validator(validate_stream_type)
        .with_autocomplete(&stream_type_suggestor)
        .prompt()?;

    let ty = match stream_type.as_str() {
        CONTROL_STREAM => 0x0,
        PUSH_STREAM => 0x1,
        QPACK_ENCODER => 0x2,
        QPACK_DECODER => 0x3,
        _ => stream_type.parse::<u64>().unwrap(),
    };

    let fin_stream = prompt_fin_stream()?;

    Ok(Action::OpenUniStream {
        stream_id,
        fin_stream,
        stream_type: ty,
    })
}

fn validate_stream_type(id: &str) -> SuggestionResult<Validation> {
    if matches!(
        id,
        CONTROL_STREAM | PUSH_STREAM | QPACK_ENCODER | QPACK_DECODER
    ) {
        return Ok(Validation::Valid);
    }

    h3::validate_varint(id)
}

fn stream_type_suggestor(val: &str) -> SuggestionResult<Vec<String>> {
    let suggestions = [CONTROL_STREAM, PUSH_STREAM, QPACK_ENCODER, QPACK_DECODER];

    squish_suggester(&suggestions, val)
}

pub fn prompt_fin_stream() -> InquireResult<bool> {
    prompt_yes_no("fin stream:")
}

pub fn prompt_reset_stream() -> InquireResult<Action> {
    let (stream_id, error_code) = prompt_close_stream()?;

    Ok(Action::ResetStream {
        stream_id,
        error_code,
    })
}

pub fn prompt_stop_sending() -> InquireResult<Action> {
    let (stream_id, error_code) = prompt_close_stream()?;

    Ok(Action::StopSending {
        stream_id,
        error_code,
    })
}

fn prompt_close_stream() -> InquireResult<(u64, u64)> {
    let id = h3::prompt_stream_id()?;

    let trans_or_app = prompt_transport_or_app()?;
    let transport = trans_or_app == TRANSPORT;

    let error_code = if transport {
        let error_code = Text::new("error code:")
            .with_validator(validate_transport_error_code)
            .with_autocomplete(&transport_error_code_suggestor)
            .with_page_size(18)
            .prompt()?;

        match error_code.as_str() {
            NO_ERROR => 0x0,
            INTERNAL_ERROR => 0x1,
            CONNECTION_REFUSED => 0x2,
            FLOW_CONTROL_ERROR => 0x3,
            STREAM_LIMIT_ERROR => 0x4,
            STREAM_STATE_ERROR => 0x5,
            FINAL_SIZE_ERROR => 0x6,
            FRAME_ENCODING_ERROR => 0x7,
            TRANSPORT_PARAMETER_ERROR => 0x8,
            CONNECTION_ID_LIMIT_ERROR => 0x9,
            PROTOCOL_VIOLATION => 0x0a,
            INVALID_TOKEN => 0x0b,
            APPLICATION_ERROR => 0x0c,
            CRYPTO_BUFFER_EXCEEDED => 0x0d,
            KEY_UPDATE_ERROR => 0x0e,
            AEAD_LIMIT_REACHED => 0x0f,
            NO_VIABLE_PATH => 0x10,
            VERSION_NEGOTIATION_ERROR => 0x11,

            v => v.parse::<u64>().unwrap(),
        }
    } else {
        let error_code = Text::new("error code:")
            .with_validator(validate_h3_error_code)
            .with_autocomplete(&h3_error_code_suggestor)
            .with_page_size(22)
            .prompt()?;

        match error_code.as_str() {
            H3_DATAGRAM_ERROR => 0x33,
            H3_NO_ERROR => 0x100,
            H3_GENERAL_PROTOCOL_ERROR => 0x101,
            H3_INTERNAL_ERROR => 0x102,
            H3_STREAM_CREATION_ERROR => 0x103,
            H3_CLOSED_CRITICAL_STREAM => 0x104,
            H3_FRAME_UNEXPECTED => 0x105,
            H3_FRAME_ERROR => 0x106,
            H3_EXCESSIVE_LOAD => 0x107,
            H3_ID_ERROR => 0x108,
            H3_SETTINGS_ERROR => 0x109,
            H3_MISSING_SETTINGS => 0x10a,
            H3_REQUEST_REJECTED => 0x10b,
            H3_REQUEST_CANCELLED => 0x10c,
            H3_REQUEST_INCOMPLETE => 0x10d,
            H3_MESSAGE_ERROR => 0x10e,
            H3_CONNECT_ERROR => 0x10f,
            H3_VERSION_FALLBACK => 0x110,
            QPACK_DECOMPRESSION_FAILED => 0x200,
            QPACK_ENCODER_STREAM_ERROR => 0x201,
            QPACK_DECODER_STREAM_ERROR => 0x202,

            v => v.parse::<u64>().unwrap(),
        }
    };

    Ok((id, error_code))
}

fn prompt_transport_or_app() -> InquireResult<String> {
    Ok(
        Select::new("transport or application:", vec![TRANSPORT, APPLICATION])
            .prompt()?
            .to_string(),
    )
}

fn validate_transport_error_code(
    id: &str,
) -> Result<Validation, CustomUserError> {
    if matches!(
        id,
        NO_ERROR |
            INTERNAL_ERROR |
            CONNECTION_REFUSED |
            FLOW_CONTROL_ERROR |
            STREAM_LIMIT_ERROR |
            STREAM_STATE_ERROR |
            FINAL_SIZE_ERROR |
            FRAME_ENCODING_ERROR |
            TRANSPORT_PARAMETER_ERROR |
            CONNECTION_ID_LIMIT_ERROR |
            PROTOCOL_VIOLATION |
            INVALID_TOKEN |
            APPLICATION_ERROR |
            CRYPTO_BUFFER_EXCEEDED |
            KEY_UPDATE_ERROR |
            AEAD_LIMIT_REACHED |
            NO_VIABLE_PATH |
            VERSION_NEGOTIATION_ERROR
    ) {
        return Ok(Validation::Valid);
    }

    h3::validate_varint(id)
}

fn transport_error_code_suggestor(
    val: &str,
) -> Result<Vec<String>, CustomUserError> {
    let suggestions = [
        NO_ERROR,
        INTERNAL_ERROR,
        CONNECTION_REFUSED,
        FLOW_CONTROL_ERROR,
        STREAM_LIMIT_ERROR,
        STREAM_STATE_ERROR,
        FINAL_SIZE_ERROR,
        FRAME_ENCODING_ERROR,
        TRANSPORT_PARAMETER_ERROR,
        CONNECTION_ID_LIMIT_ERROR,
        PROTOCOL_VIOLATION,
        INVALID_TOKEN,
        APPLICATION_ERROR,
        CRYPTO_BUFFER_EXCEEDED,
        KEY_UPDATE_ERROR,
        AEAD_LIMIT_REACHED,
        NO_VIABLE_PATH,
        VERSION_NEGOTIATION_ERROR,
    ];

    super::squish_suggester(&suggestions, val)
}

fn validate_h3_error_code(id: &str) -> SuggestionResult<Validation> {
    if matches!(
        id,
        H3_NO_ERROR |
            H3_GENERAL_PROTOCOL_ERROR |
            H3_INTERNAL_ERROR |
            H3_STREAM_CREATION_ERROR |
            H3_CLOSED_CRITICAL_STREAM |
            H3_FRAME_UNEXPECTED |
            H3_FRAME_ERROR |
            H3_EXCESSIVE_LOAD |
            H3_ID_ERROR |
            H3_SETTINGS_ERROR |
            H3_MISSING_SETTINGS |
            H3_REQUEST_REJECTED |
            H3_REQUEST_CANCELLED |
            H3_REQUEST_INCOMPLETE |
            H3_MESSAGE_ERROR |
            H3_CONNECT_ERROR |
            H3_VERSION_FALLBACK |
            QPACK_DECOMPRESSION_FAILED |
            QPACK_ENCODER_STREAM_ERROR |
            QPACK_DECODER_STREAM_ERROR |
            H3_DATAGRAM_ERROR
    ) {
        return Ok(Validation::Valid);
    }

    h3::validate_varint(id)
}

fn h3_error_code_suggestor(val: &str) -> SuggestionResult<Vec<String>> {
    let suggestions = [
        H3_NO_ERROR,
        H3_GENERAL_PROTOCOL_ERROR,
        H3_INTERNAL_ERROR,
        H3_STREAM_CREATION_ERROR,
        H3_CLOSED_CRITICAL_STREAM,
        H3_FRAME_UNEXPECTED,
        H3_FRAME_ERROR,
        H3_EXCESSIVE_LOAD,
        H3_ID_ERROR,
        H3_SETTINGS_ERROR,
        H3_MISSING_SETTINGS,
        H3_REQUEST_REJECTED,
        H3_REQUEST_CANCELLED,
        H3_REQUEST_INCOMPLETE,
        H3_MESSAGE_ERROR,
        H3_CONNECT_ERROR,
        H3_VERSION_FALLBACK,
        QPACK_DECOMPRESSION_FAILED,
        QPACK_ENCODER_STREAM_ERROR,
        QPACK_DECODER_STREAM_ERROR,
        H3_DATAGRAM_ERROR,
    ];

    super::squish_suggester(&suggestions, val)
}
