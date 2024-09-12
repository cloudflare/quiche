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

//! QUIC and HTTP/3 errors for the h3i client.
use inquire::error::InquireResult;
use inquire::validator::Validation;
use inquire::CustomUserError;
use inquire::Select;
use inquire::Text;
use qlog::events::quic::ErrorSpace;

use crate::prompts::h3;

use super::SuggestionResult;

pub const NO_ERROR: &str = "NO_ERROR";
pub const INTERNAL_ERROR: &str = "INTERNAL_ERROR";
pub const CONNECTION_REFUSED: &str = "CONNECTION_REFUSED";
pub const FLOW_CONTROL_ERROR: &str = "FLOW_CONTROL_ERROR";
pub const STREAM_LIMIT_ERROR: &str = "STREAM_LIMIT_ERROR";
pub const STREAM_STATE_ERROR: &str = "STREAM_STATE_ERROR";
pub const FINAL_SIZE_ERROR: &str = "FINAL_SIZE_ERROR";
pub const FRAME_ENCODING_ERROR: &str = "FRAME_ENCODING_ERROR";
pub const TRANSPORT_PARAMETER_ERROR: &str = "TRANSPORT_PARAMETER_ERROR";
pub const CONNECTION_ID_LIMIT_ERROR: &str = "CONNECTION_ID_LIMIT_ERROR";
pub const PROTOCOL_VIOLATION: &str = "PROTOCOL_VIOLATION";
pub const INVALID_TOKEN: &str = "INVALID_TOKEN";
pub const APPLICATION_ERROR: &str = "APPLICATION_ERROR";
pub const CRYPTO_BUFFER_EXCEEDED: &str = "CRYPTO_BUFFER_EXCEEDED";
pub const KEY_UPDATE_ERROR: &str = "KEY_UPDATE_ERROR";
pub const AEAD_LIMIT_REACHED: &str = "AEAD_LIMIT_REACHED";
pub const NO_VIABLE_PATH: &str = "NO_VIABLE_PATH";
pub const VERSION_NEGOTIATION_ERROR: &str = "VERSION_NEGOTIATION_ERROR";

pub const H3_DATAGRAM_ERROR: &str = "H3_DATAGRAM_ERROR";
pub const H3_NO_ERROR: &str = "H3_NO_ERROR";
pub const H3_GENERAL_PROTOCOL_ERROR: &str = "H3_GENERAL_PROTOCOL_ERROR";
pub const H3_INTERNAL_ERROR: &str = "H3_INTERNAL_ERROR";
pub const H3_STREAM_CREATION_ERROR: &str = "H3_STREAM_CREATION_ERROR";
pub const H3_CLOSED_CRITICAL_STREAM: &str = "H3_CLOSED_CRITICAL_STREAM";
pub const H3_FRAME_UNEXPECTED: &str = "H3_FRAME_UNEXPECTED";
pub const H3_FRAME_ERROR: &str = "H3_FRAME_ERROR";
pub const H3_EXCESSIVE_LOAD: &str = "H3_EXCESSIVE_LOAD";
pub const H3_ID_ERROR: &str = "H3_ID_ERROR";
pub const H3_SETTINGS_ERROR: &str = "H3_SETTINGS_ERROR";
pub const H3_MISSING_SETTINGS: &str = "H3_MISSING_SETTINGS";
pub const H3_REQUEST_REJECTED: &str = "H3_REQUEST_REJECTED";
pub const H3_REQUEST_CANCELLED: &str = "H3_REQUEST_CANCELLED";
pub const H3_REQUEST_INCOMPLETE: &str = "H3_REQUEST_INCOMPLETE";
pub const H3_MESSAGE_ERROR: &str = "H3_MESSAGE_ERROR";
pub const H3_CONNECT_ERROR: &str = "H3_CONNECT_ERROR";
pub const H3_VERSION_FALLBACK: &str = "H3_VERSION_FALLBACK";
pub const QPACK_DECOMPRESSION_FAILED: &str = "QPACK_DECOMPRESSION_FAILED";
pub const QPACK_ENCODER_STREAM_ERROR: &str = "QPACK_ENCODER_STREAM_ERROR";
pub const QPACK_DECODER_STREAM_ERROR: &str = "QPACK_DECODER_STREAM_ERROR";

pub const TRANSPORT: &str = "transport";
pub const APPLICATION: &str = "application";

// TODO: do we want to rely on the qlog enum here?
pub fn prompt_transport_or_app_error() -> InquireResult<(ErrorSpace, u64)> {
    let trans_or_app = prompt_transport_or_app()?;
    let space = if trans_or_app == TRANSPORT {
        ErrorSpace::TransportError
    } else {
        ErrorSpace::ApplicationError
    };

    let error_code = if matches!(space, ErrorSpace::TransportError) {
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

    Ok((space, error_code))
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
