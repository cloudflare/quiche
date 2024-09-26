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

//! Prompts for HTTP/3 header fields.

use inquire::error::InquireResult;
use inquire::validator::Validation;
use inquire::Text;
use quiche;
use quiche::h3::frame::Frame;

use crate::encode_header_block;
use crate::prompts::h3;
use crate::StreamIdAllocator;

use super::squish_suggester;
use super::stream::prompt_fin_stream;
use super::SuggestionResult;
use super::AUTO_PICK;
use super::EMPTY_PICKS;
use super::ESC_TO_RET;
use super::PUSH_ID_PROMPT;
use super::STREAM_ID_PROMPT;
use crate::actions::h3::Action;

pub fn prompt_headers(
    sid_alloc: &mut StreamIdAllocator, host_port: &str, raw: bool,
) -> InquireResult<Action> {
    let stream_id = Text::new(STREAM_ID_PROMPT)
        .with_placeholder(EMPTY_PICKS)
        .with_help_message(ESC_TO_RET)
        .with_validator(validate_stream_id)
        .prompt()?;

    let stream_id = match stream_id.as_str() {
        "" => {
            let id = sid_alloc.peek_next_id();
            println!("{AUTO_PICK}={id}");
            id
        },

        _ => stream_id.parse::<u64>().unwrap(),
    };

    let mut headers = vec![];

    if !raw {
        headers.extend_from_slice(&pseudo_headers(host_port)?);
    }

    headers.extend_from_slice(&headers_read_loop()?);

    sid_alloc.take_next_id();

    let header_block = encode_header_block(&headers).unwrap_or_default();

    let fin_stream = prompt_fin_stream()?;

    let action = Action::SendHeadersFrame {
        stream_id,
        fin_stream,
        headers,
        frame: Frame::Headers { header_block },
    };

    Ok(action)
}

pub fn prompt_push_promise() -> InquireResult<Action> {
    let stream_id = h3::prompt_stream_id()?;
    let push_id = h3::prompt_varint(PUSH_ID_PROMPT)?;

    let headers = headers_read_loop()?;
    let header_block = if headers.is_empty() {
        vec![]
    } else {
        encode_header_block(&headers).unwrap()
    };

    let fin_stream = prompt_fin_stream()?;

    let action = Action::SendFrame {
        stream_id,
        fin_stream,
        frame: Frame::PushPromise {
            push_id,
            header_block,
        },
    };

    Ok(action)
}

fn pseudo_headers(host_port: &str) -> InquireResult<Vec<quiche::h3::Header>> {
    let method = Text::new("method:")
        .with_autocomplete(&method_suggester)
        .with_default("GET")
        .with_help_message(ESC_TO_RET)
        .prompt()?;

    let help = format!("Press enter/return for default ({host_port}");
    let authority = Text::new("authority:")
        .with_default(host_port)
        .with_help_message(&help)
        .prompt()?;

    let path = Text::new("path:").with_default("/").prompt()?;

    let scheme = Text::new("scheme:")
        .with_default("https")
        .with_help_message(ESC_TO_RET)
        .prompt()?;

    Ok(vec![
        quiche::h3::Header::new(b":method", method.as_bytes()),
        quiche::h3::Header::new(b":authority", authority.as_bytes()),
        quiche::h3::Header::new(b":path", path.as_bytes()),
        quiche::h3::Header::new(b":scheme", scheme.as_bytes()),
    ])
}

fn headers_read_loop() -> InquireResult<Vec<quiche::h3::Header>> {
    let mut headers = vec![];
    loop {
        let name = Text::new("field name:")
            .with_help_message(
                "type 'q!' to complete headers, or ESC to return to actions",
            )
            .prompt()?;

        if name == "q!" {
            break;
        }

        let value = Text::new("field value:")
            .with_help_message(ESC_TO_RET)
            .prompt()?;

        headers.push(quiche::h3::Header::new(name.as_bytes(), value.as_bytes()));
    }

    Ok(headers)
}

fn method_suggester(val: &str) -> SuggestionResult<Vec<String>> {
    let suggestions = ["GET", "POST", "PUT", "DELETE"];

    squish_suggester(&suggestions, val)
}

fn validate_stream_id(id: &str) -> SuggestionResult<Validation> {
    if id.is_empty() {
        return Ok(Validation::Valid);
    }

    h3::validate_varint(id)
}
