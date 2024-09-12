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
use inquire::Text;

use crate::actions::h3::Action;
use crate::prompts::h3;
use crate::prompts::h3::errors::prompt_transport_or_app_error;
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

    let (_, error_code) = prompt_transport_or_app_error()?;

    Ok((id, error_code))
}
