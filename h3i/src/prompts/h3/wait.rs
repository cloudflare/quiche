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

use std::time::Duration;

use inquire::error::InquireResult;
use inquire::validator::Validation;
use inquire::Text;

use crate::actions::h3::Action;
use crate::actions::h3::StreamEvent;
use crate::actions::h3::StreamEventType;
use crate::actions::h3::WaitType;

use super::prompt_stream_id;
use super::squish_suggester;
use super::validate_wait_period;
use super::SuggestionResult;

const DURATION: &str = "duration";
const HEADERS: &str = "headers";
const DATA: &str = "data";
const FINISHED: &str = "stream finished";

pub fn prompt_wait() -> InquireResult<Action> {
    let wait_type = Text::new("wait type:")
        .with_autocomplete(&wait_type_suggestor)
        .with_validator(wait_type_validator)
        .prompt()?;

    let actual = match wait_type.as_str() {
        DURATION => Some(prompt_wait_period()),
        t @ (HEADERS | DATA | FINISHED) => Some(prompt_stream_wait(t)),
        _ => None,
    };

    let action = Action::Wait {
        // unwrap should be safe due to validation
        wait_type: actual.unwrap()?,
    };

    Ok(action)
}

fn wait_type_suggestor(val: &str) -> SuggestionResult<Vec<String>> {
    let suggestions = [DURATION, HEADERS, DATA, FINISHED];

    squish_suggester(&suggestions, val)
}

fn wait_type_validator(wait_type: &str) -> SuggestionResult<Validation> {
    match wait_type {
        DURATION | HEADERS | DATA | FINISHED => Ok(Validation::Valid),
        _ => Ok(Validation::Invalid(
            inquire::validator::ErrorMessage::Default,
        )),
    }
}

fn prompt_stream_wait(stream_wait_type: &str) -> InquireResult<WaitType> {
    let stream_id = prompt_stream_id()?;

    let event_type = if let HEADERS = stream_wait_type {
        Some(StreamEventType::Headers)
    } else if let DATA = stream_wait_type {
        Some(StreamEventType::Data)
    } else if let FINISHED = stream_wait_type {
        Some(StreamEventType::Finished)
    } else {
        None
    }
    // If somehow we've gotten an invalid input, we can panic. This is post validation so that
    // shouldn't happen
    .unwrap();

    Ok(WaitType::StreamEvent(StreamEvent {
        stream_id,
        event_type,
    }))
}

pub fn prompt_wait_period() -> InquireResult<WaitType> {
    let period = Text::new("wait period (ms):")
        .with_validator(validate_wait_period)
        .prompt()?;

    // period is already validated so unwrap always succeeds
    let period = Duration::from_millis(period.parse::<u64>().unwrap());

    Ok(WaitType::WaitDuration(period))
}
