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
use inquire::Select;
use inquire::Text;

use super::stream::prompt_fin_stream;
use crate::actions::h3::Action;
use crate::prompts::h3;

use quiche;

const REQUEST: &str = "request";
const PUSH: &str = "push";

pub fn prompt_priority() -> InquireResult<Action> {
    let stream_id = h3::prompt_stream_id()?;

    let ty = prompt_request_or_push()?;
    let prioritized_element_id = h3::prompt_varint("Prioritized Element ID:")?;

    let priority_field_value = Text::new("priority field value:").prompt()?;

    let frame = if ty.as_str() == REQUEST {
        quiche::h3::frame::Frame::PriorityUpdateRequest {
            prioritized_element_id,
            priority_field_value: priority_field_value.into(),
        }
    } else {
        quiche::h3::frame::Frame::PriorityUpdatePush {
            prioritized_element_id,
            priority_field_value: priority_field_value.into(),
        }
    };

    let fin_stream = prompt_fin_stream()?;

    let action = Action::SendFrame {
        stream_id,
        fin_stream,
        frame,
    };

    Ok(action)
}

fn prompt_request_or_push() -> InquireResult<String> {
    Ok(Select::new("request or push:", vec![REQUEST, PUSH])
        .prompt()?
        .to_string())
}
