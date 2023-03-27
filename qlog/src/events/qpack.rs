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

use serde::Deserialize;
use serde::Serialize;

use super::h3::HttpHeader;
use super::RawInfo;

#[derive(Serialize, Deserialize, Clone, Copy, PartialEq, Eq, Debug)]
#[serde(rename_all = "snake_case")]
pub enum QpackEventType {
    StateUpdated,
    StreamStateUpdated,
    DynamicTableUpdated,
    HeadersEncoded,
    HeadersDecoded,
    InstructionCreated,
    InstructionParsed,
}

#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Debug)]
#[serde(rename_all = "snake_case")]
pub enum QpackOwner {
    Local,
    Remote,
}

#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Debug)]
#[serde(rename_all = "snake_case")]
pub enum QpackStreamState {
    Blocked,
    Unblocked,
}

#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Debug)]
#[serde(rename_all = "snake_case")]
pub enum QpackUpdateType {
    Added,
    Evicted,
}

#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Debug)]
pub struct QpackDynamicTableEntry {
    pub index: u64,
    pub name: Option<String>,
    pub value: Option<String>,
}

#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Debug)]
pub struct QpackHeaderBlockPrefix {
    pub required_insert_count: u64,
    pub sign_bit: bool,
    pub delta_base: u64,
}

#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Debug)]
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

#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Debug)]
#[serde(rename_all = "snake_case")]
pub enum QpackTableType {
    Static,
    Dynamic,
}

#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Debug)]
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

#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Debug)]
#[serde(rename_all = "snake_case")]
pub enum QpackHeaderBlockRepresentationTypeName {
    IndexedHeaderField,
    LiteralHeaderFieldWithName,
    LiteralHeaderFieldWithoutName,
}

#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Debug)]
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

#[serde_with::skip_serializing_none]
#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Debug)]
pub struct QpackStateUpdated {
    pub owner: Option<QpackOwner>,

    pub dynamic_table_capacity: Option<u64>,
    pub dynamic_table_size: Option<u64>,

    pub known_received_count: Option<u64>,
    pub current_insert_count: Option<u64>,
}

#[serde_with::skip_serializing_none]
#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Debug)]
pub struct QpackStreamStateUpdated {
    pub stream_id: u64,

    pub state: QpackStreamState,
}

#[serde_with::skip_serializing_none]
#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Debug)]
pub struct QpackDynamicTableUpdated {
    pub update_type: QpackUpdateType,

    pub entries: Vec<QpackDynamicTableEntry>,
}

#[serde_with::skip_serializing_none]
#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Debug)]
pub struct QpackHeadersEncoded {
    pub stream_id: Option<u64>,

    pub headers: Option<HttpHeader>,

    pub block_prefix: QpackHeaderBlockPrefix,
    pub header_block: Vec<QpackHeaderBlockRepresentation>,

    pub raw: Option<RawInfo>,
}

#[serde_with::skip_serializing_none]
#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Debug)]
pub struct QpackHeadersDecoded {
    pub stream_id: Option<u64>,

    pub headers: Option<HttpHeader>,

    pub block_prefix: QpackHeaderBlockPrefix,
    pub header_block: Vec<QpackHeaderBlockRepresentation>,

    pub raw: Option<RawInfo>,
}

#[serde_with::skip_serializing_none]
#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Debug)]
pub struct QpackInstructionCreated {
    pub instruction: QPackInstruction,

    pub raw: Option<RawInfo>,
}

#[serde_with::skip_serializing_none]
#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Debug)]
pub struct QpackInstructionParsed {
    pub instruction: QPackInstruction,

    pub raw: Option<RawInfo>,
}
