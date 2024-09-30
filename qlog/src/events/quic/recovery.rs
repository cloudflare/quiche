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

use super::PacketHeader;
use crate::events::PacketNumberSpace;
use crate::events::QuicFrame;

#[derive(Serialize, Deserialize, Clone, Copy, PartialEq, Eq, Debug)]
#[serde(rename_all = "snake_case")]
pub enum RecoveryEventType {
    ParametersSet,
    MetricsUpdated,
    CongestionStateUpdated,
    LossTimerUpdated,
    PacketLost,
    MarkedForRetransmit,
}

#[derive(Serialize, Deserialize, Clone, Copy, PartialEq, Eq, Debug)]
#[serde(rename_all = "snake_case")]
pub enum CongestionStateUpdatedTrigger {
    PersistentCongestion,
    Ecn,
}

#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Debug)]
#[serde(rename_all = "snake_case")]
pub enum TimerType {
    Ack,
    Pto,
}

#[derive(Serialize, Deserialize, Clone, Copy, PartialEq, Eq, Debug)]
#[serde(rename_all = "snake_case")]
pub enum PacketLostTrigger {
    ReorderingThreshold,
    TimeThreshold,
    PtoExpired,
}

#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Debug)]
#[serde(rename_all = "snake_case")]
pub enum LossTimerEventType {
    Set,
    Expired,
    Cancelled,
}

#[serde_with::skip_serializing_none]
#[derive(Serialize, Deserialize, Clone, PartialEq, Debug)]
pub struct ParametersSet {
    pub reordering_threshold: Option<u16>,
    pub time_threshold: Option<f32>,
    pub timer_granularity: Option<u16>,
    pub initial_rtt: Option<f32>,

    pub max_datagram_size: Option<u32>,
    pub initial_congestion_window: Option<u64>,
    pub minimum_congestion_window: Option<u32>,
    pub loss_reduction_factor: Option<f32>,
    pub persistent_congestion_threshold: Option<u16>,
}

#[serde_with::skip_serializing_none]
#[derive(Serialize, Deserialize, Clone, PartialEq, Debug)]
pub struct MetricsUpdated {
    pub min_rtt: Option<f32>,
    pub smoothed_rtt: Option<f32>,
    pub latest_rtt: Option<f32>,
    pub rtt_variance: Option<f32>,

    pub pto_count: Option<u16>,

    pub congestion_window: Option<u64>,
    pub bytes_in_flight: Option<u64>,

    pub ssthresh: Option<u64>,

    // qlog defined
    pub packets_in_flight: Option<u64>,

    pub pacing_rate: Option<u64>,
}

#[serde_with::skip_serializing_none]
#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Debug)]
pub struct CongestionStateUpdated {
    pub old: Option<String>,
    pub new: String,

    pub trigger: Option<CongestionStateUpdatedTrigger>,
}

#[serde_with::skip_serializing_none]
#[derive(Serialize, Deserialize, Clone, PartialEq, Debug)]
pub struct LossTimerUpdated {
    pub timer_type: Option<TimerType>,
    pub packet_number_space: Option<PacketNumberSpace>,

    pub event_type: LossTimerEventType,

    pub delta: Option<f32>,
}

#[serde_with::skip_serializing_none]
#[derive(Serialize, Deserialize, Clone, PartialEq, Debug)]
pub struct PacketLost {
    pub header: Option<PacketHeader>,

    pub frames: Option<Vec<QuicFrame>>,

    pub trigger: Option<PacketLostTrigger>,
}

#[serde_with::skip_serializing_none]
#[derive(Serialize, Deserialize, Clone, PartialEq, Debug)]
pub struct MarkedForRetransmit {
    pub frames: Vec<QuicFrame>,
}
