use serde::Deserialize;
use serde::Serialize;

#[serde_with::skip_serializing_none]
#[derive(Serialize, Deserialize, Clone, PartialEq, Debug)]
pub struct CarefulResumePhaseUpdated {
    pub old: Option<CarefulResumePhase>,
    pub new: CarefulResumePhase,
    pub state_data: CarefulResumeStateParameters,
    pub restored_data: Option<CarefulResumeRestoredParameters>,
    pub trigger: Option<CarefulResumeTrigger>,
}

#[derive(Serialize, Deserialize, Copy, Clone, PartialEq, Eq, Debug)]
#[serde(rename_all = "snake_case")]
pub enum CarefulResumeTrigger {
    /// From [Reconnaissance][CarefulResumePhase::Reconnaissance] to
    /// [Unvalidated][CarefulResumePhase::Unvalidated]
    ///
    /// When sender has confirmed the RTT, has received an ACK for the initial
    /// data without reported congestion and has more data to send than the CWND
    /// would allow.
    CongestionWindowLimited,

    /// From [Reconnaissance][CarefulResumePhase::Reconnaissance]/
    /// [Unvalidated][CarefulResumePhase::Unvalidated] to
    /// [Normal][CarefulResumePhase::Normal]
    ///
    /// If the current_rtt is not confirmed the sender MUST enter the Normal
    /// Phase.
    RttNotValidated,

    /// From [Unvalidated][CarefulResumePhase::Unvalidated] to
    /// [Validating][CarefulResumePhase::Validating]
    ///
    /// Completed sending all packets, e.g., when flight_size is equal to the
    /// CWND after the jump
    LastUnvalidatedPacketSent,

    /// From [Unvalidated][CarefulResumePhase::Unvalidated] to
    /// [Validating][CarefulResumePhase::Validating]
    ///
    /// The sender enters the Validating Phase when an ACK is received for the
    /// first packet number (or higher) sent in the Unvalidated Phase.
    FirstUnvalidatedPacketAcknowledged,

    /// From [Unvalidated][CarefulResumePhase::Unvalidated] to
    /// [Validating][CarefulResumePhase::Validating]
    ///
    /// When greater than 1 RTT has passed in Unvalidated Phase.
    RttExceeded,

    /// From [Unvalidated][CarefulResumePhase::Unvalidated] to
    /// [Normal][CarefulResumePhase::Normal]
    ///
    /// If the flight_size is less than or equal to the PipeSize sender enters
    /// Normal Phase.
    RateLimited,

    /// From [Validating][CarefulResumePhase::Validating] to
    /// [Normal][CarefulResumePhase::Normal]
    ///
    /// The sender enters the Normal Phase when an ACK is received for the last
    /// packet number (or higher) that was sent in the Unvalidated Phase.
    LastUnvalidatedPacketAcknowledged,

    /// From [Unvalidated][CarefulResumePhase::Unvalidated] to
    /// [SafeRetreat][CarefulResumePhase::SafeRetreat]
    ///
    /// If a sender determines that it is not valid to use the previous CC
    /// parameters due to a deteced path change, e.g., a change in RTT or an
    /// explicit signal indicating a path change.
    PathChanged,

    /// From [Reconnaissance][CarefulResumePhase::Reconnaissance] to
    /// [Normal][CarefulResumePhase::Normal]
    ///
    /// and from [Unvalidated][CarefulResumePhase::Unvalidated]/
    /// [Validating][CarefulResumePhase::Validating]
    /// to [SafeRetreat][CarefulResumePhase::SafeRetreat]
    ///
    /// If a sender determines that congestion was experienced, e.g., packet
    /// loss, the sender enters the Safe Retreat Phase.
    PacketLoss,

    /// From [Reconnaissance][CarefulResumePhase::Reconnaissance] to
    /// [Normal][CarefulResumePhase::Normal]
    ///
    /// and from [Unvalidated][CarefulResumePhase::Unvalidated]/
    /// [Validating][CarefulResumePhase::Validating]
    /// to [SafeRetreat][CarefulResumePhase::SafeRetreat]
    ///
    /// If a sender determines that congestion was experienced, e.g., ECN-CE
    /// marking, sender enters the Safe Retreat Phase.
    #[serde(rename = "ECN_CE")]
    EcnCe,

    /// From [SafeRetreat][CarefulResumePhase::SafeRetreat] to
    /// [Normal][CarefulResumePhase::Normal]
    ///
    /// The sender enters the Normal Phase when the last packet sent in the
    /// Unvalidated Phase is ACKed.
    ExitRecovery,
}

/// Careful Resume defines a series of phases that a congestion controller moves
/// through as a connection uses the mechanism.
#[derive(Serialize, Deserialize, Copy, Clone, PartialEq, Eq, Debug)]
#[serde(rename_all = "snake_case")]
pub enum CarefulResumePhase {
    Reconnaissance,
    Unvalidated,
    Validating,
    Normal,
    SafeRetreat,
}

#[serde_with::skip_serializing_none]
#[derive(Serialize, Deserialize, Copy, Clone, PartialEq, Eq, Debug)]
pub struct CarefulResumeStateParameters {
    pub pipesize: u64,
    pub first_unvalidated_packet: u64,
    pub last_unvalidated_packet: u64,
    pub congestion_window: Option<u64>,
    pub ssthresh: Option<u64>,
}

#[serde_with::skip_serializing_none]
#[derive(Serialize, Deserialize, Copy, Clone, PartialEq, Debug)]
pub struct CarefulResumeRestoredParameters {
    pub saved_congestion_window: u64,
    pub saved_rtt: f32,
}
