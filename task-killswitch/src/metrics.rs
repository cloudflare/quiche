use crate::ActiveTaskOp;
use foundations::telemetry::metrics::metrics;
use foundations::telemetry::metrics::Counter;
use foundations::telemetry::metrics::Gauge;

pub const OP_KIND_ADD: &str = "add";
pub const OP_KIND_REMOVE: &str = "remove";

#[metrics]
pub mod killswitch_queue {
    /// Length of task-killswitch's operation queue.
    pub fn length() -> Gauge;

    /// Number of operations of each `kind` that have been sent on the channel.
    pub fn ops_sent(kind: &'static str) -> Counter;

    /// Number of operations of each `kind` that have been received on the
    /// channel.
    pub fn ops_received(kind: &'static str) -> Counter;
}

pub fn count_ops_received(ops: &[ActiveTaskOp]) {
    let mut add = 0;
    let mut remove = 0;

    for op in ops {
        match op {
            ActiveTaskOp::Add { .. } => add += 1,
            ActiveTaskOp::Remove { .. } => remove += 1,
        }
    }

    self::killswitch_queue::ops_received(OP_KIND_ADD).inc_by(add);
    self::killswitch_queue::ops_received(OP_KIND_REMOVE).inc_by(remove);
}
