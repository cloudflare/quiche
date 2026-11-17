// quiche/src/clock.rs
//
// A pluggable clock so quiche's timing (RTT, pacing, loss detection)
// can be driven by an external simulated clock (e.g. ns-3) instead of
// the real OS clock.

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::OnceLock;
use std::time::{Duration, Instant};

static EPOCH: OnceLock<Instant> = OnceLock::new();
static SIM_OFFSET_US: AtomicU64 = AtomicU64::new(0);
static SIM_MODE: AtomicBool = AtomicBool::new(false);

fn epoch() -> Instant {
    *EPOCH.get_or_init(Instant::now)
}

/// Returns the current time as quiche should see it.
///
/// In real-clock mode (default), this is identical to `Instant::now()`.
/// In simulated mode, this is `epoch + simulated_offset`.
pub fn now() -> Instant {
    if SIM_MODE.load(Ordering::Acquire) {
        epoch() + Duration::from_micros(SIM_OFFSET_US.load(Ordering::Acquire))
    } else {
        Instant::now()
    }
}

/// Switches quiche into simulated-time mode and sets the current
/// simulated time, in microseconds since the connection/process epoch.
///
/// Call this once before any quiche API that reads time (recv/send/
/// on_timeout/timeout), every time the external simulator's clock
/// advances — e.g. from an ns-3 wrapper calling this before each
/// quiche operation with `Simulator::Now()`.
pub fn set_simulated_time_us(time_us: u64) {
    SIM_MODE.store(true, Ordering::Release);
    // Force epoch initialization now, so epoch() is stable from here on.
    let _ = epoch();
    SIM_OFFSET_US.store(time_us, Ordering::Release);
}

/// Reverts to the real OS clock (mainly useful for tests).
#[allow(dead_code)]
pub fn use_real_clock() {
    SIM_MODE.store(false, Ordering::Release);
}
