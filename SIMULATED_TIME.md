# QUICHE with Simulated-Time Support

A modified version of [Cloudflare QUICHE](https://github.com/cloudflare/quiche) that introduces a configurable clock abstraction and a C-compatible API for controlling QUICHE's internal time.

## 1. Problem Statement

QUICHE internally relies on Rust's `std::time::Instant::now()` to obtain the current system time.

This works correctly in conventional network environments, where applications operate using the operating system's real-time clock. However, it creates a challenge when QUICHE is used in a discrete-event simulation environment.

In such environments, simulated time advances independently of real-world time. For example, a simulation may advance by several seconds while only a few milliseconds pass on the actual machine.

If QUICHE continues using the system clock, its internal time-dependent operations can become inconsistent with the simulation's timeline.

This affects mechanisms that depend on elapsed time, including:

- Round-trip time (RTT) measurement.
- Packet loss detection.
- Congestion control.
- Packet pacing.
- Connection timeout calculations.

**Objective:** Introduce a pluggable clock inside QUICHE that preserves its existing real-clock behaviour by default while allowing an external application to control its internal time through a C-compatible interface.

## 2. Proposed Solution

The implementation introduces a simulated-time clock abstraction directly into the QUICHE Rust crate.

Instead of accessing `Instant::now()` directly at the modified production-code locations, QUICHE uses a common clock interface:

```rust
crate::clock::now()
```

This provides two operating modes:

1. **Real-clock mode:** The default mode. QUICHE uses the operating system's clock, preserving its original behaviour.
2. **Simulated-clock mode:** An external application supplies time in microseconds through the exported C FFI function.

The implementation uses Rust atomic variables to maintain the simulated-clock state.

## 3. Architecture and Implementation

### 3.1 Simulated Clock Abstraction

**File:** `quiche/src/clock.rs`

A new clock module provides the central time interface.

Its main components are:

| Component | Responsibility |
|---|---|
| `EPOCH` | Stores a stable `Instant` used as the clock's reference point. |
| `SIM_OFFSET_US` | Stores the externally supplied simulated time in microseconds. |
| `SIM_MODE` | Determines whether QUICHE uses real or simulated time. |
| `now()` | Returns the current time according to the active clock mode. |
| `set_simulated_time_us()` | Enables simulated-clock mode and updates the simulated time. |
| `use_real_clock()` | Restores real-clock mode. |

The implementation uses:

- `OnceLock<Instant>` for one-time epoch initialization.
- `AtomicU64` for simulated-time storage.
- `AtomicBool` for tracking the active clock mode.
- `Ordering::Acquire` and `Ordering::Release` for atomic synchronization.

### How the clock works

In real-clock mode:

```rust
Instant::now()
```

is returned, maintaining the original QUICHE behaviour.

In simulated-clock mode:

```rust
epoch() + Duration::from_micros(
    SIM_OFFSET_US.load(Ordering::Acquire)
)
```

is returned.

Rust's `Instant` cannot be constructed directly from an arbitrary numeric timestamp. Therefore, the implementation captures a stable real `Instant` as an epoch and adds the externally supplied simulated-time offset.

For example:

| Simulated time | Internal time representation |
|---|---|
| 0 ms | E + 0 ms |
| 20 ms | E + 20 ms |
| 70 ms | E + 70 ms |

The difference between two returned instants represents the corresponding simulated-time difference.

### 3.2 Clock Module Registration

**File:** `quiche/src/lib.rs`

The new clock module is registered within the QUICHE crate:

```rust
mod clock;
```

This makes the clock abstraction available to other modules within the crate.

### 3.3 Replacing Direct System-Clock Access

Direct `Instant::now()` calls in the relevant production code have been replaced with:

```rust
crate::clock::now()
```

A total of **17 call sites across 8 Rust source files** were updated.

| File | Modified call sites |
|---|---:|
| `quiche/src/lib.rs` | 9 |
| `quiche/src/minmax.rs` | 1 |
| `quiche/src/packet.rs` | 1 |
| `quiche/src/recovery/mod.rs` | 1 |
| `quiche/src/recovery/congestion/delivery_rate.rs` | 1 |
| `quiche/src/recovery/gcongestion/bbr2/network_model.rs` | 1 |
| `quiche/src/recovery/gcongestion/bbr2/mode.rs` | 1 |
| `quiche/src/recovery/gcongestion/bbr/bandwidth_sampler.rs` | 4 |

These changes ensure that the relevant QUICHE timing operations use the configurable clock abstraction rather than independently accessing the system clock.

Existing test-specific and intentionally retained real-clock accesses are not indiscriminately replaced.

### 3.4 C Foreign Function Interface (FFI)

**File:** `quiche/src/ffi.rs`

A C-compatible function exposes simulated-time control outside the Rust crate:

```rust
#[no_mangle]
pub extern "C" fn quiche_set_simulated_time_us(time_us: u64) {
    crate::clock::set_simulated_time_us(time_us);
}
```

This function allows an external C/C++ application to supply the current simulated time in microseconds.

The first invocation activates simulated-clock mode.

Subsequent invocations update the simulated-time offset.

### 3.5 C Header Declaration

**File:** `quiche/include/quiche.h`

The corresponding C function declaration is added to QUICHE's public header:

```c
void quiche_set_simulated_time_us(uint64_t time_us);
```

This exposes the API to applications integrating with the QUICHE C interface.

## 4. Files Modified

The implementation introduces one new Rust source file and modifies the following existing QUICHE files.

| File | Modification |
|---|---|
| `quiche/src/clock.rs` | New simulated-clock implementation |
| `quiche/src/ffi.rs` | New C-compatible simulated-time setter |
| `quiche/include/quiche.h` | Declaration of the exported API |
| `quiche/src/lib.rs` | Clock module registration and time-source replacements |
| `quiche/src/minmax.rs` | Uses configurable clock |
| `quiche/src/packet.rs` | Uses configurable clock |
| `quiche/src/recovery/mod.rs` | Uses configurable clock |
| `quiche/src/recovery/congestion/delivery_rate.rs` | Uses configurable clock |
| `quiche/src/recovery/gcongestion/bbr2/network_model.rs` | Uses configurable clock |
| `quiche/src/recovery/gcongestion/bbr2/mode.rs` | Uses configurable clock |
| `quiche/src/recovery/gcongestion/bbr/bandwidth_sampler.rs` | Uses configurable clock |

All these modifications are already included in this repository.

**No additional source-code patching or `sed` replacement commands are required when using this repository.**

## 5. Building QUICHE

The implementation can be built using Cargo with FFI support enabled.

From the QUICHE crate directory:

```bash
cd quiche
cargo build --release --features ffi
```

The build uses the parent workspace's `target` directory.

## 6. Verifying the Exported API

After a successful build, verify that the shared library exports the simulated-time function.

From the `quiche/` directory, run:

```bash
nm -D ../target/release/libquiche.so | grep simulated_time
```

The expected output should contain:

```text
T quiche_set_simulated_time_us
```

The `T` symbol indicates that the function is defined in the library's exported text section.

This confirms that the C-compatible simulated-time API is available in the generated shared library.

## 7. Scope and Integration Boundary

This repository focuses exclusively on modifications to the QUICHE implementation.

It includes:

- The configurable clock abstraction.
- Simulated-time state management.
- Updated QUICHE production-code time accesses.
- The C FFI setter.
- The corresponding public C header declaration.
- Build and symbol-verification instructions.

It does not include external simulator-specific wrappers, event scheduling, simulation topology, or application integration code.

The responsibility of this repository is to provide QUICHE with a configurable internal time source and expose an interface through which an external application can control that time.

## 8. Expected Outcome

The modified QUICHE implementation provides:

1. Backward-compatible real-clock operation by default.
2. An externally controllable simulated-clock mode.
3. Consistent time-source access across the modified QUICHE production code.
4. A C-compatible API for supplying simulated time.
5. A buildable QUICHE library with an exported simulated-time function.

This establishes the QUICHE-side foundation for using its time-dependent transport mechanisms in externally controlled simulated environments.
