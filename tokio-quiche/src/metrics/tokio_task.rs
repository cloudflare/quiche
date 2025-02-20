// Copyright (C) 2025, Cloudflare, Inc.
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

//! Instrumentation and metrics for spawned tokio tasks.
//!
//! Currently, this is implemented by creating wrapper futures and wakers for
//! the future inside of a spawned task. Ideally we would be able to move at
//! least some of this work into tokio proper at some point, but this should be
//! sufficient for now.
//!
//! This does *not* rely on the tokio-metrics crate, as that has more overhead
//! than we would like.

use crate::metrics::Metrics;
use foundations::telemetry::TelemetryContext;
use pin_project::pin_project;
use std::future::Future;
use std::pin::pin;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::Mutex;
use std::task::Context;
use std::task::Poll;
use std::task::Wake;
use std::task::Waker;
use std::time::Instant;
use task_killswitch::spawn_with_killswitch as killswitch_spawn;
use tokio::task::JoinHandle;

/// An instrumented future.
///
/// It's important to keep overhead low here, especially where contention is
/// concerned.
#[pin_project]
struct Instrumented<F, M> {
    #[pin]
    future: F,
    name: Arc<str>,
    timer: Arc<Mutex<Option<Instant>>>,
    metrics: M,
}

/// An instrumented waker for our instrumented future.
///
/// It's very important to keep overhead low here, especially where contention
/// is concerned.
struct InstrumentedWaker {
    timer: Arc<Mutex<Option<Instant>>>,
    waker: Waker,
}

impl Wake for InstrumentedWaker {
    fn wake(self: Arc<Self>) {
        self.wake_by_ref()
    }

    fn wake_by_ref(self: &Arc<Self>) {
        // let's scope the guard's lifespan in case the inner waker is slow
        // this is still highly unlikely to be contended ever
        {
            let mut guard = self.timer.lock().unwrap();

            if guard.is_none() {
                *guard = Some(Instant::now())
            }
        }

        self.waker.wake_by_ref();
    }
}

impl<F, M> Instrumented<F, M>
where
    M: Metrics,
{
    fn new(name: &str, metrics: M, future: F) -> Self {
        let name = Arc::from(name);

        Self {
            future,
            name,
            metrics,
            timer: Arc::new(Mutex::new(Some(Instant::now()))),
        }
    }
}

impl<F: Future, M: Metrics> Future for Instrumented<F, M> {
    type Output = F::Output;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let total_timer = Instant::now();

        // if we were to hold the lock over the poll boundary, self-wakes would
        // deadlock us, so we won't do that.
        //
        // this is unlikely to be contended much otherwise.
        let maybe_schedule_timer = self.timer.lock().unwrap().take();

        // for various reasons related to how rust does lifetime things, we will
        // not acquire the lock in the if statement
        if let Some(schedule_timer) = maybe_schedule_timer {
            let elapsed = schedule_timer.elapsed();

            self.metrics
                .tokio_runtime_task_schedule_delay_histogram(&self.name)
                .observe(elapsed.as_nanos() as u64);
        }

        let projected = self.project();

        let waker = Waker::from(Arc::new(InstrumentedWaker {
            timer: Arc::clone(projected.timer),
            waker: cx.waker().clone(),
        }));

        let mut new_cx = Context::from_waker(&waker);

        let timer = Instant::now();

        let output = projected.future.poll(&mut new_cx);

        let elapsed = timer.elapsed();

        projected
            .metrics
            .tokio_runtime_task_poll_duration_histogram(projected.name)
            .observe(elapsed.as_nanos() as u64);

        let total_elapsed = total_timer.elapsed();

        projected
            .metrics
            .tokio_runtime_task_total_poll_time_micros(projected.name)
            .inc_by(total_elapsed.as_micros() as u64);

        output
    }
}

/// Spawn a potentially instrumented task.
///
/// Depending on whether the `tokio-task-metrics` feature is enabled, this may
/// instrument the task and collect metrics for it.
pub fn spawn<M, T>(name: &str, metrics: M, future: T) -> JoinHandle<T::Output>
where
    T: Future + Send + 'static,
    T::Output: Send + 'static,
    M: Metrics,
{
    let ctx = TelemetryContext::current();

    if cfg!(feature = "tokio-task-metrics") {
        tokio::spawn(Instrumented::new(name, metrics, ctx.apply(future)))
    } else {
        tokio::spawn(ctx.apply(future))
    }
}

/// Spawn a potentially instrumented, long-lived task. Integrates with
/// [task-killswitch](task_killswitch).
///
/// Depending on whether the `tokio-task-metrics` feature is enabled, this may
/// instrument the task and collect metrics for it.
pub fn spawn_with_killswitch<M, T>(name: &str, metrics: M, future: T)
where
    T: Future<Output = ()> + Send + 'static,
    M: Metrics,
{
    let ctx = TelemetryContext::current();

    if cfg!(feature = "tokio-task-metrics") {
        killswitch_spawn(Instrumented::new(name, metrics, ctx.apply(future)))
    } else {
        killswitch_spawn(ctx.apply(future))
    }
}
