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

use tokio::sync::mpsc;
use tokio::sync::watch;
use tokio::task::JoinHandle;

use std::collections::HashMap;

use std::future::Future;
use std::sync::atomic::AtomicU64;
use std::sync::atomic::Ordering;
use std::sync::LazyLock;

enum ActiveTaskOp {
    Add { id: u64, handle: JoinHandle<()> },
    Remove { id: u64 },
}

/// Drop guard for task removal. If a task panics, this makes sure
/// it is removed from [`ActiveTasks`] properly.
struct RemoveOnDrop {
    id: u64,
    task_tx_weak: mpsc::WeakUnboundedSender<ActiveTaskOp>,
}
impl Drop for RemoveOnDrop {
    fn drop(&mut self) {
        if let Some(tx) = self.task_tx_weak.upgrade() {
            let _ = tx.send(ActiveTaskOp::Remove { id: self.id });
        }
    }
}

/// A task killswitch that allows aborting all the tasks spawned with it at
/// once. The implementation strives to not introduce any in-band locking, so
/// spawning the future doesn't require acquiring a global lock, keeping the
/// regular pace of operation.
struct TaskKillswitch {
    // NOTE: use a lock without poisoning here to not panic all the threads if
    // one of the worker threads panic.
    task_tx: parking_lot::RwLock<Option<mpsc::UnboundedSender<ActiveTaskOp>>>,
    task_counter: AtomicU64,
    all_killed: watch::Receiver<()>,
}

impl TaskKillswitch {
    fn new() -> Self {
        let (task_tx, task_rx) = mpsc::unbounded_channel();
        let (signal_killed, all_killed) = watch::channel(());

        let active_tasks = ActiveTasks {
            task_rx,
            tasks: Default::default(),
            signal_killed,
        };
        tokio::spawn(active_tasks.collect());

        Self {
            task_tx: parking_lot::RwLock::new(Some(task_tx)),
            task_counter: Default::default(),
            all_killed,
        }
    }

    fn spawn_task(&self, fut: impl Future<Output = ()> + Send + 'static) {
        // NOTE: acquiring the lock here is very cheap, as unless the killswitch
        // is activated, this one is always unlocked and this is just a
        // few atomic operations.
        let Some(task_tx) = self.task_tx.read().as_ref().cloned() else {
            return;
        };

        let id = self.task_counter.fetch_add(1, Ordering::SeqCst);
        let task_tx_weak = task_tx.downgrade();

        let handle = tokio::spawn(async move {
            // NOTE: we use a weak sender inside the spawned task - dropping
            // all strong senders activates the killswitch. In that case,
            // we don't need to remove anything from ActiveTasks anymore.
            let _guard = RemoveOnDrop { task_tx_weak, id };
            fut.await;
        });

        let _ = task_tx.send(ActiveTaskOp::Add { id, handle });
    }

    fn activate(&self) {
        // take()ing the sender here drops it and thereby triggers the killswitch.
        // Concurrent spawn_task calls may still hold strong senders, which
        // ensures those tasks are added to ActiveTasks before the killing
        // starts.
        assert!(
            self.task_tx.write().take().is_some(),
            "killswitch can't be used twice"
        );
    }

    fn killed(&self) -> impl Future<Output = ()> + Send + 'static {
        let mut signal = self.all_killed.clone();
        async move {
            let _ = signal.changed().await;
        }
    }
}

struct ActiveTasks {
    task_rx: mpsc::UnboundedReceiver<ActiveTaskOp>,
    tasks: HashMap<u64, JoinHandle<()>>,
    signal_killed: watch::Sender<()>,
}

impl ActiveTasks {
    async fn collect(mut self) {
        while let Some(op) = self.task_rx.recv().await {
            self.handle_task_op(op);
        }

        for task in self.tasks.into_values() {
            task.abort();
        }
        drop(self.signal_killed);
    }

    fn handle_task_op(&mut self, op: ActiveTaskOp) {
        match op {
            ActiveTaskOp::Add { id, handle } => {
                self.tasks.insert(id, handle);
            },
            ActiveTaskOp::Remove { id } => {
                self.tasks.remove(&id);
            },
        }
    }
}

/// The global [`TaskKillswitch`] exposed publicly from the crate.
static TASK_KILLSWITCH: LazyLock<TaskKillswitch> =
    LazyLock::new(TaskKillswitch::new);

/// Spawns a new asynchronous task and registers it in the crate's global
/// killswitch.
///
/// Under the hood, [`tokio::spawn`] schedules the actual execution.
#[inline]
pub fn spawn_with_killswitch(fut: impl Future<Output = ()> + Send + 'static) {
    TASK_KILLSWITCH.spawn_task(fut);
}

#[deprecated = "activate() was unnecessarily declared async. Use activate_now() instead."]
pub async fn activate() {
    TASK_KILLSWITCH.activate()
}

/// Triggers the killswitch, thereby scheduling all registered tasks to be
/// killed.
///
/// Note: tasks are not killed synchronously in this function. This means
/// `activate_now()` will return before all tasks have been stopped.
#[inline]
pub fn activate_now() {
    TASK_KILLSWITCH.activate();
}

/// Returns a future that resolves when all registered tasks have been killed,
/// after [`activate_now`] has been called.
///
/// Note: tokio does not kill a task until the next time it yields to the
/// runtime. This means some killed tasks may still be running by the time this
/// Future resolves.
#[inline]
pub fn killed_signal() -> impl Future<Output = ()> + Send + 'static {
    TASK_KILLSWITCH.killed()
}

#[cfg(test)]
mod tests {
    use super::*;
    use futures_util::future;
    use std::time::Duration;
    use tokio::sync::oneshot;

    struct TaskAbortSignal(Option<oneshot::Sender<()>>);

    impl TaskAbortSignal {
        fn new() -> (Self, oneshot::Receiver<()>) {
            let (tx, rx) = oneshot::channel();

            (Self(Some(tx)), rx)
        }
    }

    impl Drop for TaskAbortSignal {
        fn drop(&mut self) {
            let _ = self.0.take().unwrap().send(());
        }
    }

    fn start_test_tasks(
        killswitch: &TaskKillswitch,
    ) -> Vec<oneshot::Receiver<()>> {
        (0..1000)
            .map(|_| {
                let (tx, rx) = TaskAbortSignal::new();

                killswitch.spawn_task(async move {
                    tokio::time::sleep(tokio::time::Duration::from_secs(3600))
                        .await;
                    drop(tx);
                });

                rx
            })
            .collect()
    }

    #[tokio::test]
    async fn activate_killswitch_early() {
        let killswitch = TaskKillswitch::new();
        let abort_signals = start_test_tasks(&killswitch);

        killswitch.activate();

        tokio::time::timeout(
            Duration::from_secs(1),
            future::join_all(abort_signals),
        )
        .await
        .expect("tasks should be killed within given timeframe");
    }

    #[tokio::test]
    async fn activate_killswitch_with_delay() {
        let killswitch = TaskKillswitch::new();
        let abort_signals = start_test_tasks(&killswitch);
        let signal_handle = tokio::spawn(killswitch.killed());

        // NOTE: give tasks time to start executing.
        tokio::time::sleep(tokio::time::Duration::from_millis(200)).await;

        assert!(!signal_handle.is_finished());
        killswitch.activate();

        tokio::time::timeout(
            Duration::from_secs(1),
            future::join_all(abort_signals),
        )
        .await
        .expect("tasks should be killed within given timeframe");

        tokio::time::timeout(Duration::from_secs(1), signal_handle)
            .await
            .expect("killed() signal should have resolved")
            .expect("signal task should join successfully");
    }
}
