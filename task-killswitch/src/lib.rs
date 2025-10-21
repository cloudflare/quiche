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

use dashmap::DashMap;
use parking_lot::Mutex;
use tokio::sync::watch;
use tokio::task;
use tokio::task::AbortHandle;

use std::future::Future;
use std::sync::atomic::AtomicBool;
use std::sync::atomic::Ordering;
use std::sync::LazyLock;

/// Drop guard for task removal. If a task panics, this makes sure
/// it is removed from [`ActiveTasks`] properly.
struct RemoveOnDrop {
    id: task::Id,
    storage: &'static ActiveTasks,
}
impl Drop for RemoveOnDrop {
    fn drop(&mut self) {
        self.storage.remove_task(self.id);
    }
}

/// A task killswitch that allows aborting all the tasks spawned with it at
/// once. The implementation strives to minimize in-band locking. Spawning a
/// future requires a single sharded lock from an internal [`DashMap`].
/// Conflicts are expected to be very rare (dashmap defaults to `4 * nproc`
/// shards, while each thread can only spawn one task at a time.)
struct TaskKillswitch {
    // Invariant: If `activated` is true, we don't add new tasks anymore.
    activated: AtomicBool,
    storage: &'static ActiveTasks,

    /// Watcher that is triggered after all kill signals have been sent (by
    /// dropping `signal_killed`.) Currently-running tasks are killed after
    /// their next yield, which may be after this triggers.
    all_killed: watch::Receiver<()>,
    // NOTE: All we want here is to take ownership of `signal_killed` when
    // activating the killswitch. That code path only runs once per instance, but
    // requires interior mutability. Using `Mutex` is easier than bothering with
    // an `UnsafeCell`. The mutex is guaranteed to be unlocked.
    signal_killed: Mutex<Option<watch::Sender<()>>>,
}

impl TaskKillswitch {
    fn new(storage: &'static ActiveTasks) -> Self {
        let (signal_killed, all_killed) = watch::channel(());
        let signal_killed = Mutex::new(Some(signal_killed));

        Self {
            activated: AtomicBool::new(false),
            storage,
            signal_killed,
            all_killed,
        }
    }

    /// Creates a killswitch by allocating and leaking the task storage.
    ///
    /// **NOTE:** This is intended for use in `static`s and tests. It should not
    /// be exposed publicly!
    fn with_leaked_storage() -> Self {
        let storage = Box::leak(Box::new(ActiveTasks::default()));
        Self::new(storage)
    }

    fn was_activated(&self) -> bool {
        // All synchronization is done using locks,
        // so we can use relaxed for our atomics.
        self.activated.load(Ordering::Relaxed)
    }

    fn spawn_task(&self, fut: impl Future<Output = ()> + Send + 'static) {
        if self.was_activated() {
            return;
        }

        let storage = self.storage;
        let handle = tokio::spawn(async move {
            let id = task::id();
            let _guard = RemoveOnDrop { id, storage };
            fut.await;
        })
        .abort_handle();

        let res = self.storage.add_task_if(handle, || !self.was_activated());
        if let Err(handle) = res {
            // Killswitch was activated by the time we got a lock on the map shard
            handle.abort();
        }
    }

    fn activate(&self) {
        // We check `activated` after locking the map shard and before inserting
        // an element. This ensures in-progress spawns either complete before
        // `tasks.kill_all()` obtains the lock for that shard, or they abort
        // afterwards.
        assert!(
            !self.activated.swap(true, Ordering::Relaxed),
            "killswitch can't be used twice"
        );

        let tasks = self.storage;
        let signal_killed = self.signal_killed.lock().take();
        std::thread::spawn(move || {
            tasks.kill_all();
            drop(signal_killed);
        });
    }

    fn killed(&self) -> impl Future<Output = ()> + Send + 'static {
        let mut signal = self.all_killed.clone();
        async move {
            let _ = signal.changed().await;
        }
    }
}

enum TaskEntry {
    /// Task was added and not yet removed.
    Handle(AbortHandle),
    /// Task was removed before it was added. This can happen if a spawned
    /// future completes before the spawning thread can add it to the map.
    Tombstone,
}

#[derive(Default)]
struct ActiveTasks {
    tasks: DashMap<task::Id, TaskEntry>,
}

impl ActiveTasks {
    fn kill_all(&self) {
        self.tasks.retain(|_, entry| {
            if let TaskEntry::Handle(task) = entry {
                task.abort();
            }
            false // remove all elements
        });
    }

    fn add_task_if(
        &self, handle: AbortHandle, cond: impl FnOnce() -> bool,
    ) -> Result<(), AbortHandle> {
        use dashmap::Entry::*;
        let id = handle.id();

        match self.tasks.entry(id) {
            Vacant(e) => {
                if !cond() {
                    return Err(handle);
                }
                e.insert(TaskEntry::Handle(handle));
            },
            Occupied(e) if matches!(e.get(), TaskEntry::Tombstone) => {
                // Task was removed before it was added. Clear the map entry and
                // drop the handle.
                e.remove();
            },
            Occupied(_) => panic!("tokio task ID already in use: {id}"),
        }

        Ok(())
    }

    fn remove_task(&self, id: task::Id) {
        use dashmap::Entry::*;
        match self.tasks.entry(id) {
            Vacant(e) => {
                // Task was not added yet, set a tombstone instead.
                e.insert(TaskEntry::Tombstone);
            },
            Occupied(e) if matches!(e.get(), TaskEntry::Tombstone) => {},
            Occupied(e) => {
                e.remove();
            },
        }
    }
}

/// The global [`TaskKillswitch`] exposed publicly from the crate.
static TASK_KILLSWITCH: LazyLock<TaskKillswitch> =
    LazyLock::new(TaskKillswitch::with_leaked_storage);

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
        let killswitch = TaskKillswitch::with_leaked_storage();
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
        let killswitch = TaskKillswitch::with_leaked_storage();
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
