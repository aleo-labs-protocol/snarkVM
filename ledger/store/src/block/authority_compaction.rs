// Copyright (c) 2019-2026 Provable Inc.
// This file is part of the snarkVM library.

// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at:

// http://www.apache.org/licenses/LICENSE-2.0

// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! Compaction of the authority map after pruning, on a background thread.

use super::*;

use crate::helpers::Progress;
use std::{
    sync::{
        Weak,
        atomic::{AtomicBool, AtomicU32, Ordering},
    },
    time::{Duration, Instant},
};

/// The number of authorities pruned at insert time between compactions of the authority map. Unit
/// tests use a few blocks.
const AUTHORITY_COMPACTION_INTERVAL_BLOCKS: u32 = if cfg!(test) { 8 } else { 100_000 };

/// The least time between two starts of the compaction.
const AUTHORITY_COMPACTION_MIN_INTERVAL: Duration = Duration::from_secs(12 * 60 * 60);

/// Compacts the authority map slice by slice (see [`BlockStorage::authority_compaction_plan`]),
/// skipping the slices with nothing to reclaim. Stops between slices once `signal` says so or every
/// store sharing `state` is gone.
fn compact_authority_slices<N: Network, B: BlockStorage<N>>(
    storage: &B,
    signal: &Signal,
    state: &Weak<CompactionState>,
    #[cfg(test)] gate: Option<Arc<Gate>>,
) -> Result<()> {
    // The thread must not upgrade `state`: holding the last strong reference would run the state's
    // drop, and its join, on this thread.
    let stopping = || signal.stop.load(Ordering::SeqCst) || state.strong_count() == 0;
    let plan = storage.authority_compaction_plan()?;
    let (total, to_compact) = (plan.len(), plan.iter().filter(|&&compact| compact).count());
    if to_compact == 0 {
        debug!("Nothing to reclaim in the authority map ({total} slices)");
    } else {
        info!("Compacting {to_compact} of {total} authority slices; this can take a while");
    }
    let mut progress = Progress::new(to_compact);
    for (i, &compact) in plan.iter().enumerate() {
        #[cfg(test)]
        if let Some(gate) = &gate {
            gate.wait(stopping);
        }
        if stopping() {
            info!("Stopped the authority map compaction before slice {i} of {total}; the next start redoes it");
            return Ok(());
        }
        if compact {
            storage.compact_authority_slice(i, total)?;
            if let Some((elapsed, remaining)) = progress.advance() {
                info!(
                    "Compacted {} of {to_compact} marked slices in {elapsed:.0} s, about {remaining:.0} s left",
                    progress.done()
                );
            }
        }
    }
    if to_compact > 0 {
        info!(
            "Compacted {to_compact} of {total} authority slices, skipped {} with nothing to reclaim, in {:.1} s",
            total - to_compact,
            progress.elapsed_secs()
        );
    }
    Ok(())
}

/// What the compaction thread shares with the stores.
#[derive(Default)]
struct Signal {
    /// Set at shutdown, so no compaction starts and the running one stops between slices.
    stop: AtomicBool,
    /// Set when a compaction failed, so the next trigger starts one without waiting for the floor.
    failed: AtomicBool,
}

/// The state of the background authority map compaction, shared by the clones of a [`BlockStore`];
/// the compaction thread holds only its [`Signal`] and a weak reference.
#[derive(Default)]
pub(super) struct CompactionState {
    /// The number of authorities pruned since the authority map was compacted.
    pruned: AtomicU32,
    signal: Arc<Signal>,
    /// The last compaction started.
    last: Mutex<LastRun>,
}

/// The last compaction's start time and thread handle.
#[derive(Default)]
struct LastRun {
    started: Option<Instant>,
    thread: Option<std::thread::JoinHandle<()>>,
}

impl LastRun {
    fn running(&self) -> bool {
        self.thread.as_ref().is_some_and(|thread| !thread.is_finished())
    }
}

impl CompactionState {
    /// Stops the compaction, if one runs, and waits for it: the running slice finishes, then the
    /// thread is joined.
    fn stop_and_join(&self) {
        self.signal.stop.store(true, Ordering::SeqCst);
        let Some(thread) = self.last.lock().thread.take() else {
            return;
        };
        let running = !thread.is_finished();
        let timer = Instant::now();
        // A failed join means the thread panicked, and the process is aborting.
        let _ = thread.join();
        if running {
            info!("Waited {:.1} s for the authority map compaction to finish its slice", timer.elapsed().as_secs_f64());
            #[cfg(test)]
            AUTHORITY_COMPACTION_RUNNING_JOINS.with(|count| count.set(count.get() + 1));
        }
    }
}

/// The last store's drop of the state stops the thread, which never holds the state strongly.
impl Drop for CompactionState {
    fn drop(&mut self) {
        self.stop_and_join();
    }
}

impl<N: Network, B: BlockStorage<N>> BlockStore<N, B> {
    /// Counts the authority pruned by the insert of the block at `height`, if any, and starts a
    /// compaction every [`AUTHORITY_COMPACTION_INTERVAL_BLOCKS`] of them, subject to
    /// [`AUTHORITY_COMPACTION_MIN_INTERVAL`]. Counts by height, so after a rollback or a reopen with a
    /// larger window it overstates until the watermark catches up.
    pub(super) fn count_insert_time_pruning(&self, height: u32) {
        let Some(retention) = self.authority_retention else {
            return;
        };
        // The insert at the retention height expires genesis, which is never pruned.
        if height <= retention || !self.storage.compacts_authority_map() {
            return;
        }
        let compaction = &self.authority_compaction;
        if compaction.pruned.fetch_add(1, Ordering::SeqCst) + 1 >= AUTHORITY_COMPACTION_INTERVAL_BLOCKS
            && self.compact_authorities()
        {
            compaction.pruned.store(0, Ordering::SeqCst);
        }
    }

    /// Starts a compaction on a background thread if this store prunes, unless one runs, the floor
    /// applies, or the store is stopping; returns whether one started. A panic on the thread aborts
    /// the process.
    pub(super) fn compact_authorities(&self) -> bool {
        if self.authority_retention.is_none() || !self.storage.compacts_authority_map() {
            return false;
        }
        let compaction = &self.authority_compaction;
        let signal = compaction.signal.clone();
        // One lock covers the checks, the spawn and the handle, so a concurrent stop cannot miss
        // the thread.
        let mut last = compaction.last.lock();
        let floor = last.started.is_some_and(|started| started.elapsed() < AUTHORITY_COMPACTION_MIN_INTERVAL);
        if signal.stop.load(Ordering::SeqCst) || last.running() || (floor && !signal.failed.load(Ordering::SeqCst)) {
            return false;
        }
        #[cfg(test)]
        let gate = AUTHORITY_COMPACTION_GATE.with(|gate| gate.borrow().clone());
        let (storage, state) = (self.storage.clone(), Arc::downgrade(compaction));
        let compact = move || {
            let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                compact_authority_slices(
                    &storage,
                    &signal,
                    &state,
                    #[cfg(test)]
                    gate,
                )
            }));
            match result {
                Ok(Ok(())) => {}
                Ok(Err(error)) => {
                    error!("Failed to compact the authority map: {error}");
                    signal.failed.store(true, Ordering::SeqCst);
                }
                Err(_) => {
                    error!("The authority map compaction panicked");
                    std::process::abort();
                }
            }
        };
        compaction.signal.failed.store(false, Ordering::SeqCst);
        last.started = Some(Instant::now());
        #[cfg(test)]
        {
            AUTHORITY_COMPACTIONS.with(|count| count.set(count.get() + 1));
            if AUTHORITY_COMPACTION_GATE.with(|gate| gate.borrow().is_none()) {
                drop(last);
                compact();
                return true;
            }
        }
        match std::thread::Builder::new().name("authority-compaction".into()).spawn(compact) {
            Ok(thread) => {
                last.thread = Some(thread);
                true
            }
            Err(error) => {
                error!("Failed to start the authority map compaction: {error}");
                last.started = None;
                false
            }
        }
    }

    /// Stops the background authority map compaction; see `CompactionState::stop_and_join`.
    pub fn stop_background_work(&self) {
        self.authority_compaction.stop_and_join();
    }
}

/// A test's control over a compaction thread: the thread waits before each slice until the test
/// has released more slices than have passed, or until it is stopping.
#[cfg(test)]
#[derive(Default)]
struct Gate {
    released: std::sync::atomic::AtomicUsize,
    passed: std::sync::atomic::AtomicUsize,
}

#[cfg(test)]
impl Gate {
    #[cfg(feature = "rocks")]
    fn release(&self, slices: usize) {
        self.released.fetch_add(slices, Ordering::SeqCst);
    }

    fn passed(&self) -> usize {
        self.passed.load(Ordering::SeqCst)
    }

    /// Waits for a released slice, or for `stopping`.
    fn wait(&self, stopping: impl Fn() -> bool) {
        while self.released.load(Ordering::SeqCst) <= self.passed() {
            if stopping() {
                return;
            }
            std::thread::sleep(Duration::from_millis(1));
        }
        self.passed.fetch_add(1, Ordering::SeqCst);
    }
}

#[cfg(test)]
thread_local! {
    /// The number of authority map compactions started on this thread.
    static AUTHORITY_COMPACTIONS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
    /// How this thread's stores compact: inline (`None`), or on a thread driven by the gate.
    static AUTHORITY_COMPACTION_GATE: std::cell::RefCell<Option<Arc<Gate>>> = const { std::cell::RefCell::new(None) };
    /// The number of running compaction threads this thread has stopped and joined.
    static AUTHORITY_COMPACTION_RUNNING_JOINS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        block::{
            test_chain::sample_block_chain,
            tests::{TEST_RETENTION, open_pruning},
        },
        helpers::memory::BlockMemory,
    };

    type CurrentNetwork = console::network::MainnetV0;

    fn compactions() -> usize {
        AUTHORITY_COMPACTIONS.with(|count| count.get())
    }

    /// Inserts `block`, through the deferred block tree path if `deferred`.
    fn insert<B: BlockStorage<CurrentNetwork>>(
        store: &BlockStore<CurrentNetwork, B>,
        block: &Block<CurrentNetwork>,
        deferred: bool,
    ) {
        if deferred {
            store.pause_atomic_writes().unwrap();
            store.insert_deferring_block_tree(block).unwrap();
            store.commit_paused_writes_and_publish_block_tree(block).unwrap();
        } else {
            store.insert(block).unwrap();
        }
    }

    /// Ensures pruning in-memory storage, which has nothing to compact, starts no compaction and
    /// counts no inserts.
    #[test]
    fn test_memory_storage_compacts_nothing() {
        let store = open_pruning::<BlockMemory<_>>(StorageMode::new_test(None));
        assert!(!store.compact_authorities());
        let rng = &mut TestRng::default();
        let before = compactions();
        for block in &sample_block_chain(TEST_RETENTION + 3, rng) {
            insert(&store, block, false);
        }
        assert_eq!(compactions(), before);
        assert_eq!(store.authority_compaction.pruned.load(Ordering::SeqCst), 0);
    }

    #[cfg(feature = "rocks")]
    mod rocks {
        use super::*;
        use crate::helpers::rocksdb::BlockDB;

        type Store = BlockStore<CurrentNetwork, BlockDB<CurrentNetwork>>;

        /// Opens a store on `storage_mode` that prunes with [`TEST_RETENTION`] if `prunes`.
        fn open_with(storage_mode: StorageMode, prunes: bool) -> Store {
            BlockStore::open_with_authority_retention(storage_mode, prunes.then_some(TEST_RETENTION)).unwrap()
        }

        /// Opens an empty store that prunes with [`TEST_RETENTION`] if `prunes`.
        fn open(prunes: bool) -> Store {
            open_with(StorageMode::new_test(Some(Arc::new(tempfile::tempdir().unwrap()))), prunes)
        }

        /// Opens, as [`open`] does, a store whose storage has pruned before.
        fn open_pruned(prunes: bool) -> Store {
            let storage_mode = StorageMode::new_test(Some(Arc::new(tempfile::tempdir().unwrap())));
            let storage = BlockDB::<CurrentNetwork>::open(storage_mode.clone()).unwrap();
            atomic_batch_scope!(storage, { set_authority_pruned_below(&storage, 2) }).unwrap();
            open_with(storage_mode, prunes)
        }

        fn running_joins() -> usize {
            AUTHORITY_COMPACTION_RUNNING_JOINS.with(|count| count.get())
        }

        /// Forgets the last start, so the floor does not apply to the next trigger.
        fn clear_floor(store: &Store) {
            store.authority_compaction.last.lock().started = None;
        }

        /// Whether the store's compaction thread is running.
        fn thread_running(store: &Store) -> bool {
            store.authority_compaction.last.lock().running()
        }

        /// Runs `open` with any compaction it starts on a thread the returned gate controls; the
        /// thread waits before its first slice.
        fn with_gate(open: impl FnOnce() -> Store) -> (Store, Arc<Gate>) {
            let gate = Arc::new(Gate::default());
            AUTHORITY_COMPACTION_GATE.with(|slot| *slot.borrow_mut() = Some(gate.clone()));
            let store = open();
            AUTHORITY_COMPACTION_GATE.with(|slot| *slot.borrow_mut() = None);
            (store, gate)
        }

        /// Opens a pruning store that has pruned before, with its open-time compaction on a gated
        /// thread.
        fn open_with_gate() -> (Store, Arc<Gate>) {
            let (store, gate) = with_gate(|| open_pruned(true));
            assert!(thread_running(&store));
            (store, gate)
        }

        /// Waits until `gate` has passed `slices`.
        fn wait_passed(gate: &Gate, slices: usize) {
            while gate.passed() < slices {
                std::thread::sleep(Duration::from_millis(1));
            }
        }

        /// Ensures the real thread path starts at open, stops on request, and is not restarted.
        #[test]
        fn test_authority_compaction_thread_stops() {
            let (store, gate) = open_with_gate();
            let before = running_joins();
            store.stop_background_work();
            assert_eq!(running_joins(), before + 1);
            assert_eq!(gate.passed(), 0);
            assert!(store.authority_compaction.last.lock().thread.is_none());
            clear_floor(&store);
            assert!(!store.compact_authorities());
        }

        /// Ensures dropping the last store, while the thread waits between slices, stops and joins
        /// the thread on the dropping thread.
        #[test]
        fn test_dropping_the_store_stops_the_thread() {
            let (store, gate) = open_with_gate();
            gate.release(1);
            wait_passed(&gate, 1);
            let clone = store.clone();
            let before = running_joins();
            // A clone remains, so nothing stops yet.
            drop(store);
            assert_eq!(running_joins(), before);
            assert!(thread_running(&clone));
            drop(clone);
            assert_eq!(running_joins(), before + 1);
            assert_eq!(gate.passed(), 1);
        }

        /// Ensures a compaction stops at the next slice once its signal says so or its state is
        /// gone.
        #[test]
        fn test_authority_compaction_stops_without_a_store() {
            let store = open(true);
            let state = Arc::new(CompactionState::default());
            let gate = Arc::new(Gate::default());
            let worker = {
                let (storage, signal, weak, gate) =
                    (store.storage.clone(), state.signal.clone(), Arc::downgrade(&state), gate.clone());
                std::thread::spawn(move || compact_authority_slices(&storage, &signal, &weak, Some(gate)))
            };
            gate.release(2);
            wait_passed(&gate, 2);
            state.signal.stop.store(true, Ordering::SeqCst);
            worker.join().unwrap().unwrap();
            assert_eq!(gate.passed(), 2);

            // Every store gone: the run ends before its first slice.
            let weak = Arc::downgrade(&state);
            drop(state);
            let gate = Arc::new(Gate::default());
            compact_authority_slices(&store.storage, &Signal::default(), &weak, Some(gate.clone())).unwrap();
            assert_eq!(gate.passed(), 0);
        }

        /// Ensures an open starts one authority compaction thread, and the floor, only if the store
        /// prunes and has pruned before.
        #[test]
        fn test_open_starts_authority_compaction() {
            for (prunes, pruned_before) in [(true, true), (true, false), (false, true)] {
                let starts = prunes && pruned_before;
                let before = compactions();
                let (store, _gate) = with_gate(|| if pruned_before { open_pruned(prunes) } else { open(prunes) });
                assert_eq!(compactions(), before + usize::from(starts), "{prunes} {pruned_before}");
                assert_eq!(thread_running(&store), starts);
                assert_eq!(store.authority_compaction.last.lock().started.is_some(), starts);
                let joins = running_joins();
                store.stop_background_work();
                assert_eq!(running_joins(), joins + usize::from(starts));
            }
        }

        /// Ensures a secondary instance opened with a retention window does not prune, so it
        /// neither counts inserts nor compacts. The primary and the secondary each run in a child
        /// process, as a process holds only one database outside the test storage mode.
        #[test]
        fn test_secondary_does_not_compact() {
            const ROLE: &str = "SNARKVM_COMPACTION_TEST_ROLE";
            const PRIMARY: &str = "SNARKVM_COMPACTION_TEST_PRIMARY";
            const SECONDARY: &str = "SNARKVM_COMPACTION_TEST_SECONDARY";
            let path = |var| std::path::PathBuf::from(std::env::var(var).unwrap());
            match std::env::var(ROLE).as_deref() {
                Ok("primary") => {
                    let primary = open_with(StorageMode::Custom(path(PRIMARY), None), true);
                    for block in &sample_block_chain(TEST_RETENTION + 2, &mut TestRng::default()) {
                        primary.insert(block).unwrap();
                    }
                    assert_eq!(primary.authority_pruned_below().unwrap(), Some(2));
                }
                Ok("secondary") => {
                    let storage_mode = StorageMode::Custom(path(PRIMARY), Some(path(SECONDARY)));
                    let (secondary, _gate) = with_gate(|| open_with(storage_mode, true));
                    assert_eq!(secondary.authority_retention, None);
                    assert_eq!(secondary.authority_pruned_below().unwrap(), Some(2));
                    assert_eq!(compactions(), 0);
                    assert!(!thread_running(&secondary));
                }
                _ => {
                    let (primary_dir, secondary_dir) = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
                    for role in ["primary", "secondary"] {
                        let status = std::process::Command::new(std::env::current_exe().unwrap())
                            .args([
                                "block::authority_compaction::tests::rocks::test_secondary_does_not_compact",
                                "--exact",
                            ])
                            .env(ROLE, role)
                            .env(PRIMARY, primary_dir.path())
                            .env(SECONDARY, secondary_dir.path())
                            .status()
                            .unwrap();
                        assert!(status.success(), "The {role} instance failed");
                    }
                }
            }
        }

        /// Ensures a deferred insert whose batch is discarded counts nothing.
        #[test]
        fn test_discarded_deferred_insert_is_not_counted() {
            let store = open(true);
            let blocks = sample_block_chain(TEST_RETENTION + 2, &mut TestRng::default());
            for block in &blocks[..=TEST_RETENTION as usize] {
                store.insert(block).unwrap();
            }
            let pruned = || store.authority_compaction.pruned.load(Ordering::SeqCst);
            assert_eq!(pruned(), 0);

            // The VM's path for a block that fails to finalize.
            let block = &blocks[TEST_RETENTION as usize + 1];
            store.pause_atomic_writes().unwrap();
            store.insert_deferring_block_tree(block).unwrap();
            store.abort_atomic();
            store.discard_prepared_block_tree();
            store.unpause_atomic_writes::<true>().unwrap();
            assert_eq!(pruned(), 0);

            insert(&store, block, true);
            assert_eq!(pruned(), 1);
        }

        /// Checks that insert-time pruning on a store opened empty compacts the authority map once
        /// per `AUTHORITY_COMPACTION_INTERVAL_BLOCKS` pruned authorities if the store prunes, without
        /// waiting for the floor, and that a store that does not prune never compacts.
        fn check_insert_time_pruning_compacts_after_interval(prunes: bool, deferred: bool) {
            let store = open(prunes);
            let rng = &mut TestRng::default();
            let blocks = sample_block_chain(TEST_RETENTION + AUTHORITY_COMPACTION_INTERVAL_BLOCKS + 2, rng);
            let before = compactions();
            // The insert at the retention height prunes nothing; the interval of inserts after it ends here.
            let trigger = TEST_RETENTION + AUTHORITY_COMPACTION_INTERVAL_BLOCKS;
            for block in &blocks {
                insert(&store, block, deferred);
                let expected = before + usize::from(prunes && block.height() >= trigger);
                assert_eq!(compactions(), expected, "at block {}", block.height());
            }
            if !prunes {
                assert_eq!(store.authority_compaction.pruned.load(Ordering::SeqCst), 0);
            }
        }

        /// Ensures insert-time pruning compacts the authority map after the interval, through both
        /// insert paths, and only if the store prunes.
        #[test]
        fn test_insert_time_pruning_compacts_after_interval() {
            for prunes in [true, false] {
                check_insert_time_pruning_compacts_after_interval(prunes, false);
                check_insert_time_pruning_compacts_after_interval(prunes, true);
            }
        }

        /// Checks that a trigger at the interval fires nothing and keeps its count while `block`
        /// holds, and fires on the next insert once `release` lifts it.
        fn check_trigger_waits(block: impl FnOnce(&Store), release: impl FnOnce(&Store)) {
            let store = open(true);
            let rng = &mut TestRng::default();
            let blocks = sample_block_chain(TEST_RETENTION + AUTHORITY_COMPACTION_INTERVAL_BLOCKS + 2, rng);
            let trigger = TEST_RETENTION + AUTHORITY_COMPACTION_INTERVAL_BLOCKS;
            block(&store);

            let before = compactions();
            for block in blocks.iter().filter(|block| block.height() <= trigger) {
                store.insert(block).unwrap();
            }
            assert_eq!(compactions(), before);
            assert_eq!(store.authority_compaction.pruned.load(Ordering::SeqCst), AUTHORITY_COMPACTION_INTERVAL_BLOCKS);

            release(&store);
            store.insert(&blocks[trigger as usize + 1]).unwrap();
            assert_eq!(compactions(), before + 1);
            assert_eq!(store.authority_compaction.pruned.load(Ordering::SeqCst), 0);
        }

        /// Ensures a trigger inside the floor after the last start waits for the floor, unless the
        /// last compaction failed.
        #[test]
        fn test_trigger_waits_for_the_floor() {
            check_trigger_waits(
                |store| store.authority_compaction.last.lock().started = Some(Instant::now()),
                |store| {
                    store.authority_compaction.last.lock().started =
                        Instant::now().checked_sub(AUTHORITY_COMPACTION_MIN_INTERVAL)
                },
            );
            check_trigger_waits(
                |store| store.authority_compaction.last.lock().started = Some(Instant::now()),
                |store| store.authority_compaction.signal.failed.store(true, Ordering::SeqCst),
            );
        }

        /// Ensures a trigger while a compaction runs waits for it to end.
        #[test]
        fn test_trigger_waits_for_the_running_compaction() {
            let release = Arc::new(AtomicBool::new(false));
            let released = release.clone();
            check_trigger_waits(
                // A compaction that runs until released.
                move |store| {
                    store.authority_compaction.last.lock().thread = Some(std::thread::spawn(move || {
                        while !released.load(Ordering::SeqCst) {
                            std::thread::sleep(Duration::from_millis(1));
                        }
                    }));
                },
                move |store| {
                    release.store(true, Ordering::SeqCst);
                    while thread_running(store) {
                        std::thread::sleep(Duration::from_millis(1));
                    }
                },
            );
        }
    }
}
