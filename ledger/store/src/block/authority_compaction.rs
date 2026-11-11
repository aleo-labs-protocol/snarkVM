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
/// skipping the slices with nothing to reclaim. Stops between slices once `compaction` is stopping
/// or dropped.
fn compact_authority_slices<N: Network, B: BlockStorage<N>>(
    storage: &B,
    compaction: &Weak<CompactionState>,
    #[cfg(test)] delay: Option<Duration>,
) -> Result<()> {
    let plan = storage.authority_compaction_plan()?;
    let (total, to_compact) = (plan.len(), plan.iter().filter(|&&compact| compact).count());
    if to_compact == 0 {
        debug!("Nothing to reclaim in the authority map ({total} slices)");
    } else {
        info!("Compacting {to_compact} of {total} authority slices; this can take a while");
    }
    let mut progress = Progress::new(to_compact);
    for (i, &compact) in plan.iter().enumerate() {
        if compaction.upgrade().is_none_or(|compaction| compaction.stop.load(Ordering::SeqCst)) {
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
        #[cfg(test)]
        if let Some(delay) = delay {
            std::thread::sleep(delay);
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

/// The state of the background authority map compaction, shared by the clones of a [`BlockStore`]
/// and held weakly by the compaction thread.
#[derive(Default)]
pub(super) struct CompactionState {
    /// The number of authorities pruned since the authority map was compacted.
    pruned: AtomicU32,
    /// Set at shutdown, so no compaction starts and the running one stops between slices.
    stop: AtomicBool,
    /// The last compaction started.
    last: Mutex<LastRun>,
}

/// The last compaction's start time and thread handle.
#[derive(Default)]
struct LastRun {
    started: Option<Instant>,
    thread: Option<std::thread::JoinHandle<()>>,
}

impl CompactionState {
    /// Stops the compaction, if one runs, and waits for it: the running slice finishes, then the
    /// thread is joined.
    fn stop_and_join(&self) {
        self.stop.store(true, Ordering::SeqCst);
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

/// The last store's drop of the state stops the thread, which holds the state only weakly.
impl Drop for CompactionState {
    fn drop(&mut self) {
        self.stop_and_join();
    }
}

/// A [`BlockStore`]'s share of its [`CompactionState`].
#[derive(Clone, Default)]
pub(super) struct AuthorityCompaction(Arc<CompactionState>);

impl Deref for AuthorityCompaction {
    type Target = CompactionState;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<N: Network, B: BlockStorage<N>> BlockStore<N, B> {
    /// Counts the authority pruned by the insert of the block at `height`, if any, and starts a
    /// compaction every [`AUTHORITY_COMPACTION_INTERVAL_BLOCKS`] of them, subject to
    /// [`AUTHORITY_COMPACTION_MIN_INTERVAL`]. Counts by height, so after a rollback it overstates
    /// until the watermark catches up.
    pub(super) fn count_insert_time_pruning(&self, height: u32) {
        // The insert at the retention height expires genesis, which is never pruned.
        if height <= AUTHORITY_RETENTION_BLOCKS || !self.storage.compacts_authority_map() {
            return;
        }
        let compaction = &self.authority_compaction;
        if compaction.pruned.fetch_add(1, Ordering::SeqCst) + 1 >= AUTHORITY_COMPACTION_INTERVAL_BLOCKS
            && self.compact_authorities()
        {
            compaction.pruned.store(0, Ordering::SeqCst);
        }
    }

    /// Starts a compaction on a background thread unless one runs, the floor applies, or the store
    /// is stopping; returns whether one started. A panic on the thread aborts the process.
    pub(super) fn compact_authorities(&self) -> bool {
        if !self.storage.compacts_authority_map() {
            return false;
        }
        let compaction = &self.authority_compaction;
        // One lock covers the checks, the spawn and the handle, so a concurrent stop cannot miss
        // the thread.
        let mut last = compaction.last.lock();
        if compaction.stop.load(Ordering::SeqCst)
            || last.thread.as_ref().is_some_and(|thread| !thread.is_finished())
            || last.started.is_some_and(|started| started.elapsed() < AUTHORITY_COMPACTION_MIN_INTERVAL)
        {
            return false;
        }
        #[cfg(test)]
        let delay = AUTHORITY_COMPACTION_THREAD.with(|thread| thread.get());
        let (storage, weak) = (self.storage.clone(), Arc::downgrade(&compaction.0));
        let compact = move || {
            let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                compact_authority_slices(
                    &storage,
                    &weak,
                    #[cfg(test)]
                    delay,
                )
            }));
            match result {
                Ok(Ok(())) => {}
                Ok(Err(error)) => error!("Failed to compact the authority map: {error}"),
                Err(_) => {
                    error!("The authority map compaction panicked");
                    std::process::abort();
                }
            }
        };
        last.started = Some(Instant::now());
        #[cfg(test)]
        {
            AUTHORITY_COMPACTIONS.with(|count| count.set(count.get() + 1));
            if delay.is_none() {
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

#[cfg(test)]
thread_local! {
    /// The number of authority map compactions started on this thread.
    static AUTHORITY_COMPACTIONS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
    /// How this thread's stores compact: inline (`None`), or on a thread that sleeps this long per
    /// slice.
    static AUTHORITY_COMPACTION_THREAD: std::cell::Cell<Option<Duration>> = const { std::cell::Cell::new(None) };
    /// The number of running compaction threads this thread has stopped and joined.
    static AUTHORITY_COMPACTION_RUNNING_JOINS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{block::test_chain::sample_block_chain, helpers::memory::BlockMemory};

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

    /// Ensures in-memory storage, which has nothing to compact, starts no compaction and counts no
    /// inserts.
    #[test]
    fn test_memory_storage_compacts_nothing() {
        let store = BlockStore::<CurrentNetwork, BlockMemory<_>>::open(StorageMode::new_test(None)).unwrap();
        assert!(!store.compact_authorities());
        let rng = &mut TestRng::default();
        let before = compactions();
        for block in &sample_block_chain(AUTHORITY_RETENTION_BLOCKS + 3, rng) {
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

        /// How long a slice of a test thread takes: long enough for a test to act before it ends.
        const SLOW_SLICE: Duration = Duration::from_millis(100);

        fn open() -> Store {
            let temp_dir = Arc::new(tempfile::tempdir().unwrap());
            BlockStore::open(StorageMode::new_test(Some(temp_dir))).unwrap()
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
            store.authority_compaction.last.lock().thread.as_ref().is_some_and(|thread| !thread.is_finished())
        }

        /// Opens a store whose compaction runs on a thread that takes a while per slice.
        fn open_with_slow_thread() -> Store {
            AUTHORITY_COMPACTION_THREAD.with(|thread| thread.set(Some(SLOW_SLICE)));
            let store = open();
            AUTHORITY_COMPACTION_THREAD.with(|thread| thread.set(None));
            assert!(thread_running(&store));
            store
        }

        /// Ensures the real thread path starts at open, stops on request, and is not restarted.
        #[test]
        fn test_authority_compaction_thread_stops() {
            let store = open_with_slow_thread();
            let before = running_joins();
            store.stop_background_work();
            assert_eq!(running_joins(), before + 1);
            assert!(store.authority_compaction.last.lock().thread.is_none());
            clear_floor(&store);
            assert!(!store.compact_authorities());
            store.stop_background_work();
        }

        /// Ensures dropping the last store stops and joins a running compaction thread.
        #[test]
        fn test_dropping_the_store_stops_the_thread() {
            let store = open_with_slow_thread();
            let clone = store.clone();
            let before = running_joins();
            // A clone remains, so nothing stops yet.
            drop(store);
            assert_eq!(running_joins(), before);
            assert!(thread_running(&clone));
            drop(clone);
            assert_eq!(running_joins(), before + 1);
        }

        /// Ensures a compaction stops at the next slice once its state is stopping or gone.
        #[test]
        fn test_authority_compaction_stops_without_a_store() {
            let store = open();
            let slices = u32::try_from(store.storage.authority_compaction_plan().unwrap().len()).unwrap();
            let state = Arc::new(CompactionState::default());
            let weak = Arc::downgrade(&state);

            // A live state: every slice is passed.
            let timer = Instant::now();
            compact_authority_slices(&store.storage, &weak, Some(SLOW_SLICE)).unwrap();
            assert!(timer.elapsed() >= SLOW_SLICE * slices);

            // A stopping state, then a dropped one: the loop ends before its first slice.
            state.stop.store(true, Ordering::SeqCst);
            let timer = Instant::now();
            compact_authority_slices(&store.storage, &weak, Some(SLOW_SLICE)).unwrap();
            assert!(timer.elapsed() < SLOW_SLICE * slices);

            drop(state);
            let timer = Instant::now();
            compact_authority_slices(&store.storage, &weak, Some(SLOW_SLICE)).unwrap();
            assert!(timer.elapsed() < SLOW_SLICE * slices);
        }

        /// Ensures an open starts exactly one authority compaction.
        #[test]
        fn test_open_starts_authority_compaction() {
            let before = compactions();
            let _store = open();
            assert_eq!(compactions(), before + 1);
        }

        /// Checks that insert-time pruning compacts the authority map once per
        /// `AUTHORITY_COMPACTION_INTERVAL_BLOCKS` pruned authorities.
        fn check_insert_time_pruning_compacts_after_interval(deferred: bool) {
            let store = open();
            let rng = &mut TestRng::default();
            let blocks = sample_block_chain(AUTHORITY_RETENTION_BLOCKS + AUTHORITY_COMPACTION_INTERVAL_BLOCKS + 2, rng);
            clear_floor(&store);
            let before = compactions();
            // The insert at the retention height prunes nothing; the interval of inserts after it ends here.
            let trigger = AUTHORITY_RETENTION_BLOCKS + AUTHORITY_COMPACTION_INTERVAL_BLOCKS;
            for block in &blocks {
                insert(&store, block, deferred);
                let expected = before + usize::from(block.height() >= trigger);
                assert_eq!(compactions(), expected, "at block {}", block.height());
            }
        }

        /// Ensures insert-time pruning compacts the authority map after the interval, through both
        /// insert paths.
        #[test]
        fn test_insert_time_pruning_compacts_after_interval() {
            check_insert_time_pruning_compacts_after_interval(false);
            check_insert_time_pruning_compacts_after_interval(true);
        }

        /// Checks that a trigger at the interval fires nothing and keeps its count while `block`
        /// holds, and fires on the next insert once `release` lifts it.
        fn check_trigger_waits(block: impl FnOnce(&Store), release: impl FnOnce(&Store)) {
            let store = open();
            let rng = &mut TestRng::default();
            let blocks = sample_block_chain(AUTHORITY_RETENTION_BLOCKS + AUTHORITY_COMPACTION_INTERVAL_BLOCKS + 2, rng);
            let trigger = AUTHORITY_RETENTION_BLOCKS + AUTHORITY_COMPACTION_INTERVAL_BLOCKS;
            clear_floor(&store);
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

        /// Ensures a trigger inside the floor after the last start waits for the floor.
        #[test]
        fn test_trigger_waits_for_the_floor() {
            check_trigger_waits(
                |store| store.authority_compaction.last.lock().started = Some(Instant::now()),
                |store| {
                    store.authority_compaction.last.lock().started =
                        Instant::now().checked_sub(AUTHORITY_COMPACTION_MIN_INTERVAL)
                },
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
