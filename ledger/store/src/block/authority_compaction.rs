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

/// The least time between two starts of the compaction. Unit tests use a few milliseconds.
const AUTHORITY_COMPACTION_MIN_INTERVAL: Duration =
    if cfg!(test) { Duration::from_millis(20) } else { Duration::from_secs(12 * 60 * 60) };

/// Compacts the authority map slice by slice (see [`BlockStorage::authority_compaction_plan`]),
/// skipping the slices with nothing to reclaim, and returns the number of slices passed. Stops
/// between slices once `compaction` is stopping or dropped.
fn compact_authority_slices<N: Network, B: BlockStorage<N>>(
    storage: &B,
    compaction: &Weak<AuthorityCompaction>,
) -> Result<usize> {
    let plan = storage.authority_compaction_plan()?;
    let total = plan.len();
    info!("Compacting the authority map in {total} slices; this can take a while");
    let mut progress = Progress::new(total);
    let mut skipped = 0;
    for (i, &compact) in plan.iter().enumerate() {
        if compaction.upgrade().is_none_or(|compaction| compaction.stop.load(Ordering::SeqCst)) {
            info!("Stopped the authority map compaction before slice {i} of {total}; the next start redoes it");
            return Ok(i);
        }
        if compact {
            storage.compact_authority_slice(i, total)?;
        } else {
            skipped += 1;
        }
        #[cfg(test)]
        {
            std::thread::sleep(Duration::from_millis(SLICE_DELAY_MS.load(Ordering::SeqCst)));
            AUTHORITY_SLICES_DONE.with(|count| {
                count.set(count.get() + 1);
                if AUTHORITY_COMPACTION_STOP_AFTER.with(|n| n.get()) == Some(count.get())
                    && let Some(compaction) = compaction.upgrade()
                {
                    compaction.stop.store(true, Ordering::SeqCst);
                }
            });
        }
        if let Some((elapsed, remaining)) = progress.advance() {
            info!(
                "Compacted {} of {total} authority slices in {elapsed:.0} s, about {remaining:.0} s left",
                progress.done()
            );
        }
    }
    info!(
        "Compacted {} of {total} authority slices, skipped {skipped} with nothing to reclaim, in {:.1} s",
        total - skipped,
        progress.elapsed_secs()
    );
    Ok(total)
}

/// The state of the background authority map compaction, shared by the clones of a [`BlockStore`].
pub(super) struct AuthorityCompaction {
    /// Whether the storage compacts at all.
    compacts: bool,
    /// The number of authorities pruned since the authority map was compacted.
    pruned: AtomicU32,
    /// Set at shutdown, so no compaction starts and the running one stops between slices.
    stop: AtomicBool,
    /// The last compaction started.
    last: Mutex<LastRun>,
}

/// When the last compaction started and its thread, running while not finished.
#[derive(Default)]
struct LastRun {
    started: Option<Instant>,
    thread: Option<std::thread::JoinHandle<()>>,
}

impl AuthorityCompaction {
    pub(super) fn new(compacts: bool) -> Self {
        Self { compacts, pruned: Default::default(), stop: Default::default(), last: Default::default() }
    }
}

impl<N: Network, B: BlockStorage<N>> BlockStore<N, B> {
    /// Counts the authority pruned by the insert of the block at `height`, if any, and starts a
    /// compaction every [`AUTHORITY_COMPACTION_INTERVAL_BLOCKS`] of them, subject to
    /// [`AUTHORITY_COMPACTION_MIN_INTERVAL`]. Counts by height, so after a rollback it overstates
    /// until the watermark catches up.
    pub(super) fn count_insert_time_pruning(&self, height: u32) {
        let compaction = &self.authority_compaction;
        if height < AUTHORITY_RETENTION_BLOCKS || !compaction.compacts || compaction.stop.load(Ordering::SeqCst) {
            return;
        }
        if compaction.pruned.fetch_add(1, Ordering::SeqCst) + 1 >= AUTHORITY_COMPACTION_INTERVAL_BLOCKS
            && self.compact_authorities()
        {
            compaction.pruned.store(0, Ordering::SeqCst);
        }
    }

    /// Starts a compaction on a background thread unless one runs, the floor applies, or the store
    /// is stopping; returns whether one started. A panic on the thread aborts the process.
    pub(super) fn compact_authorities(&self) -> bool {
        let compaction = &self.authority_compaction;
        if !compaction.compacts {
            return false;
        }
        // One lock covers the checks, the spawn and the handle, so a concurrent stop cannot miss
        // the thread.
        let mut last = compaction.last.lock();
        if compaction.stop.load(Ordering::SeqCst)
            || last.thread.as_ref().is_some_and(|thread| !thread.is_finished())
            || last.started.is_some_and(|started| started.elapsed() < AUTHORITY_COMPACTION_MIN_INTERVAL)
        {
            return false;
        }
        let (storage, weak) = (self.storage.clone(), Arc::downgrade(compaction));
        let compact = move || {
            let result =
                std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| compact_authority_slices(&storage, &weak)));
            match result {
                Ok(Ok(_)) => {}
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
            if AUTHORITY_COMPACTION_INLINE.with(|inline| inline.get()) {
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

    /// Stops the background authority map compaction, if one runs, and waits for it: the running
    /// slice finishes, then the thread is joined.
    pub fn stop_background_work(&self) {
        self.authority_compaction.stop.store(true, Ordering::SeqCst);
        let Some(thread) = self.authority_compaction.last.lock().thread.take() else {
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

/// The last store sharing the compaction state stops its thread; the thread itself holds the state
/// only weakly.
impl<N: Network, B: BlockStorage<N>> Drop for BlockStore<N, B> {
    fn drop(&mut self) {
        if Arc::strong_count(&self.authority_compaction) == 1 {
            self.stop_background_work();
        }
    }
}

/// Milliseconds each slice takes in tests, so a test can stop a running thread.
#[cfg(test)]
static SLICE_DELAY_MS: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

#[cfg(test)]
thread_local! {
    /// The number of authority map compactions started on this thread.
    static AUTHORITY_COMPACTIONS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
    /// The number of authority map slices passed, compacted or skipped, on this thread.
    static AUTHORITY_SLICES_DONE: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
    /// Stops the authority map compaction once this many slices were passed on this thread.
    static AUTHORITY_COMPACTION_STOP_AFTER: std::cell::Cell<Option<usize>> = const { std::cell::Cell::new(None) };
    /// Whether this thread's stores compact the authority map inline instead of on a thread.
    static AUTHORITY_COMPACTION_INLINE: std::cell::Cell<bool> = const { std::cell::Cell::new(true) };
    /// The number of running compaction threads this thread has stopped and joined.
    static AUTHORITY_COMPACTION_RUNNING_JOINS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(feature = "rocks")]
    use crate::helpers::rocksdb::BlockDB;
    use crate::{block::test_chain::sample_block_chain, helpers::memory::BlockMemory};

    type CurrentNetwork = console::network::MainnetV0;

    #[cfg(feature = "rocks")]
    fn open_rocksdb() -> BlockStore<CurrentNetwork, BlockDB<CurrentNetwork>> {
        let temp_dir = Arc::new(tempfile::tempdir().unwrap());
        BlockStore::open(StorageMode::new_test(Some(temp_dir))).unwrap()
    }

    fn compactions() -> usize {
        AUTHORITY_COMPACTIONS.with(|count| count.get())
    }

    #[cfg(feature = "rocks")]
    fn slices() -> usize {
        AUTHORITY_SLICES_DONE.with(|count| count.get())
    }

    #[cfg(feature = "rocks")]
    fn running_joins() -> usize {
        AUTHORITY_COMPACTION_RUNNING_JOINS.with(|count| count.get())
    }

    /// Forgets the last start, so the floor does not apply to the next trigger.
    #[cfg(feature = "rocks")]
    fn clear_floor<B: BlockStorage<CurrentNetwork>>(store: &BlockStore<CurrentNetwork, B>) {
        store.authority_compaction.last.lock().started = None;
    }

    /// Opens a store whose compaction runs on a thread, slowly.
    #[cfg(feature = "rocks")]
    fn open_with_slow_thread() -> BlockStore<CurrentNetwork, BlockDB<CurrentNetwork>> {
        SLICE_DELAY_MS.store(30, Ordering::SeqCst);
        AUTHORITY_COMPACTION_INLINE.with(|inline| inline.set(false));
        let store = open_rocksdb();
        AUTHORITY_COMPACTION_INLINE.with(|inline| inline.set(true));
        assert!(store.authority_compaction.last.lock().thread.is_some());
        store
    }

    /// Ensures the real thread path starts at open, stops on request, and is not restarted.
    #[cfg(feature = "rocks")]
    #[test]
    fn test_authority_compaction_thread_stops_rocksdb() {
        let store = open_with_slow_thread();
        let before = running_joins();
        store.stop_background_work();
        SLICE_DELAY_MS.store(0, Ordering::SeqCst);
        assert_eq!(running_joins(), before + 1);
        assert!(store.authority_compaction.last.lock().thread.is_none());
        clear_floor(&store);
        assert!(!store.compact_authorities());
        store.stop_background_work();
    }

    /// Ensures dropping the last store stops and joins a running compaction thread.
    #[cfg(feature = "rocks")]
    #[test]
    fn test_dropping_the_store_stops_the_thread_rocksdb() {
        let store = open_with_slow_thread();
        let clone = store.clone();
        let before = running_joins();
        // A clone remains, so nothing stops yet.
        drop(store);
        assert_eq!(running_joins(), before);
        drop(clone);
        SLICE_DELAY_MS.store(0, Ordering::SeqCst);
        assert_eq!(running_joins(), before + 1);
    }

    /// Ensures a compaction stops at the next slice once every holder of its state is gone.
    #[cfg(feature = "rocks")]
    #[test]
    fn test_authority_compaction_stops_without_a_store_rocksdb() {
        let store = open_rocksdb();
        let total = store.storage.authority_compaction_plan().unwrap().len();
        let compaction = Arc::new(AuthorityCompaction::new(true));
        let weak = Arc::downgrade(&compaction);
        assert_eq!(compact_authority_slices(&store.storage, &weak).unwrap(), total);
        drop(compaction);
        assert_eq!(compact_authority_slices(&store.storage, &weak).unwrap(), 0);
    }

    /// Ensures every open starts exactly one authority compaction, and that an open after a stopped
    /// one passes every slice again.
    #[cfg(feature = "rocks")]
    #[test]
    fn test_open_starts_authority_compaction_rocksdb() {
        let temp_dir = Arc::new(tempfile::tempdir().unwrap());
        let storage_mode = StorageMode::new_test(Some(temp_dir));

        // This open's compaction is stopped after one slice.
        let (compactions_before, slices_before) = (compactions(), slices());
        AUTHORITY_COMPACTION_STOP_AFTER.with(|n| n.set(Some(slices_before + 1)));
        let store = BlockStore::<CurrentNetwork, BlockDB<_>>::open(storage_mode.clone()).unwrap();
        AUTHORITY_COMPACTION_STOP_AFTER.with(|n| n.set(None));
        assert_eq!((compactions(), slices()), (compactions_before + 1, slices_before + 1));
        let total = store.storage.authority_compaction_plan().unwrap().len();
        drop(store);

        let _store = BlockStore::<CurrentNetwork, BlockDB<_>>::open(storage_mode).unwrap();
        assert_eq!((compactions(), slices()), (compactions_before + 2, slices_before + 1 + total));
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

    /// Checks that insert-time pruning compacts the authority map once per
    /// `AUTHORITY_COMPACTION_INTERVAL_BLOCKS` pruned authorities.
    #[cfg(feature = "rocks")]
    fn check_insert_time_pruning_compacts_after_interval(deferred: bool) {
        let store = open_rocksdb();
        let rng = &mut TestRng::default();
        let blocks = sample_block_chain(AUTHORITY_RETENTION_BLOCKS + AUTHORITY_COMPACTION_INTERVAL_BLOCKS + 1, rng);
        clear_floor(&store);
        let before = compactions();
        let trigger = AUTHORITY_RETENTION_BLOCKS + AUTHORITY_COMPACTION_INTERVAL_BLOCKS - 1;
        for block in &blocks {
            insert(&store, block, deferred);
            let expected = before + usize::from(block.height() >= trigger);
            assert_eq!(compactions(), expected, "at block {}", block.height());
        }
    }

    /// Ensures insert-time pruning compacts the authority map after the interval, through both
    /// insert paths.
    #[cfg(feature = "rocks")]
    #[test]
    fn test_insert_time_pruning_compacts_after_interval_rocksdb() {
        check_insert_time_pruning_compacts_after_interval(false);
        check_insert_time_pruning_compacts_after_interval(true);
    }

    /// Ensures in-memory storage, which has nothing to compact, starts no compaction and counts no
    /// inserts.
    #[test]
    fn test_memory_storage_compacts_nothing() {
        let store = BlockStore::<CurrentNetwork, BlockMemory<_>>::open(StorageMode::new_test(None)).unwrap();
        assert!(!store.authority_compaction.compacts);
        assert!(!store.compact_authorities());
        let rng = &mut TestRng::default();
        let before = compactions();
        for block in &sample_block_chain(AUTHORITY_RETENTION_BLOCKS + 3, rng) {
            insert(&store, block, false);
        }
        assert_eq!(compactions(), before);
        assert_eq!(store.authority_compaction.pruned.load(Ordering::SeqCst), 0);
    }

    /// Ensures a trigger inside the floor after the last start fires nothing and keeps its count,
    /// and fires on the next insert after the floor.
    #[cfg(feature = "rocks")]
    #[test]
    fn test_trigger_waits_for_the_floor_rocksdb() {
        let store = open_rocksdb();
        let rng = &mut TestRng::default();
        let blocks = sample_block_chain(AUTHORITY_RETENTION_BLOCKS + AUTHORITY_COMPACTION_INTERVAL_BLOCKS + 1, rng);
        let trigger = AUTHORITY_RETENTION_BLOCKS + AUTHORITY_COMPACTION_INTERVAL_BLOCKS - 1;

        // A start in the future is inside the floor for the whole test.
        store.authority_compaction.last.lock().started = Some(Instant::now() + Duration::from_secs(3600));
        let before = compactions();
        for block in blocks.iter().filter(|block| block.height() <= trigger) {
            store.insert(block).unwrap();
        }
        assert_eq!(compactions(), before);
        assert_eq!(store.authority_compaction.pruned.load(Ordering::SeqCst), AUTHORITY_COMPACTION_INTERVAL_BLOCKS);

        store.authority_compaction.last.lock().started = Instant::now().checked_sub(AUTHORITY_COMPACTION_MIN_INTERVAL);
        store.insert(&blocks[trigger as usize + 1]).unwrap();
        assert_eq!(compactions(), before + 1);
        assert_eq!(store.authority_compaction.pruned.load(Ordering::SeqCst), 0);
    }

    /// Ensures a trigger that fires while a compaction runs keeps its count, and fires on the next
    /// insert once the compaction has ended.
    #[cfg(feature = "rocks")]
    #[test]
    fn test_trigger_waits_for_the_running_compaction_rocksdb() {
        let store = open_rocksdb();
        let rng = &mut TestRng::default();
        let blocks = sample_block_chain(AUTHORITY_RETENTION_BLOCKS + AUTHORITY_COMPACTION_INTERVAL_BLOCKS + 1, rng);
        let trigger = AUTHORITY_RETENTION_BLOCKS + AUTHORITY_COMPACTION_INTERVAL_BLOCKS - 1;
        clear_floor(&store);

        // A compaction that runs until released.
        let release = Arc::new(AtomicBool::new(false));
        let running = {
            let release = release.clone();
            std::thread::spawn(move || {
                while !release.load(Ordering::SeqCst) {
                    std::thread::sleep(Duration::from_millis(1));
                }
            })
        };
        store.authority_compaction.last.lock().thread = Some(running);

        let before = compactions();
        for block in blocks.iter().filter(|block| block.height() <= trigger) {
            store.insert(block).unwrap();
        }
        assert_eq!(compactions(), before);
        assert_eq!(store.authority_compaction.pruned.load(Ordering::SeqCst), AUTHORITY_COMPACTION_INTERVAL_BLOCKS);

        release.store(true, Ordering::SeqCst);
        while store.authority_compaction.last.lock().thread.as_ref().is_some_and(|thread| !thread.is_finished()) {
            std::thread::sleep(Duration::from_millis(1));
        }
        store.insert(&blocks[trigger as usize + 1]).unwrap();
        assert_eq!(compactions(), before + 1);
        assert_eq!(store.authority_compaction.pruned.load(Ordering::SeqCst), 0);
    }
}
