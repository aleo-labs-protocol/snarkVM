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

/// The least time between two starts of the compaction, so a catch-up sync does not compact at
/// every interval. Unit tests use a few milliseconds.
const AUTHORITY_COMPACTION_MIN_INTERVAL: Duration =
    if cfg!(test) { Duration::from_millis(20) } else { Duration::from_secs(12 * 60 * 60) };

/// Compacts the authority map in the storage's slices for this run (see
/// [`BlockStorage::authority_compaction_slices`]), and returns the number of slices done. Stops
/// between slices once `compaction` is stopping or dropped; the next start, which always compacts,
/// redoes the rest.
fn compact_authority_slices<N: Network, B: BlockStorage<N>>(
    storage: &B,
    compaction: &Weak<AuthorityCompaction>,
) -> Result<usize> {
    let total = storage.authority_compaction_slices();
    info!("Compacting the authority map in {total} slices; this can take a while");
    let mut progress = Progress::new(total);
    for i in 0..total {
        if compaction.upgrade().is_none_or(|compaction| compaction.stop.load(Ordering::SeqCst)) {
            info!("Stopped the authority map compaction before slice {i} of {total}; the next start redoes it");
            return Ok(i);
        }
        storage.compact_authority_slice(i, total)?;
        #[cfg(test)]
        AUTHORITY_SLICES_COMPACTED.with(|count| {
            count.set(count.get() + 1);
            if AUTHORITY_COMPACTION_STOP_AFTER.with(|n| n.get()) == Some(count.get())
                && let Some(compaction) = compaction.upgrade()
            {
                compaction.stop.store(true, Ordering::SeqCst);
            }
        });
        if let Some((elapsed, remaining)) = progress.advance() {
            info!(
                "Compacted {} of {total} authority slices in {elapsed:.0} s, about {remaining:.0} s left",
                progress.done()
            );
        }
    }
    info!("Compacted the authority map in {:.1} s", progress.elapsed_secs());
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
    /// When the last compaction started.
    last_start: Mutex<Option<Instant>>,
    /// The thread of the last compaction started; running while it is not finished.
    thread: Mutex<Option<std::thread::JoinHandle<()>>>,
}

impl AuthorityCompaction {
    pub(super) fn new(compacts: bool) -> Self {
        Self {
            compacts,
            pruned: Default::default(),
            stop: Default::default(),
            last_start: Default::default(),
            thread: Default::default(),
        }
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

    /// Starts an authority map compaction on a background thread. Returns `false` and starts
    /// nothing when the storage has nothing to compact, while one runs, within
    /// [`AUTHORITY_COMPACTION_MIN_INTERVAL`] of the last start, once the store is stopping, or when
    /// the thread cannot be spawned. A panic on the thread aborts the process. Tests compact inline
    /// by default, so they can count it.
    pub(super) fn compact_authorities(&self) -> bool {
        let compaction = &self.authority_compaction;
        if !compaction.compacts {
            return false;
        }
        // One lock covers the checks, the spawn and the handle, so a concurrent stop cannot miss
        // the thread.
        let mut thread = compaction.thread.lock();
        let mut last_start = compaction.last_start.lock();
        if compaction.stop.load(Ordering::SeqCst)
            || thread.as_ref().is_some_and(|thread| !thread.is_finished())
            || last_start.is_some_and(|start| start.elapsed() < AUTHORITY_COMPACTION_MIN_INTERVAL)
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
        *last_start = Some(Instant::now());
        #[cfg(test)]
        {
            AUTHORITY_COMPACTIONS.with(|count| count.set(count.get() + 1));
            if AUTHORITY_COMPACTION_INLINE.with(|inline| inline.get()) {
                drop(last_start);
                drop(thread);
                compact();
                return true;
            }
        }
        match std::thread::Builder::new().name("authority-compaction".into()).spawn(compact) {
            Ok(handle) => {
                *thread = Some(handle);
                true
            }
            Err(error) => {
                error!("Failed to start the authority map compaction: {error}");
                *last_start = None;
                false
            }
        }
    }

    /// Stops the background authority map compaction, if one runs, and waits for it: the running
    /// slice finishes, then the thread is joined. The next start redoes the map. Call it once per
    /// process, at shutdown.
    pub fn stop_background_work(&self) {
        self.authority_compaction.stop.store(true, Ordering::SeqCst);
        let Some(thread) = self.authority_compaction.thread.lock().take() else {
            return;
        };
        let running = !thread.is_finished();
        let timer = Instant::now();
        // A failed join means the thread panicked, and the process is aborting.
        let _ = thread.join();
        if running {
            info!("Waited {:.1} s for the authority map compaction to finish its slice", timer.elapsed().as_secs_f64());
        }
    }
}

#[cfg(test)]
thread_local! {
    /// The number of authority map compactions started on this thread.
    static AUTHORITY_COMPACTIONS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
    /// The number of authority map slices compacted on this thread.
    static AUTHORITY_SLICES_COMPACTED: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
    /// Stops the authority map compaction once this many slices were compacted on this thread.
    static AUTHORITY_COMPACTION_STOP_AFTER: std::cell::Cell<Option<usize>> = const { std::cell::Cell::new(None) };
    /// Whether this thread's stores compact the authority map inline instead of on a thread.
    static AUTHORITY_COMPACTION_INLINE: std::cell::Cell<bool> = const { std::cell::Cell::new(true) };
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
        AUTHORITY_SLICES_COMPACTED.with(|count| count.get())
    }

    /// Forgets the last start, so the floor does not apply to the next trigger.
    fn clear_floor<B: BlockStorage<CurrentNetwork>>(store: &BlockStore<CurrentNetwork, B>) {
        *store.authority_compaction.last_start.lock() = None;
    }

    /// Ensures the real thread path starts at open, stops on request, and is not restarted.
    #[cfg(feature = "rocks")]
    #[test]
    fn test_authority_compaction_thread_stops_rocksdb() {
        AUTHORITY_COMPACTION_INLINE.with(|inline| inline.set(false));
        let store = open_rocksdb();
        AUTHORITY_COMPACTION_INLINE.with(|inline| inline.set(true));
        assert!(store.authority_compaction.thread.lock().is_some());

        store.stop_background_work();
        assert!(store.authority_compaction.thread.lock().is_none());
        clear_floor(&store);
        assert!(!store.compact_authorities());
        store.stop_background_work();
    }

    /// Ensures a compaction stops at the next slice once every store holding its state is dropped.
    #[cfg(feature = "rocks")]
    #[test]
    fn test_authority_compaction_stops_without_a_store_rocksdb() {
        let store = open_rocksdb();
        let total = store.storage.authority_compaction_slices();
        let compaction = Arc::new(AuthorityCompaction::new(true));
        let weak = Arc::downgrade(&compaction);
        assert_eq!(compact_authority_slices(&store.storage, &weak).unwrap(), total);
        drop(compaction);
        assert_eq!(compact_authority_slices(&store.storage, &weak).unwrap(), 0);
    }

    /// Ensures every open starts exactly one authority compaction, and that an open after a stopped
    /// one compacts every slice again.
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
        let total = store.storage.authority_compaction_slices();
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
    /// `AUTHORITY_COMPACTION_INTERVAL_BLOCKS` pruned authorities, if the storage compacts at all.
    fn check_insert_time_pruning_compacts_after_interval<B: BlockStorage<CurrentNetwork>>(
        store: BlockStore<CurrentNetwork, B>,
        deferred: bool,
    ) {
        let rng = &mut TestRng::default();
        let blocks = sample_block_chain(AUTHORITY_RETENTION_BLOCKS + AUTHORITY_COMPACTION_INTERVAL_BLOCKS + 1, rng);
        clear_floor(&store);
        let before = compactions();
        let trigger = AUTHORITY_RETENTION_BLOCKS + AUTHORITY_COMPACTION_INTERVAL_BLOCKS - 1;
        let compacts = store.authority_compaction.compacts;
        for block in &blocks {
            insert(&store, block, deferred);
            let expected = before + usize::from(compacts && block.height() >= trigger);
            assert_eq!(compactions(), expected, "at block {}", block.height());
        }
    }

    /// Ensures insert-time pruning compacts the authority map after the interval with RocksDB storage.
    #[cfg(feature = "rocks")]
    #[test]
    fn test_insert_time_pruning_compacts_after_interval_rocksdb() {
        check_insert_time_pruning_compacts_after_interval(open_rocksdb(), false);
        check_insert_time_pruning_compacts_after_interval(open_rocksdb(), true);
    }

    /// Ensures in-memory storage, which has nothing to compact, never starts a compaction.
    #[test]
    fn test_insert_time_pruning_compacts_after_interval_memory() {
        let store = BlockStore::<CurrentNetwork, BlockMemory<_>>::open(StorageMode::new_test(None)).unwrap();
        assert!(!store.authority_compaction.compacts);
        assert!(!store.compact_authorities());
        check_insert_time_pruning_compacts_after_interval(store, false);
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

        // A start far enough in the past to be outside the floor is set below; this one is inside it.
        *store.authority_compaction.last_start.lock() = Some(Instant::now() + Duration::from_secs(3600));
        let before = compactions();
        for block in blocks.iter().filter(|block| block.height() <= trigger) {
            store.insert(block).unwrap();
        }
        assert_eq!(compactions(), before);
        assert_eq!(store.authority_compaction.pruned.load(Ordering::SeqCst), AUTHORITY_COMPACTION_INTERVAL_BLOCKS);

        *store.authority_compaction.last_start.lock() = Instant::now().checked_sub(AUTHORITY_COMPACTION_MIN_INTERVAL);
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
        *store.authority_compaction.thread.lock() = Some(running);

        let before = compactions();
        for block in blocks.iter().filter(|block| block.height() <= trigger) {
            store.insert(block).unwrap();
        }
        assert_eq!(compactions(), before);
        assert_eq!(store.authority_compaction.pruned.load(Ordering::SeqCst), AUTHORITY_COMPACTION_INTERVAL_BLOCKS);

        release.store(true, Ordering::SeqCst);
        while store.authority_compaction.thread.lock().as_ref().is_some_and(|thread| !thread.is_finished()) {
            std::thread::sleep(Duration::from_millis(1));
        }
        store.insert(&blocks[trigger as usize + 1]).unwrap();
        assert_eq!(compactions(), before + 1);
        assert_eq!(store.authority_compaction.pruned.load(Ordering::SeqCst), 0);
    }
}
