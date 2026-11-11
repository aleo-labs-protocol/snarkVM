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
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};

/// The number of authorities pruned at insert time between compactions of the authority map.
/// Pruned authorities are interleaved with retained ones in every file, so without a compaction
/// their space is reclaimed only when RocksDB happens to rewrite the file. Each run reads and
/// rewrites the retained window, about 25 GB each way on mainnet, to reclaim the rows pruned since
/// the last run, about 5 GB at 100,000 blocks (about three days), so the interval trades disk
/// headroom for I/O. A height-keyed authority layout, in a later change, removes that cost. Unit
/// tests use a few blocks.
const AUTHORITY_COMPACTION_INTERVAL_BLOCKS: u32 = if cfg!(test) { 8 } else { 100_000 };

/// Compacts the authority map in the storage's slices (see
/// [`BlockStorage::authority_compaction_slices`]). Stops between slices once `stop` is set; the
/// next start, which always compacts, redoes the rest.
fn compact_authority_slices<N: Network, B: BlockStorage<N>>(storage: &B, stop: &AtomicBool) -> Result<()> {
    let total = storage.authority_compaction_slices();
    if total == 0 || stop.load(Ordering::SeqCst) {
        return Ok(());
    }
    info!("Compacting the authority map in {total} slices; this can take a while");
    let mut progress = Progress::new(total);
    for i in 0..total {
        if stop.load(Ordering::SeqCst) {
            info!("Stopped the authority map compaction before slice {i} of {total}; the next start redoes it");
            return Ok(());
        }
        storage.compact_authority_slice(i, total)?;
        #[cfg(test)]
        AUTHORITY_SLICES_COMPACTED.with(|count| {
            count.set(count.get() + 1);
            if AUTHORITY_COMPACTION_STOP_AFTER.with(|n| n.get()) == Some(count.get()) {
                stop.store(true, Ordering::SeqCst);
            }
        });
        if let Some((elapsed, remaining)) = progress.advance(1) {
            info!(
                "Compacted {} of {total} authority slices in {elapsed:.0} s, about {remaining:.0} s left",
                progress.done()
            );
        }
    }
    info!("Compacted the authority map in {:.1} s", progress.elapsed_secs());
    Ok(())
}

/// The state of the background authority map compaction of a [`BlockStore`].
#[derive(Default)]
pub(super) struct AuthorityCompaction {
    /// The number of authorities pruned since the authority map was compacted.
    pruned: AtomicU32,
    /// Set at shutdown, so no compaction starts and the running one stops between slices.
    stop: AtomicBool,
    /// The thread of the last compaction started; running while it is not finished.
    thread: Mutex<Option<std::thread::JoinHandle<()>>>,
}

impl<N: Network, B: BlockStorage<N>> BlockStore<N, B> {
    /// Counts the authority pruned by the insert of the block at `height`, if any, and starts a
    /// compaction every [`AUTHORITY_COMPACTION_INTERVAL_BLOCKS`] of them. Counts by height, so
    /// after a rollback it overstates until the watermark catches up; a compaction a little early is
    /// harmless.
    pub(super) fn count_insert_time_pruning(&self, height: u32) {
        if height < AUTHORITY_RETENTION_BLOCKS || self.authority_compaction.stop.load(Ordering::SeqCst) {
            return;
        }
        let pruned = self.authority_compaction.pruned.fetch_add(1, Ordering::SeqCst) + 1;
        if pruned >= AUTHORITY_COMPACTION_INTERVAL_BLOCKS && self.compact_authorities() {
            self.authority_compaction.pruned.store(0, Ordering::SeqCst);
        }
    }

    /// Starts an authority map compaction on a background thread. Returns `false` and starts
    /// nothing while one runs, once the store is stopping, when the storage has nothing to
    /// compact, or when the thread cannot be spawned. Tests compact inline by default, so they can
    /// count it.
    pub(super) fn compact_authorities(&self) -> bool {
        let compaction = &self.authority_compaction;
        if self.storage.authority_compaction_slices() == 0 {
            return false;
        }
        // One lock covers the stop and running checks, the spawn and the handle, so a concurrent
        // stop cannot miss the thread.
        let mut thread = compaction.thread.lock();
        if compaction.stop.load(Ordering::SeqCst) || thread.as_ref().is_some_and(|thread| !thread.is_finished()) {
            return false;
        }
        let (storage, compaction) = (self.storage.clone(), compaction.clone());
        let compact = move || {
            if let Err(error) = compact_authority_slices(&storage, &compaction.stop) {
                error!("Failed to compact the authority map: {error}");
            }
        };
        #[cfg(test)]
        {
            AUTHORITY_COMPACTIONS.with(|count| count.set(count.get() + 1));
            if AUTHORITY_COMPACTION_INLINE.with(|inline| inline.get()) {
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
                false
            }
        }
    }

    /// Stops the background authority map compaction, if one runs, and waits for it; the next
    /// start redoes it. The running slice finishes first: RocksDB's `cancel_all_background_work`
    /// is process-wide and irreversible, and the Rust bindings do not reach its
    /// `DisableManualCompaction`. Call it once per process, at shutdown.
    pub fn stop_background_work(&self) {
        self.authority_compaction.stop.store(true, Ordering::SeqCst);
        let Some(thread) = self.authority_compaction.thread.lock().take() else {
            return;
        };
        if !thread.is_finished() {
            info!("Waiting for the authority map compaction to finish its slice");
        }
        if thread.join().is_err() {
            error!("The authority map compaction thread panicked");
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

    /// Ensures a compaction stopped between slices leaves the rest, that nothing starts while the
    /// stop flag is set, and that the next compaction runs every slice again.
    #[cfg(feature = "rocks")]
    #[test]
    fn test_authority_compaction_stops_rocksdb() {
        let store = open_rocksdb();
        let total = store.storage.authority_compaction_slices();

        let before = slices();
        AUTHORITY_COMPACTION_STOP_AFTER.with(|n| n.set(Some(before + 2)));
        assert!(store.compact_authorities());
        assert_eq!(slices(), before + 2);
        AUTHORITY_COMPACTION_STOP_AFTER.with(|n| n.set(None));

        // While the stop flag is set, nothing starts.
        assert!(!store.compact_authorities());
        assert_eq!(slices(), before + 2);

        store.authority_compaction.stop.store(false, Ordering::SeqCst);
        assert!(store.compact_authorities());
        assert_eq!(slices(), before + 2 + total);
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
        assert!(!store.compact_authorities());
        store.stop_background_work();
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

    /// Checks that insert-time pruning compacts the authority map once per
    /// `AUTHORITY_COMPACTION_INTERVAL_BLOCKS` pruned authorities, if the storage compacts at all.
    fn check_insert_time_pruning_compacts_after_interval<B: BlockStorage<CurrentNetwork>>(
        store: BlockStore<CurrentNetwork, B>,
    ) {
        let rng = &mut TestRng::default();
        let blocks = sample_block_chain(AUTHORITY_RETENTION_BLOCKS + AUTHORITY_COMPACTION_INTERVAL_BLOCKS + 1, rng);
        let before = compactions();
        let trigger = AUTHORITY_RETENTION_BLOCKS + AUTHORITY_COMPACTION_INTERVAL_BLOCKS - 1;
        let compacts = store.storage.authority_compaction_slices() > 0;
        for block in &blocks {
            store.insert(block).unwrap();
            let expected = before + usize::from(compacts && block.height() >= trigger);
            assert_eq!(compactions(), expected, "at block {}", block.height());
        }
    }

    /// Ensures insert-time pruning compacts the authority map after the interval with RocksDB storage.
    #[cfg(feature = "rocks")]
    #[test]
    fn test_insert_time_pruning_compacts_after_interval_rocksdb() {
        check_insert_time_pruning_compacts_after_interval(open_rocksdb());
    }

    /// Ensures in-memory storage, which has nothing to compact, never starts a compaction.
    #[test]
    fn test_insert_time_pruning_compacts_after_interval_memory() {
        let store = BlockStore::<CurrentNetwork, BlockMemory<_>>::open(StorageMode::new_test(None)).unwrap();
        assert!(!store.compact_authorities());
        check_insert_time_pruning_compacts_after_interval(store);
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

        // A compaction that runs until released.
        let release = Arc::new(AtomicBool::new(false));
        let running = {
            let release = release.clone();
            std::thread::spawn(move || {
                while !release.load(Ordering::SeqCst) {
                    std::thread::sleep(std::time::Duration::from_millis(1));
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
            std::thread::sleep(std::time::Duration::from_millis(1));
        }
        store.insert(&blocks[trigger as usize + 1]).unwrap();
        assert_eq!(compactions(), before + 1);
        assert_eq!(store.authority_compaction.pruned.load(Ordering::SeqCst), 0);
    }
}
