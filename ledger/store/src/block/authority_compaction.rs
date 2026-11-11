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

/// The number of authorities pruned at insert time between compactions of the authority map.
/// Pruned authorities are interleaved with retained ones in every file, so without a compaction
/// their space is reclaimed only when RocksDB happens to rewrite the file. Each run reads and
/// rewrites the retained window, about 25 GB each way on mainnet, to reclaim the rows pruned since
/// the last run, about 5 GB at 100,000 blocks (about three days), so the interval trades disk
/// headroom for I/O. A height-keyed authority layout, in a later change, removes that cost. Unit
/// tests use a few blocks.
const AUTHORITY_COMPACTION_INTERVAL_BLOCKS: u32 = if cfg!(test) { 8 } else { 100_000 };

/// The number of key-range slices the authority map is compacted in, one call each, so progress
/// can be logged and a shutdown can stop between them. Block hashes are uniform in their first
/// bytes, so the slices split the first two key bytes evenly. Unit tests use a few slices.
const AUTHORITY_COMPACTION_SLICES: usize = if cfg!(test) { 4 } else { 256 };

/// The authority map compaction logs progress about this often.
const AUTHORITY_COMPACTION_REPORT_INTERVAL: std::time::Duration = std::time::Duration::from_secs(10);

/// Compacts the authority map in [`AUTHORITY_COMPACTION_SLICES`] slices. Stops between slices once
/// `stop` is set; the next start, which always compacts, redoes the rest.
fn compact_authority_slices<N: Network, B: BlockStorage<N>>(storage: &B, stop: &AtomicBool) -> Result<()> {
    let total = AUTHORITY_COMPACTION_SLICES;
    info!("Compacting the authority map in {total} slices; this can take a while");
    let timer = std::time::Instant::now();
    let mut next_report = AUTHORITY_COMPACTION_REPORT_INTERVAL;
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

        let (done, elapsed) = (i + 1, timer.elapsed());
        if elapsed >= next_report && done < total {
            let remaining = elapsed.as_secs_f64() * (total - done) as f64 / done as f64;
            info!(
                "Compacted {done} of {total} authority slices in {:.0} s, about {remaining:.0} s left",
                elapsed.as_secs_f64()
            );
            next_report = elapsed + AUTHORITY_COMPACTION_REPORT_INTERVAL;
        }
    }
    info!("Compacted the authority map in {:.1} s", timer.elapsed().as_secs_f64());
    Ok(())
}

/// The state of the background authority map compaction of a [`BlockStore`].
#[derive(Default)]
pub(super) struct AuthorityCompaction {
    /// The number of authorities pruned since the authority map was compacted.
    pruned: AtomicU32,
    /// Whether an authority map compaction is running.
    running: AtomicBool,
    /// Set at shutdown, so the authority map compaction stops between slices.
    stop: AtomicBool,
    /// The thread of the running authority map compaction, joined at shutdown.
    thread: Mutex<Option<std::thread::JoinHandle<()>>>,
}

impl<N: Network, B: BlockStorage<N>> BlockStore<N, B> {
    /// Adds `pruned` to the authorities pruned since the last authority map compaction, and starts
    /// one when they reach [`AUTHORITY_COMPACTION_INTERVAL_BLOCKS`].
    fn count_pruned_authorities(&self, pruned: u32) {
        let total = self.authority_compaction.pruned.fetch_add(pruned, Ordering::SeqCst) + pruned;
        if total >= AUTHORITY_COMPACTION_INTERVAL_BLOCKS && self.compact_authorities() {
            self.authority_compaction.pruned.store(0, Ordering::SeqCst);
        }
    }

    /// Counts the authority pruned by the insert of the block at `height`, if any.
    pub(super) fn count_insert_time_pruning(&self, height: u32) {
        if height >= AUTHORITY_RETENTION_BLOCKS {
            self.count_pruned_authorities(1);
        }
    }

    /// Starts an authority map compaction on a background thread, and returns `false` if one is
    /// already running or the storage has nothing to compact. RocksDB reports compaction errors
    /// only in its LOG. Tests compact inline by default, so they can count it.
    pub(super) fn compact_authorities(&self) -> bool {
        /// Clears the running flag when the compaction ends, by return or by panic.
        struct Running(Arc<AuthorityCompaction>);
        impl Drop for Running {
            fn drop(&mut self) {
                self.0.running.store(false, Ordering::SeqCst);
            }
        }

        if !self.storage.compacts_authority_map() || self.authority_compaction.running.swap(true, Ordering::SeqCst) {
            return false;
        }
        let running = Running(self.authority_compaction.clone());
        let storage = self.storage.clone();
        let compact = move || {
            let running = running;
            if let Err(error) = compact_authority_slices(&storage, &running.0.stop) {
                error!("Failed to compact the authority map: {error}");
            }
        };
        #[cfg(test)]
        {
            AUTHORITY_COMPACTIONS.with(|count| count.set(count.get() + 1));
            if AUTHORITY_COMPACTION_INLINE.with(|inline| inline.get()) {
                compact();
                return true;
            }
        }
        // Hold the slot while spawning, so a concurrent `stop_background_work` waits for the handle.
        let mut thread = self.authority_compaction.thread.lock();
        match std::thread::Builder::new().name("authority-compaction".into()).spawn(compact) {
            Ok(handle) => *thread = Some(handle),
            Err(error) => error!("Failed to start the authority map compaction: {error}"),
        }
        true
    }

    /// Stops the background authority map compaction, if one runs, and waits for it; the next
    /// start redoes it. The running slice finishes first: RocksDB's `cancel_all_background_work`
    /// is process-wide and irreversible, and the Rust bindings do not reach its
    /// `DisableManualCompaction`, so a slice, one of [`AUTHORITY_COMPACTION_SLICES`], is the unit
    /// of waiting. Call it once per process at shutdown; a second `BlockStore` on the same path is
    /// not supported for background compaction, as it is not for pruning. A no-op when nothing runs.
    pub fn stop_background_work(&self) {
        self.authority_compaction.stop.store(true, Ordering::SeqCst);
        let Some(thread) = self.authority_compaction.thread.lock().take() else {
            return;
        };
        if thread.is_finished() {
            return;
        }
        info!("Waiting for the authority map compaction to finish its slice");
        if thread.join().is_err() {
            error!("The authority map compaction thread panicked");
        }
        info!("The authority map compaction stopped");
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

    /// Checks that a compaction stopped between slices leaves the rest, that nothing runs while the
    /// stop flag is set, and that the next compaction runs every slice again.
    #[cfg(feature = "rocks")]
    fn check_authority_compaction_stops<B: BlockStorage<CurrentNetwork>>(store: BlockStore<CurrentNetwork, B>) {
        let slices = || AUTHORITY_SLICES_COMPACTED.with(|count| count.get());
        let total = AUTHORITY_COMPACTION_SLICES;

        let before = slices();
        AUTHORITY_COMPACTION_STOP_AFTER.with(|n| n.set(Some(before + 2)));
        assert!(store.compact_authorities());
        assert_eq!(slices(), before + 2);
        AUTHORITY_COMPACTION_STOP_AFTER.with(|n| n.set(None));

        // While the stop flag is set, a compaction ends before its first slice.
        assert!(store.compact_authorities());
        assert_eq!(slices(), before + 2);

        store.authority_compaction.stop.store(false, Ordering::SeqCst);
        assert!(store.compact_authorities());
        assert_eq!(slices(), before + 2 + total);

        // Stopping with nothing running is a no-op.
        store.stop_background_work();
        store.stop_background_work();
    }

    /// Ensures a stopped authority compaction leaves the loop between slices, with RocksDB storage.
    #[cfg(feature = "rocks")]
    #[test]
    fn test_authority_compaction_stops_rocksdb() {
        let temp_dir = Arc::new(tempfile::tempdir().unwrap());
        check_authority_compaction_stops(
            BlockStore::<CurrentNetwork, BlockDB<_>>::open(StorageMode::new_test(Some(temp_dir))).unwrap(),
        );
    }

    /// Ensures the real thread path starts, stops on request and leaves consistent state.
    #[cfg(feature = "rocks")]
    #[test]
    fn test_authority_compaction_thread_stops_rocksdb() {
        let temp_dir = Arc::new(tempfile::tempdir().unwrap());
        AUTHORITY_COMPACTION_INLINE.with(|inline| inline.set(false));
        // The open starts the compaction on a thread.
        let block_store =
            BlockStore::<CurrentNetwork, BlockDB<_>>::open(StorageMode::new_test(Some(temp_dir))).unwrap();
        AUTHORITY_COMPACTION_INLINE.with(|inline| inline.set(true));
        assert!(block_store.authority_compaction.thread.lock().is_some());

        block_store.stop_background_work();
        assert!(block_store.authority_compaction.thread.lock().is_none());
        assert!(!block_store.authority_compaction.running.load(Ordering::SeqCst));
        assert!(block_store.authority_compaction.stop.load(Ordering::SeqCst));
        // Stopped: nothing starts, and stopping again is a no-op.
        assert!(block_store.compact_authorities());
        block_store.stop_background_work();
        assert!(!block_store.authority_compaction.running.load(Ordering::SeqCst));
    }

    /// Ensures every open starts exactly one authority compaction, and that an open after a stopped
    /// one compacts every slice again.
    #[cfg(feature = "rocks")]
    #[test]
    fn test_open_starts_authority_compaction_rocksdb() {
        let temp_dir = Arc::new(tempfile::tempdir().unwrap());
        let storage_mode = StorageMode::new_test(Some(temp_dir));
        let compactions = || AUTHORITY_COMPACTIONS.with(|count| count.get());
        let slices = || AUTHORITY_SLICES_COMPACTED.with(|count| count.get());
        let total = AUTHORITY_COMPACTION_SLICES;

        // This open's compaction is stopped after one slice.
        let (compactions_before, slices_before) = (compactions(), slices());
        AUTHORITY_COMPACTION_STOP_AFTER.with(|n| n.set(Some(slices_before + 1)));
        let block_store = BlockStore::<CurrentNetwork, BlockDB<_>>::open(storage_mode.clone()).unwrap();
        AUTHORITY_COMPACTION_STOP_AFTER.with(|n| n.set(None));
        assert_eq!((compactions(), slices()), (compactions_before + 1, slices_before + 1));
        drop(block_store);

        let _block_store = BlockStore::<CurrentNetwork, BlockDB<_>>::open(storage_mode).unwrap();
        assert_eq!((compactions(), slices()), (compactions_before + 2, slices_before + 1 + total));
    }

    /// Ensures in-memory storage, which has nothing to compact, starts no compaction.
    #[test]
    fn test_memory_storage_starts_no_authority_compaction() {
        let compactions = || AUTHORITY_COMPACTIONS.with(|count| count.get());
        let before = compactions();
        let block_store = BlockStore::<CurrentNetwork, BlockMemory<_>>::open(StorageMode::new_test(None)).unwrap();
        assert!(!block_store.compact_authorities());
        assert_eq!(compactions(), before);
        block_store.stop_background_work();
    }

    /// Checks that insert-time pruning compacts the authority map once per
    /// `AUTHORITY_COMPACTION_INTERVAL_BLOCKS` pruned authorities, if the storage compacts at all.
    fn check_insert_time_pruning_compacts_after_interval<B: BlockStorage<CurrentNetwork>>(
        block_store: BlockStore<CurrentNetwork, B>,
    ) {
        let rng = &mut TestRng::default();
        let blocks = sample_block_chain(AUTHORITY_RETENTION_BLOCKS + AUTHORITY_COMPACTION_INTERVAL_BLOCKS + 1, rng);
        let compactions = || AUTHORITY_COMPACTIONS.with(|count| count.get());
        let before = compactions();
        let trigger = AUTHORITY_RETENTION_BLOCKS + AUTHORITY_COMPACTION_INTERVAL_BLOCKS - 1;
        let compacts = block_store.storage.compacts_authority_map();
        for block in &blocks {
            block_store.insert(block).unwrap();
            let expected = before + usize::from(compacts && block.height() >= trigger);
            assert_eq!(compactions(), expected, "at block {}", block.height());
        }
    }

    /// Ensures insert-time pruning compacts the authority map after the interval with RocksDB storage.
    #[cfg(feature = "rocks")]
    #[test]
    fn test_insert_time_pruning_compacts_after_interval_rocksdb() {
        let temp_dir = Arc::new(tempfile::tempdir().unwrap());
        check_insert_time_pruning_compacts_after_interval(
            BlockStore::<CurrentNetwork, BlockDB<_>>::open(StorageMode::new_test(Some(temp_dir))).unwrap(),
        );
    }

    /// Ensures in-memory storage, which has nothing to compact, never starts one.
    #[test]
    fn test_insert_time_pruning_compacts_after_interval_memory() {
        check_insert_time_pruning_compacts_after_interval(
            BlockStore::<CurrentNetwork, BlockMemory<_>>::open(StorageMode::new_test(None)).unwrap(),
        );
    }
}
