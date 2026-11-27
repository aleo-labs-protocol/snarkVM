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

//! Compaction of the certificate and authority maps after pruning, on a background thread.

use super::*;

use crate::helpers::Progress;
use anyhow::anyhow;
use std::{
    sync::{
        Weak,
        atomic::{AtomicBool, AtomicU32, Ordering},
    },
    time::{Duration, Instant},
};
use tracing::error;

/// The advance of the watermark, in heights, after which a map is compacted again. Unit tests use a
/// few blocks.
const AUTHORITY_COMPACTION_INTERVAL_BLOCKS: u32 = if cfg!(test) { 8 } else { 100_000 };

/// The least time between two starts of the compaction, which is also how soon a failed run is
/// retried. It is not persisted: a restart resumes at once.
const AUTHORITY_COMPACTION_MIN_INTERVAL: Duration = Duration::from_secs(60 * 60);

/// The most slices a stored run can have: no storage compacts in more.
const MAX_STORED_SLICES: u16 = 256;
#[cfg(feature = "rocks")]
const _: () = assert!(MAX_STORED_SLICES as usize == crate::helpers::rocksdb::MAX_COMPACTION_SLICES);

/// The progress of the authority map compaction, stored under
/// [`BlockMetadataKey::AuthorityCompaction`] as its four fields in little-endian order.
///
/// It is advisory. The compaction thread writes it outside any batch, and no read of the ledger
/// depends on it: a lost or unreadable value costs one more run. It never claims more than was
/// compacted, because the cursor moves only after a slice passed its check, and every deletion
/// below `target` was written before the run started.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct AuthorityCompaction {
    /// The watermark at the start of the last run that finished; 0 if none did.
    compacted_below: u32,
    /// The watermark at the start of the run in progress.
    target: u32,
    /// The number of slices of the run in progress; 0 if none is. With `next` it bounds a key
    /// range, so it stays valid when the map's files change.
    slices: u16,
    /// The next slice of the run in progress.
    next: u16,
}

impl AuthorityCompaction {
    fn to_bytes(self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(12);
        bytes.extend_from_slice(&self.compacted_below.to_le_bytes());
        bytes.extend_from_slice(&self.target.to_le_bytes());
        bytes.extend_from_slice(&self.slices.to_le_bytes());
        bytes.extend_from_slice(&self.next.to_le_bytes());
        bytes
    }

    /// Decodes a stored value. `None` if it is malformed or names a height above `watermark`.
    fn from_bytes(bytes: &[u8], watermark: u32) -> Option<Self> {
        let (compacted_below, rest) = bytes.split_first_chunk::<4>()?;
        let (target, rest) = rest.split_first_chunk::<4>()?;
        let (slices, rest) = rest.split_first_chunk::<2>()?;
        let next = <[u8; 2]>::try_from(rest).ok()?;
        let state = Self {
            compacted_below: u32::from_le_bytes(*compacted_below),
            target: u32::from_le_bytes(*target),
            slices: u16::from_le_bytes(*slices),
            next: u16::from_le_bytes(next),
        };
        let valid = state.next <= state.slices
            && state.slices <= MAX_STORED_SLICES
            && state.compacted_below <= watermark
            && state.target <= watermark;
        valid.then_some(state)
    }

    /// Reads the state of a store whose watermark is `watermark`. A missing or unreadable value
    /// reads as never compacted.
    fn read<N: Network, B: BlockStorage<N>>(storage: &B, watermark: u32) -> Self {
        let Some(bytes) = compaction_state_bytes(storage, BlockMetadataKey::AuthorityCompaction) else {
            return Self::default();
        };
        Self::from_bytes(&bytes, watermark).unwrap_or_else(|| {
            debug!("Ignoring the malformed authority compaction state {bytes:?}");
            Self::default()
        })
    }

    /// The watermark from which a run is due: any, while a run is unfinished.
    fn due_at(&self) -> u32 {
        if self.slices > 0 { 0 } else { self.compacted_below.saturating_add(AUTHORITY_COMPACTION_INTERVAL_BLOCKS) }
    }

    /// The value of [`Signal::due_at`] for this state on a store whose watermark is `watermark`.
    fn insert_trigger(&self, watermark: u32) -> u32 {
        let due_at = self.due_at();
        if watermark >= due_at { 0 } else { due_at }
    }
}

/// Reads the value of a compaction key. A failed read counts as no value: the state is advisory.
fn compaction_state_bytes<N: Network, B: BlockStorage<N>>(storage: &B, key: BlockMetadataKey) -> Option<Vec<u8>> {
    match storage.block_metadata_map().get_confirmed(&key) {
        Ok(bytes) => bytes.map(Cow::into_owned),
        Err(error) => {
            debug!("Ignoring the unreadable compaction state {key:?}: {error}");
            None
        }
    }
}

/// Returns the watermark the certificate map was last compacted at, on a store whose watermark is
/// `watermark`: 0 if it never was, or if the stored value is unreadable.
fn certificate_compacted_below<N: Network, B: BlockStorage<N>>(storage: &B, watermark: u32) -> u32 {
    let Some(bytes) = compaction_state_bytes(storage, BlockMetadataKey::CertificateCompaction) else {
        return 0;
    };
    match <[u8; 4]>::try_from(bytes.as_slice()).map(u32::from_le_bytes) {
        Ok(below) if below <= watermark => below,
        _ => {
            debug!("Ignoring the malformed certificate compaction state {bytes:?}");
            0
        }
    }
}

/// Returns whether the certificate map is due for a compaction after a startup pass that removed
/// the rows below `below`: pruning has advanced an interval since the last finished compaction, or
/// the `retention` window if that is shorter. What the pass removed does not decide it, so a
/// compaction that was killed runs again. The window caps the interval so that a pass that removed
/// more rows than it kept, and so rewrote slices, is followed by the compaction that clears their
/// old copies.
fn certificate_compaction_due<N: Network, B: BlockStorage<N>>(storage: &B, below: u32, retention: u32) -> bool {
    below - certificate_compacted_below(storage, below) >= AUTHORITY_COMPACTION_INTERVAL_BLOCKS.min(retention)
}

/// Compacts the certificate map after a startup pass that removed the rows below `below`, so the
/// next pass reads only live rows, and records `below` once the compaction has finished. RocksDB
/// cannot interrupt the compaction, so a stop waits for it.
fn compact_certificate_map<N: Network, B: BlockStorage<N>>(
    storage: &B,
    below: u32,
    #[cfg(test)] gate: Option<&Gate>,
) -> Result<()> {
    let compacted_below = certificate_compacted_below(storage, below);
    #[cfg(test)]
    CERTIFICATE_COMPACTIONS.with(|count| count.set(count.get() + 1));
    info!("Compacting the certificate map; this can take a while");
    let timer = Instant::now();
    let errors_before = storage.background_error_count();
    storage.compact_certificate_map()?;
    let failed = job_failed(
        storage,
        errors_before,
        #[cfg(test)]
        gate,
    );
    // After a failed compaction this rewrites the unchanged value, as a probe.
    let recorded = if failed { compacted_below } else { below };
    put_compaction_state(
        storage,
        BlockMetadataKey::CertificateCompaction,
        recorded.to_le_bytes().to_vec(),
        #[cfg(test)]
        gate,
    )?;
    if failed {
        return Err(job_failure(storage, format_args!("the certificate map compaction"), "The next start retries it."));
    }
    info!("Compacted the certificate map in {:.1} s", timer.elapsed().as_secs_f64());
    Ok(())
}

/// Writes the value of a compaction key. The write doubles as a probe: after a failed flush or
/// compaction RocksDB can refuse every write until the process restarts, and a failed flush can
/// stop the store without raising [`BlockStorage::background_error_count`].
fn put_compaction_state<N: Network, B: BlockStorage<N>>(
    storage: &B,
    key: BlockMetadataKey,
    value: Vec<u8>,
    #[cfg(test)] gate: Option<&Gate>,
) -> Result<()> {
    let refused = |error: anyhow::Error| {
        anyhow!("The ledger store refuses writes after a storage error: {error:#}. Restart the node.")
    };
    #[cfg(test)]
    if gate.is_some_and(|gate| gate.fail_put.swap(false, Ordering::SeqCst)) {
        return Err(refused(anyhow!("injected")));
    }
    storage.put_compaction_state(key, value).map_err(refused)
}

/// Returns whether a background job of the storage failed since it counted `errors_before` of
/// them. RocksDB returns no error from a compaction call, so this is how a failed one shows.
fn job_failed<N: Network, B: BlockStorage<N>>(
    storage: &B,
    errors_before: u64,
    #[cfg(test)] gate: Option<&Gate>,
) -> bool {
    #[cfg(test)]
    if gate.is_some_and(|gate| gate.fail_job.swap(false, Ordering::SeqCst)) {
        return true;
    }
    storage.background_error_count() > errors_before
}

/// The error for a compaction step during which a background job failed.
fn job_failure<N: Network, B: BlockStorage<N>>(storage: &B, step: std::fmt::Arguments, retry: &str) -> anyhow::Error {
    match storage.background_error() {
        Some(error) => anyhow!("A RocksDB background job failed during {step}: {error}. {retry}"),
        None => anyhow!("A RocksDB background job failed during {step}; see the RocksDB LOG. {retry}"),
    }
}

/// Returns whether the compaction thread must stop: `signal` says so, or every store sharing
/// `state` is gone. The thread must not upgrade `state`: holding the last strong reference would
/// run the state's drop, and its join, on the thread.
fn stopping(signal: &Signal, state: &Weak<CompactionState>) -> bool {
    signal.stop.load(Ordering::SeqCst) || state.strong_count() == 0
}

/// The work of the compaction thread: the certificate map, if a startup pass below
/// `certificate_below` left it due, then the authority map. A failure ends it.
fn compact<N: Network, B: BlockStorage<N>>(
    storage: &B,
    signal: &Signal,
    state: &Weak<CompactionState>,
    certificate_below: Option<u32>,
    #[cfg(test)] gate: Option<Arc<Gate>>,
) -> Result<()> {
    if let Some(below) = certificate_below
        && !stopping(signal, state)
    {
        #[cfg(test)]
        if let Some(gate) = &gate {
            gate.hold_certificate_compaction(|| stopping(signal, state));
        }
        compact_certificate_map(
            storage,
            below,
            #[cfg(test)]
            gate.as_deref(),
        )
        .context("Failed to compact the certificate map")?;
    }
    compact_authority_slices(
        storage,
        signal,
        state,
        #[cfg(test)]
        gate,
    )
    .context("Failed to compact the authority map")
}

/// Compacts the authority map slice by slice (see [`BlockStorage::compact_authority_slice`]) if a
/// run is due: one is unfinished, or the watermark is an interval past the last finished run's.
/// The cursor is stored after each slice, so the next start resumes a run that was stopped or
/// killed. Stops between slices once `signal` says so or every store sharing `state` is gone, and
/// at the first slice that fails, which leaves the run due.
fn compact_authority_slices<N: Network, B: BlockStorage<N>>(
    storage: &B,
    signal: &Signal,
    state: &Weak<CompactionState>,
    #[cfg(test)] gate: Option<Arc<Gate>>,
) -> Result<()> {
    const KEY: BlockMetadataKey = BlockMetadataKey::AuthorityCompaction;
    let Some(watermark) = storage.confirmed_authority_pruned_below()? else {
        return Ok(());
    };
    let mut run = AuthorityCompaction::read(storage, watermark);
    // The inserts must see what this thread decides: nothing due until the watermark gets there,
    // or a run that is due until it has finished, whatever ends this attempt.
    let due_at = run.insert_trigger(watermark);
    signal.due_at.store(due_at, Ordering::SeqCst);
    if due_at > 0 || stopping(signal, state) {
        return Ok(());
    }
    if run.slices == 0 {
        let slices = storage.authority_compaction_slices();
        #[cfg(test)]
        let slices = match gate.as_deref().is_some_and(|gate| gate.fail_flush.swap(false, Ordering::SeqCst)) {
            true => Err(anyhow!("injected flush failure")),
            false => slices,
        };
        let slices = match slices {
            Ok(slices) => u16::try_from(slices)?,
            Err(error) => {
                // The count flushes, and a failed flush can stop the store: the write says so if it did.
                put_compaction_state(
                    storage,
                    KEY,
                    run.to_bytes(),
                    #[cfg(test)]
                    gate.as_deref(),
                )?;
                return Err(error);
            }
        };
        run = AuthorityCompaction { target: watermark, slices, next: 0, ..run };
        put_compaction_state(
            storage,
            KEY,
            run.to_bytes(),
            #[cfg(test)]
            gate.as_deref(),
        )?;
    }
    // A run that was killed after its last slice has none left, and is only recorded as finished.
    let (total, to_compact) = (run.slices, usize::from(run.slices - run.next));
    if to_compact > 0 {
        info!("Compacting {to_compact} of {total} authority slices; this can take a while");
    }
    let mut progress = Progress::new(to_compact);
    for i in run.next..total {
        #[cfg(test)]
        if let Some(gate) = &gate {
            gate.wait(|| stopping(signal, state));
        }
        if stopping(signal, state) {
            info!("Stopped the authority map compaction before slice {i} of {total}; the next start resumes there");
            return Ok(());
        }
        let errors_before = storage.background_error_count();
        storage.compact_authority_slice(usize::from(i), usize::from(total))?;
        let failed = job_failed(
            storage,
            errors_before,
            #[cfg(test)]
            gate.as_deref(),
        );
        if !failed {
            run.next = i + 1;
        }
        // After a failed slice this rewrites the unchanged cursor, as a probe.
        put_compaction_state(
            storage,
            KEY,
            run.to_bytes(),
            #[cfg(test)]
            gate.as_deref(),
        )?;
        if failed {
            let retry = format!(
                "The compaction retries within {} min or at the next start.",
                AUTHORITY_COMPACTION_MIN_INTERVAL.as_secs() / 60
            );
            return Err(job_failure(storage, format_args!("authority slice {i} of {total}"), &retry));
        }
        #[cfg(test)]
        if let Some(gate) = &gate {
            gate.compacted.fetch_add(1, Ordering::SeqCst);
        }
        if let Some((elapsed, remaining)) = progress.advance() {
            info!(
                "Compacted {} of {to_compact} authority slices in {elapsed:.0} s, about {remaining:.0} s left",
                progress.done()
            );
        }
    }
    let finished = AuthorityCompaction { compacted_below: run.target, ..Default::default() };
    put_compaction_state(
        storage,
        KEY,
        finished.to_bytes(),
        #[cfg(test)]
        gate.as_deref(),
    )?;
    // The watermark read at the start decides whether the next run is due already. An insert that
    // has moved the watermark since then compares equal to it.
    signal.due_at.store(finished.insert_trigger(watermark), Ordering::SeqCst);
    if to_compact > 0 {
        info!("Compacted {to_compact} of {total} authority slices in {:.1} s", progress.elapsed_secs());
    }
    Ok(())
}

/// What the compaction thread shares with the stores.
#[derive(Default)]
struct Signal {
    /// Set at shutdown, so no compaction starts and the running one stops after its current step.
    stop: AtomicBool,
    /// What an insert compares the watermark it leaves with: 0 while a run is due, else the
    /// watermark from which the next one is. See [`AuthorityCompaction::insert_trigger`].
    due_at: AtomicU32,
}

/// The state of the background compaction, shared by the clones of a [`BlockStore`];
/// the compaction thread holds only its [`Signal`] and a weak reference.
#[derive(Default)]
pub(super) struct CompactionState {
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
    /// Stops the compaction, if one runs, and waits for it: the running authority slice or
    /// certificate map compaction finishes, then the thread is joined.
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
            info!("Waited {:.1} s for the background compaction to finish its step", timer.elapsed().as_secs_f64());
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
    /// At the open of a store that prunes with `retention`, after startup pruning: reads the stored
    /// compaction state, sets from it the watermark at which an insert starts a compaction, and
    /// starts one now if either map is due. Only this start compacts the certificate map, whose
    /// rows only the startup pass removes.
    pub(super) fn start_due_compaction(&self, retention: u32) -> Result<()> {
        if !self.storage.compacts_authority_map() {
            return Ok(());
        }
        let signal = &self.authority_compaction.signal;
        let Some(watermark) = self.authority_pruned_below()? else {
            signal.due_at.store(AuthorityCompaction::default().due_at(), Ordering::SeqCst);
            return Ok(());
        };
        // A run that is due stays due for the inserts if this start fails or does not finish it.
        let due_at = AuthorityCompaction::read(&self.storage, watermark).insert_trigger(watermark);
        signal.due_at.store(due_at, Ordering::SeqCst);
        // The startup pass removed the certificate rows below the watermark.
        let certificate_below = certificate_compaction_due(&self.storage, watermark, retention).then_some(watermark);
        if due_at == 0 || certificate_below.is_some() {
            self.start_compaction(certificate_below);
        }
        Ok(())
    }

    /// Starts a compaction if a run is due already, or the insert of the block at `height` has
    /// advanced the watermark to where one is. A due run that cannot start now, or that fails, stays
    /// due, so each later insert tries again; [`AUTHORITY_COMPACTION_MIN_INTERVAL`] spaces the starts.
    pub(super) fn compact_if_due(&self, height: u32) {
        let Some(retention) = self.authority_retention else {
            return;
        };
        if !self.storage.compacts_authority_map() {
            return;
        }
        let due_at = self.authority_compaction.signal.due_at.load(Ordering::SeqCst);
        // An insert up to the retention height prunes nothing: the one at that height expires
        // genesis, which is never pruned. A later one leaves this watermark, unless the stored one
        // is ahead already, after a rollback or a reopen with a larger window; then it prunes
        // nothing either, and only a run that was due before it is due.
        let advanced_to = || height > retention && oldest_retained_authority_height(height, retention) >= due_at;
        if due_at == 0 || advanced_to() {
            self.start_compaction(None);
        }
    }

    /// Starts a compaction (see [`compact`]) on a background thread if this store prunes, unless one
    /// runs, the floor applies, or the store is stopping; returns whether one started. A panic on
    /// the thread aborts the process.
    pub(super) fn start_compaction(&self, certificate_below: Option<u32>) -> bool {
        if self.authority_retention.is_none() || !self.storage.compacts_authority_map() {
            return false;
        }
        let compaction = &self.authority_compaction;
        let signal = compaction.signal.clone();
        // One lock covers the checks, the spawn and the handle, so a concurrent stop cannot miss
        // the thread.
        let mut last = compaction.last.lock();
        let floor = last.started.is_some_and(|started| started.elapsed() < AUTHORITY_COMPACTION_MIN_INTERVAL);
        if signal.stop.load(Ordering::SeqCst) || last.running() || floor {
            return false;
        }
        #[cfg(test)]
        let gate = AUTHORITY_COMPACTION_GATE.with(|gate| gate.borrow().clone());
        #[cfg(test)]
        let inline = gate.is_none();
        let (storage, state) = (self.storage.clone(), Arc::downgrade(compaction));
        let compact = move || {
            let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                compact(
                    &storage,
                    &signal,
                    &state,
                    certificate_below,
                    #[cfg(test)]
                    gate,
                )
            }));
            match result {
                Ok(Ok(())) => {}
                Ok(Err(error)) => error!("{error:#}"),
                Err(_) => {
                    error!("The background compaction panicked");
                    std::process::abort();
                }
            }
        };
        last.started = Some(Instant::now());
        #[cfg(test)]
        {
            AUTHORITY_COMPACTIONS.with(|count| count.set(count.get() + 1));
            if inline {
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
                error!("Failed to start the background compaction: {error}");
                last.started = None;
                false
            }
        }
    }

    /// Stops the background compaction; see `CompactionState::stop_and_join`.
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
    /// The slices compacted and recorded.
    compacted: std::sync::atomic::AtomicUsize,
    /// Makes the next check of a compaction step find a failed background job.
    fail_job: AtomicBool,
    /// Makes the next write of the compaction state fail.
    fail_put: AtomicBool,
    /// Makes the next slice count, which flushes the database, fail.
    fail_flush: AtomicBool,
    /// 1 holds the certificate map compaction back until a stop is requested, as a compaction that
    /// is running when the request arrives; 2 says that it is being held.
    hold_certificate: std::sync::atomic::AtomicUsize,
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

    #[cfg(feature = "rocks")]
    fn compacted(&self) -> usize {
        self.compacted.load(Ordering::SeqCst)
    }

    fn hold_certificate_compaction(&self, stopping: impl Fn() -> bool) {
        if self.hold_certificate.compare_exchange(1, 2, Ordering::SeqCst, Ordering::SeqCst).is_ok() {
            while !stopping() {
                std::thread::sleep(Duration::from_millis(1));
            }
        }
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
    /// The number of certificate map compactions started on this thread.
    static CERTIFICATE_COMPACTIONS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
    /// The number of compactions started on this thread.
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

    /// Ensures pruning in-memory storage, which has nothing to compact, starts no compaction.
    #[test]
    fn test_memory_storage_compacts_nothing() {
        let store = open_pruning::<BlockMemory<_>>(StorageMode::new_test(None));
        assert!(!store.start_compaction(None));
        let rng = &mut TestRng::default();
        let before = compactions();
        for block in &sample_block_chain(TEST_RETENTION + AUTHORITY_COMPACTION_INTERVAL_BLOCKS + 2, rng) {
            insert(&store, block, false);
        }
        assert_eq!(compactions(), before);
    }

    /// Ensures the stored compaction state keeps its encoding, and that every value a run could not
    /// have written decodes as no state.
    #[test]
    fn test_authority_compaction_state_encoding() {
        let state =
            AuthorityCompaction { compacted_below: 0x0102_0304, target: 0x0506_0708, slices: 0x0100, next: 0x000f };
        let bytes = state.to_bytes();
        assert_eq!(bytes, [4, 3, 2, 1, 8, 7, 6, 5, 0, 1, 0x0f, 0]);
        assert_eq!(AuthorityCompaction::from_bytes(&bytes, state.target), Some(state));

        // Short, long, a cursor past its run, too many slices, and heights above the watermark.
        assert_eq!(AuthorityCompaction::from_bytes(&bytes[..11], u32::MAX), None);
        assert_eq!(AuthorityCompaction::from_bytes(&[&bytes[..], &[0]].concat(), u32::MAX), None);
        let decode =
            |state: AuthorityCompaction, watermark| AuthorityCompaction::from_bytes(&state.to_bytes(), watermark);
        assert_eq!(decode(AuthorityCompaction { slices: 4, next: 5, ..state }, u32::MAX), None);
        assert_eq!(decode(AuthorityCompaction { slices: MAX_STORED_SLICES + 1, ..state }, u32::MAX), None);
        assert_eq!(decode(state, state.target - 1), None);
        assert_eq!(decode(AuthorityCompaction { compacted_below: state.target + 1, ..state }, state.target), None);
        // A finished run with nothing in progress, and a run whose last slice is done.
        let finished = AuthorityCompaction { compacted_below: 9, ..Default::default() };
        assert_eq!(decode(finished, 9), Some(finished));
        assert_eq!(decode(AuthorityCompaction { next: state.slices, ..state }, u32::MAX).map(|s| s.next), Some(0x0100));

        assert_eq!(AuthorityCompaction::default().due_at(), AUTHORITY_COMPACTION_INTERVAL_BLOCKS);
        assert_eq!(finished.due_at(), 9 + AUTHORITY_COMPACTION_INTERVAL_BLOCKS);
        assert_eq!(state.due_at(), 0);
    }

    #[cfg(feature = "rocks")]
    mod rocks {
        use super::*;
        use crate::helpers::rocksdb::{BlockDB, BlockMap, DataMap, Database, MapID, RocksDB};

        type Store = BlockStore<CurrentNetwork, BlockDB<CurrentNetwork>>;

        const KEY: BlockMetadataKey = BlockMetadataKey::AuthorityCompaction;
        const CERTIFICATE_KEY: BlockMetadataKey = BlockMetadataKey::CertificateCompaction;

        /// The lowest watermark at which a store that never compacted is due.
        const DUE: u32 = AUTHORITY_COMPACTION_INTERVAL_BLOCKS;

        /// The number of slices a unit test's run has.
        const SLICES: u16 = 4;

        /// The height whose insert makes a store opened empty due.
        const TRIGGER: u32 = TEST_RETENTION + DUE - 1;

        fn sample_chain() -> Vec<Block<CurrentNetwork>> {
            sample_block_chain(TRIGGER + 3, &mut TestRng::default())
        }

        /// A new, empty test storage.
        fn new_storage() -> StorageMode {
            StorageMode::new_test(Some(Arc::new(tempfile::tempdir().unwrap())))
        }

        /// A new test storage that has pruned up to `watermark`. With `state`, it has compacted
        /// before: `state` is its authority compaction state, and its certificate map is compacted
        /// at `watermark`.
        fn new_pruned_storage(watermark: u32, state: Option<AuthorityCompaction>) -> StorageMode {
            let storage_mode = new_storage();
            let storage = BlockDB::<CurrentNetwork>::open(storage_mode.clone()).unwrap();
            atomic_batch_scope!(storage, { set_authority_pruned_below(&storage, watermark) }).unwrap();
            if let Some(state) = state {
                storage.put_compaction_state(KEY, state.to_bytes()).unwrap();
                storage.put_compaction_state(CERTIFICATE_KEY, watermark.to_le_bytes().to_vec()).unwrap();
            }
            storage_mode
        }

        /// Opens a store on `storage_mode` that prunes with `retention`.
        fn open_with(storage_mode: &StorageMode, retention: Option<u32>) -> Store {
            BlockStore::open_with_authority_retention(storage_mode.clone(), retention).unwrap()
        }

        /// Opens an empty store that prunes with [`TEST_RETENTION`] if `prunes`.
        fn open(prunes: bool) -> Store {
            open_with(&new_storage(), prunes.then_some(TEST_RETENTION))
        }

        /// The state a run stores when it finishes with `compacted_below` as its target.
        fn finished(compacted_below: u32) -> AuthorityCompaction {
            AuthorityCompaction { compacted_below, ..Default::default() }
        }

        /// The state the first run of a store that is due at [`DUE`] stores with `next` slices done.
        fn cursor(next: u16) -> AuthorityCompaction {
            AuthorityCompaction { target: DUE, slices: SLICES, next, ..Default::default() }
        }

        /// The stored compaction state.
        fn stored(store: &Store) -> AuthorityCompaction {
            AuthorityCompaction::read(&store.storage, u32::MAX)
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

        /// Waits until `done` holds; a compaction thread makes it so.
        fn wait_until(done: impl Fn() -> bool) {
            let timer = Instant::now();
            while !done() {
                assert!(timer.elapsed() < Duration::from_secs(10), "The compaction thread made no progress");
                std::thread::sleep(Duration::from_millis(1));
            }
        }

        /// Waits for the store's compaction thread to end.
        fn wait_finished(store: &Store) {
            wait_until(|| !thread_running(store));
        }

        /// Runs `start` with any compaction it starts on a thread that `gate` controls.
        fn gated<T>(gate: &Arc<Gate>, start: impl FnOnce() -> T) -> T {
            AUTHORITY_COMPACTION_GATE.with(|slot| *slot.borrow_mut() = Some(gate.clone()));
            let result = start();
            AUTHORITY_COMPACTION_GATE.with(|slot| *slot.borrow_mut() = None);
            result
        }

        /// Runs `open` with any compaction it starts on a thread the returned gate controls; the
        /// thread waits before its first slice.
        fn with_gate(open: impl FnOnce() -> Store) -> (Store, Arc<Gate>) {
            let gate = Arc::new(Gate::default());
            let store = gated(&gate, open);
            (store, gate)
        }

        /// Opens a pruning store on `storage_mode`, with the compaction that is due at open on a
        /// gated thread.
        fn open_with_gate(storage_mode: &StorageMode) -> (Store, Arc<Gate>) {
            let (store, gate) = with_gate(|| open_with(storage_mode, Some(TEST_RETENTION)));
            assert!(thread_running(&store));
            (store, gate)
        }

        /// Opens a pruning store that is due for its first compaction, as [`open_with_gate`] does.
        fn open_due_with_gate() -> (Store, Arc<Gate>) {
            open_with_gate(&new_pruned_storage(DUE, None))
        }

        /// Releases `slices` more slices and waits until they are compacted and recorded.
        fn compact_slices(gate: &Gate, slices: usize) {
            let target = gate.compacted() + slices;
            gate.release(slices);
            wait_until(|| gate.compacted() >= target);
        }

        /// Ensures the real thread path starts at open, stops on request, and is not restarted.
        #[test]
        fn test_authority_compaction_thread_stops() {
            let (store, gate) = open_due_with_gate();
            let before = running_joins();
            store.stop_background_work();
            assert_eq!(running_joins(), before + 1);
            assert_eq!(gate.passed(), 0);
            assert!(store.authority_compaction.last.lock().thread.is_none());
            clear_floor(&store);
            assert!(!store.start_compaction(None));
        }

        /// Ensures dropping the last store, while the thread waits between slices, stops and joins
        /// the thread on the dropping thread.
        #[test]
        fn test_dropping_the_store_stops_the_thread() {
            let (store, gate) = open_due_with_gate();
            compact_slices(&gate, 1);
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
            let storage = BlockDB::<CurrentNetwork>::open(new_pruned_storage(DUE, None)).unwrap();
            let state = Arc::new(CompactionState::default());
            let gate = Arc::new(Gate::default());
            let worker = {
                let (storage, signal, weak, gate) =
                    (storage.clone(), state.signal.clone(), Arc::downgrade(&state), gate.clone());
                std::thread::spawn(move || compact_authority_slices(&storage, &signal, &weak, Some(gate)))
            };
            compact_slices(&gate, 2);
            state.signal.stop.store(true, Ordering::SeqCst);
            worker.join().unwrap().unwrap();
            assert_eq!(gate.passed(), 2);

            // Every store gone: the run ends before its next slice.
            let weak = Arc::downgrade(&state);
            drop(state);
            let gate = Arc::new(Gate::default());
            gate.release(usize::from(SLICES));
            compact_authority_slices(&storage, &Signal::default(), &weak, Some(gate.clone())).unwrap();
            assert_eq!(gate.passed(), 0);
            assert_eq!(AuthorityCompaction::read(&storage, DUE).next, 2);
        }

        /// Ensures a write of the compaction state lands at once, and stays, whatever becomes of a
        /// block batch that is open or paused meanwhile, as during the VM's block insert.
        #[test]
        fn test_compaction_state_bypasses_block_batches() {
            let store = open(true);
            let blocks = sample_block_chain(2, &mut TestRng::default());
            store.insert(&blocks[0]).unwrap();

            // A batch scope that is open on another thread, then aborted.
            store.storage.start_atomic();
            store.storage.put_compaction_state(KEY, cursor(1).to_bytes()).unwrap();
            assert_eq!(stored(&store), cursor(1));
            store.storage.abort_atomic();
            assert_eq!(stored(&store), cursor(1));

            // A paused batch that holds a block, then is discarded.
            store.pause_atomic_writes().unwrap();
            store.insert_deferring_block_tree(&blocks[1]).unwrap();
            store.storage.put_compaction_state(KEY, cursor(2).to_bytes()).unwrap();
            assert_eq!(stored(&store), cursor(2));
            store.abort_atomic();
            store.discard_prepared_block_tree();
            store.unpause_atomic_writes::<true>().unwrap();
            assert_eq!(stored(&store), cursor(2));
            assert!(store.storage.id_map().get_confirmed(&1).unwrap().is_none());
        }

        /// Ensures an open reads compaction state it cannot use as none, and still opens.
        #[test]
        fn test_open_ignores_malformed_compaction_state() {
            let cursor_past_its_run =
                AuthorityCompaction { target: DUE, slices: SLICES, next: SLICES + 1, ..Default::default() };
            let above_the_watermark = AuthorityCompaction { compacted_below: DUE + 1, ..Default::default() };
            // The empty case stores, instead, a value that is not the stored form of any bytes.
            for bytes in
                [vec![], vec![1, 2, 3], vec![0; 13], cursor_past_its_run.to_bytes(), above_the_watermark.to_bytes()]
            {
                let storage_mode = new_pruned_storage(DUE, None);
                let storage = BlockDB::<CurrentNetwork>::open(storage_mode.clone()).unwrap();
                for key in [KEY, CERTIFICATE_KEY] {
                    if bytes.is_empty() {
                        let map_id = MapID::Block(BlockMap::Metadata);
                        let raw: DataMap<BlockMetadataKey, u8> =
                            RocksDB::open_map(CurrentNetwork::ID, storage_mode.clone(), map_id).unwrap();
                        raw.insert(key, 7).unwrap();
                        assert!(storage.block_metadata_map().get_confirmed(&key).is_err());
                    } else {
                        storage.put_compaction_state(key, bytes.clone()).unwrap();
                    }
                }
                assert_eq!(AuthorityCompaction::read(&storage, DUE), AuthorityCompaction::default(), "{bytes:?}");
                // Read as never compacted, the store is due and compacts.
                let before = compactions();
                let store = open_with(&storage_mode, Some(TEST_RETENTION));
                assert_eq!(compactions(), before + 1, "{bytes:?}");
                assert_eq!(stored(&store), finished(DUE));
            }
        }

        /// Ensures an open starts a compaction thread, and the floor, only if the store prunes and
        /// a run is due: the watermark is an interval past the last finished run's, or a run is
        /// unfinished.
        #[test]
        fn test_open_starts_a_compaction_only_if_due() {
            let unfinished = AuthorityCompaction { compacted_below: DUE, target: DUE + 1, slices: SLICES, next: 1 };
            for (watermark, state, prunes, starts) in [
                // Never compacted.
                (Some(DUE), None, true, true),
                (Some(DUE - 1), None, true, false),
                (None, None, true, false),
                // Compacted before, the certificate map at this watermark.
                (Some(2 * DUE), Some(finished(DUE)), true, true),
                (Some(2 * DUE - 1), Some(finished(DUE)), true, false),
                // An unfinished run resumes whatever the watermark.
                (Some(DUE + 1), Some(unfinished), true, true),
                // A store that does not prune starts nothing.
                (Some(DUE), None, false, false),
                (Some(DUE + 1), Some(unfinished), false, false),
            ] {
                let case = format!("{watermark:?} {state:?} {prunes}");
                let storage_mode = match watermark {
                    Some(watermark) => new_pruned_storage(watermark, state),
                    None => new_storage(),
                };
                let before = compactions();
                let (store, gate) = with_gate(|| open_with(&storage_mode, prunes.then_some(TEST_RETENTION)));
                assert_eq!(compactions(), before + usize::from(starts), "{case}");
                assert_eq!(thread_running(&store), starts, "{case}");
                assert_eq!(store.authority_compaction.last.lock().started.is_some(), starts, "{case}");
                let joins = running_joins();
                store.stop_background_work();
                assert_eq!(running_joins(), joins + usize::from(starts), "{case}");
                // A store that started nothing wrote nothing.
                assert_eq!(gate.passed(), 0);
                if !starts {
                    assert_eq!(stored(&store), state.unwrap_or_default(), "{case}");
                }
            }
        }

        /// Ensures a run compacts every slice of the authority map, which rewrites the files that
        /// hold the slice, and that no deleted row is left in a file once it has finished.
        #[test]
        fn test_run_compacts_every_slice() {
            // The certificate map counts as compacted, so the thread compacts only the slices.
            let storage_mode = new_pruned_storage(DUE, Some(AuthorityCompaction::default()));
            let storage = BlockDB::<CurrentNetwork>::open(storage_mode.clone()).unwrap();
            let database = RocksDB::open(CurrentNetwork::ID, storage_mode.clone()).unwrap();
            // Two rows in each slice, by the first byte of their keys. One is deleted after a flush,
            // so a file holds the deletion.
            let authority = snarkvm_ledger_authority::test_helpers::sample_beacon_authority(&mut TestRng::default());
            let hash = |slice: u16, row: u32| -> <CurrentNetwork as Network>::BlockHash {
                Field::<CurrentNetwork>::from_u32(u32::from(slice) * 0x40 + row).into()
            };
            for slice in 0..SLICES {
                storage.authority_map().insert(hash(slice, 0), authority.clone()).unwrap();
                storage.authority_map().insert(hash(slice, 1), authority.clone()).unwrap();
            }
            database.flush().unwrap();
            for slice in 0..SLICES {
                storage.authority_map().remove(&hash(slice, 1)).unwrap();
            }
            database.flush().unwrap();
            let files = || database.live_files().unwrap();
            let names = || files().into_iter().map(|file| file.name).collect::<Vec<_>>();
            let deletions = || files().iter().map(|file| file.num_deletions).sum::<u64>();
            assert_eq!(deletions(), u64::from(SLICES));

            let (store, gate) = open_with_gate(&storage_mode);
            // The thread stores the run before it waits for its first slice.
            wait_until(|| stored(&store) != AuthorityCompaction::default());
            assert_eq!(stored(&store), cursor(0));
            for slice in 0..SLICES {
                let before = names();
                if slice + 1 < SLICES {
                    compact_slices(&gate, 1);
                    assert_eq!(stored(&store), cursor(slice + 1));
                } else {
                    gate.release(1);
                    wait_finished(&store);
                }
                assert_ne!(names(), before, "slice {slice} was not compacted");
            }
            assert_eq!(gate.compacted(), usize::from(SLICES));
            assert_eq!(stored(&store), finished(DUE));
            assert_eq!(store.authority_compaction.signal.due_at.load(Ordering::SeqCst), 2 * DUE);

            assert_eq!(deletions(), 0);
            assert_eq!(storage.authority_map().len_confirmed(), usize::from(SLICES));
            for slice in 0..SLICES {
                assert!(storage.authority_map().contains_key_confirmed(&hash(slice, 0)).unwrap());
                assert!(!storage.authority_map().contains_key_confirmed(&hash(slice, 1)).unwrap());
            }
        }

        /// Ensures a run that was killed between its last slice and its finished state is recorded
        /// as finished by the next start.
        #[test]
        fn test_run_with_no_slice_left_is_recorded_as_finished() {
            let storage_mode = new_pruned_storage(DUE, Some(cursor(SLICES)));
            let (store, gate) = with_gate(|| open_with(&storage_mode, Some(TEST_RETENTION)));
            wait_finished(&store);
            assert_eq!((stored(&store), gate.passed()), (finished(DUE), 0));
        }

        /// Ensures a run that was stopped resumes at its cursor on the next open, with its own
        /// slice count and target, and that nothing is due once it has finished.
        #[test]
        fn test_stopped_run_resumes_at_the_cursor() {
            let storage_mode = new_pruned_storage(DUE, None);
            let (store, gate) = open_with_gate(&storage_mode);
            compact_slices(&gate, 1);
            store.stop_background_work();
            assert_eq!(stored(&store), cursor(1));
            drop(store);

            // The watermark has moved on; the run keeps its target.
            let storage = BlockDB::<CurrentNetwork>::open(storage_mode.clone()).unwrap();
            atomic_batch_scope!(storage, { set_authority_pruned_below(&storage, DUE + 3) }).unwrap();
            drop(storage);
            let (store, gate) = open_with_gate(&storage_mode);
            gate.release(usize::from(SLICES));
            wait_finished(&store);
            assert_eq!(gate.passed(), usize::from(SLICES) - 1);
            assert_eq!(stored(&store), finished(DUE));
            drop(store);

            let before = compactions();
            let store = open_with(&storage_mode, Some(TEST_RETENTION));
            assert_eq!(compactions(), before);
            assert_eq!(store.authority_compaction.signal.due_at.load(Ordering::SeqCst), 2 * DUE);
        }

        /// Checks that a slice whose check fails ends the run there with an error naming `expected`,
        /// leaving the cursor; that a trigger inside the floor is refused; and that the retry
        /// after the floor starts at the same slice and finishes.
        fn check_failed_slice_stops_the_run(fail: impl Fn(&Gate), expected: &str) {
            let storage_mode = new_pruned_storage(DUE, None);
            let (store, gate) = open_with_gate(&storage_mode);
            compact_slices(&gate, 1);
            fail(&gate);
            gate.release(usize::from(SLICES));
            wait_finished(&store);
            assert_eq!(stored(&store), cursor(1));
            assert_eq!((gate.passed(), gate.compacted()), (2, 1));
            assert_eq!(store.authority_compaction.signal.due_at.load(Ordering::SeqCst), 0);

            // The error says which slice failed and what happens next.
            fail(&gate);
            let (signal, state) = (Signal::default(), Arc::new(CompactionState::default()));
            let error = compact_authority_slices(&store.storage, &signal, &Arc::downgrade(&state), Some(gate.clone()))
                .unwrap_err()
                .to_string();
            assert!(error.contains(expected), "{error}");
            assert_eq!(stored(&store), cursor(1));

            // The run stays due, and the floor holds its retry back.
            assert!(!store.start_compaction(None));
            clear_floor(&store);
            let gate = Arc::new(Gate::default());
            gate.release(usize::from(SLICES));
            assert!(gated(&gate, || store.start_compaction(None)));
            wait_finished(&store);
            assert_eq!(gate.passed(), usize::from(SLICES) - 1);
            assert_eq!(stored(&store), finished(DUE));
        }

        /// Ensures a slice during which a RocksDB background job failed stops the run.
        #[test]
        fn test_failed_background_job_stops_the_run() {
            check_failed_slice_stops_the_run(
                |gate| gate.fail_job.store(true, Ordering::SeqCst),
                "A RocksDB background job failed during authority slice 1 of 4; see the RocksDB LOG. The compaction \
                 retries within 60 min or at the next start.",
            );
        }

        /// Ensures a run whose slice count fails, as when its flush fails, says that the store
        /// refuses writes if it does since, and reports the failure itself if it does not.
        #[test]
        fn test_failed_flush_reports_a_store_that_refuses_writes() {
            let storage = BlockDB::<CurrentNetwork>::open(new_pruned_storage(DUE, None)).unwrap();
            let (signal, state) = (Signal::default(), Arc::new(CompactionState::default()));
            let gate = Arc::new(Gate::default());
            let run = || {
                gate.fail_flush.store(true, Ordering::SeqCst);
                compact_authority_slices(&storage, &signal, &Arc::downgrade(&state), Some(gate.clone()))
                    .unwrap_err()
                    .to_string()
            };
            gate.fail_put.store(true, Ordering::SeqCst);
            assert_eq!(run(), "The ledger store refuses writes after a storage error: injected. Restart the node.");
            assert_eq!(run(), "injected flush failure");
            // Neither attempt stored a run.
            assert_eq!(AuthorityCompaction::read(&storage, DUE), AuthorityCompaction::default());
        }

        /// A storage whose first run is due but has not started, because its trigger fell inside the
        /// floor, and its chain, of which heights `0..=TRIGGER` are inserted. Its certificate map is
        /// recorded as compacted at the watermark if `certificate_compacted`.
        fn new_due_storage(certificate_compacted: bool) -> (StorageMode, Vec<Block<CurrentNetwork>>) {
            let storage_mode = new_storage();
            let blocks = sample_chain();
            let store = open_with(&storage_mode, Some(TEST_RETENTION));
            store.authority_compaction.last.lock().started = Some(Instant::now());
            let before = compactions();
            for block in &blocks[..=TRIGGER as usize] {
                store.insert(block).unwrap();
            }
            assert_eq!((compactions(), stored(&store)), (before, AuthorityCompaction::default()));
            assert_eq!(store.authority_pruned_below().unwrap(), Some(DUE));
            if certificate_compacted {
                store.storage.put_compaction_state(CERTIFICATE_KEY, DUE.to_le_bytes().to_vec()).unwrap();
            }
            drop(store);
            (storage_mode, blocks)
        }

        /// Checks that the first insert after the floor starts the run that is due, although it
        /// prunes nothing and the run has not finished.
        fn check_next_insert_starts_the_run(store: &Store, blocks: &[Block<CurrentNetwork>]) {
            assert_eq!(store.authority_pruned_below().unwrap(), Some(DUE));
            clear_floor(store);
            let before = compactions();
            store.insert(&blocks[TRIGGER as usize + 1]).unwrap();
            assert_eq!((compactions(), stored(store)), (before + 1, finished(DUE)));
            assert_eq!(store.authority_pruned_below().unwrap(), Some(DUE));
        }

        /// Ensures a run that was due at an open and failed is retried by the next insert after the
        /// floor, when a window enlarged at that open, even past the tip, keeps inserts from pruning.
        #[test]
        fn test_failed_run_is_retried_after_enlarging_the_window() {
            for retention in [TEST_RETENTION + 2, TRIGGER + 10] {
                let (storage_mode, blocks) = new_due_storage(true);
                let (store, gate) = with_gate(|| open_with(&storage_mode, Some(retention)));
                compact_slices(&gate, 1);
                gate.fail_job.store(true, Ordering::SeqCst);
                gate.release(usize::from(SLICES));
                wait_finished(&store);
                assert_eq!(stored(&store), cursor(1));
                check_next_insert_starts_the_run(&store, &blocks);
            }
        }

        /// Ensures the run that was due at an open is started by the next insert after the floor
        /// when the certificate map compaction failed first and ended the thread.
        #[test]
        fn test_run_starts_after_a_failed_certificate_compaction() {
            for retention in [TEST_RETENTION + 2, TRIGGER + 10] {
                let (storage_mode, blocks) = new_due_storage(false);
                let gate = Arc::new(Gate::default());
                gate.fail_job.store(true, Ordering::SeqCst);
                gate.release(usize::from(SLICES));
                let store = gated(&gate, || open_with(&storage_mode, Some(retention)));
                wait_finished(&store);
                assert_eq!((stored(&store), gate.passed()), (AuthorityCompaction::default(), 0));
                check_next_insert_starts_the_run(&store, &blocks);
            }
        }

        /// Ensures that once a start has found nothing due, inserts start nothing until the
        /// watermark is where a run is due. Here the stored state is ahead of a store that has not
        /// pruned yet, so the open cannot use it.
        #[test]
        fn test_start_that_finds_nothing_due_is_not_repeated() {
            let storage_mode = new_storage();
            let storage = BlockDB::<CurrentNetwork>::open(storage_mode.clone()).unwrap();
            storage.put_compaction_state(KEY, finished(DUE).to_bytes()).unwrap();
            drop(storage);
            let store = open_with(&storage_mode, Some(TEST_RETENTION));

            let mut starts = Vec::new();
            for block in &sample_block_chain(TRIGGER + DUE + 2, &mut TestRng::default()) {
                clear_floor(&store);
                let before = compactions();
                store.insert(block).unwrap();
                if compactions() > before {
                    starts.push(block.height());
                }
            }
            // The first start finds the stored state valid and nothing due; the second is the run
            // that is due an interval later.
            assert_eq!(starts, [TRIGGER, TRIGGER + DUE]);
            assert_eq!(stored(&store), finished(2 * DUE));
        }

        /// Ensures a store that refuses the cursor write stops the run.
        #[test]
        fn test_refused_cursor_write_stops_the_run() {
            check_failed_slice_stops_the_run(
                |gate| gate.fail_put.store(true, Ordering::SeqCst),
                "The ledger store refuses writes after a storage error: injected. Restart the node.",
            );
        }

        /// Opens a pruning store on `storage_mode` and returns it with the number of certificate map
        /// compactions the open ran.
        fn open_counting_certificate_compactions(storage_mode: &StorageMode) -> (Store, usize) {
            let before = CERTIFICATE_COMPACTIONS.with(|count| count.get());
            let store = open_with(storage_mode, Some(TEST_RETENTION));
            let compactions = CERTIFICATE_COMPACTIONS.with(|count| count.get()) - before;
            (store, compactions)
        }

        /// Ensures the certificate map is compacted only at an open whose watermark is an interval
        /// past the one its last finished compaction recorded, so a node restarted often compacts
        /// at the restart that completes the interval.
        #[test]
        fn test_certificate_compaction_waits_for_the_interval() {
            let storage_mode = new_storage();
            let blocks = sample_chain();
            let mut inserted = 0;
            // Each start finds a few more heights pruned.
            for (watermark, compacts) in [(0, false), (3, false), (6, false), (DUE + 1, true), (DUE + 2, false)] {
                let (store, compactions) = open_counting_certificate_compactions(&storage_mode);
                assert_eq!(compactions, usize::from(compacts), "at watermark {watermark}");
                let recorded = if watermark > DUE { DUE + 1 } else { 0 };
                assert_eq!(certificate_compacted_below(&store.storage, u32::MAX), recorded);
                // The next start's watermark is three heights on.
                let tip = (TEST_RETENTION + watermark + 2).min(TRIGGER + 2) as usize;
                for block in &blocks[inserted..=tip] {
                    store.insert(block).unwrap();
                }
                inserted = tip + 1;
            }

            // A window shorter than the interval takes its place.
            let storage = BlockDB::<CurrentNetwork>::open(new_storage()).unwrap();
            assert!(!certificate_compaction_due(&storage, 3, 4));
            assert!(certificate_compaction_due(&storage, 3, 3));
        }

        /// Ensures the certificate map is compacted on the compaction thread, not by the open, and
        /// that a stop requested meanwhile waits for the compaction, which is then recorded, and
        /// lets nothing start after it.
        #[test]
        fn test_stop_waits_for_the_certificate_compaction() {
            let storage_mode = new_pruned_storage(DUE, None);
            let gate = Arc::new(Gate::default());
            gate.hold_certificate.store(1, Ordering::SeqCst);
            gate.release(usize::from(SLICES));
            let store = gated(&gate, || open_with(&storage_mode, Some(TEST_RETENTION)));
            wait_until(|| gate.hold_certificate.load(Ordering::SeqCst) == 2);
            assert!(thread_running(&store));
            assert_eq!(certificate_compacted_below(&store.storage, DUE), 0);

            let before = running_joins();
            store.stop_background_work();
            assert_eq!(running_joins(), before + 1);
            assert_eq!(certificate_compacted_below(&store.storage, DUE), DUE);
            assert_eq!((stored(&store), gate.passed()), (AuthorityCompaction::default(), 0));
        }

        /// Ensures a certificate map compaction during which a background job failed is not
        /// recorded, ends the thread before the authority map, and runs again at the next open.
        #[test]
        fn test_failed_certificate_compaction_is_retried() {
            let storage_mode = new_pruned_storage(DUE, None);
            let gate = Arc::new(Gate::default());
            gate.fail_job.store(true, Ordering::SeqCst);
            gate.release(usize::from(SLICES));
            let store = gated(&gate, || open_with(&storage_mode, Some(TEST_RETENTION)));
            wait_finished(&store);
            assert_eq!(certificate_compacted_below(&store.storage, DUE), 0);
            assert_eq!((stored(&store), gate.passed()), (AuthorityCompaction::default(), 0));

            gate.fail_job.store(true, Ordering::SeqCst);
            let error = compact_certificate_map(&store.storage, DUE, Some(&gate)).unwrap_err().to_string();
            let expected = "A RocksDB background job failed during the certificate map compaction; see the RocksDB \
                            LOG. The next start retries it.";
            assert_eq!(error, expected);
            drop(store);

            let (store, compactions) = open_counting_certificate_compactions(&storage_mode);
            assert_eq!(compactions, 1);
            assert_eq!(certificate_compacted_below(&store.storage, DUE), DUE);
        }

        /// Ensures the certificate map is compacted whether or not the startup pass removed rows,
        /// so a compaction that was killed before it was recorded runs again.
        #[test]
        fn test_certificate_compaction_reruns_until_recorded() {
            let storage_mode = new_storage();
            let store = open_with(&storage_mode, Some(TEST_RETENTION));
            for block in &sample_chain() {
                store.insert(block).unwrap();
            }
            let watermark = store.authority_pruned_below().unwrap().unwrap();
            // Inserts prune without compacting the certificate map.
            assert!(store.storage.block_metadata_map().get_confirmed(&CERTIFICATE_KEY).unwrap().is_none());
            drop(store);

            let reopen = || open_counting_certificate_compactions(&storage_mode);
            let (store, compactions) = reopen();
            assert_eq!(compactions, 1);
            assert_eq!(certificate_compacted_below(&store.storage, watermark), watermark);
            drop(store);
            let (store, compactions) = reopen();
            assert_eq!(compactions, 0);

            // A killed compaction leaves the key as it was; the pass has nothing left to remove.
            store.storage.put_compaction_state(CERTIFICATE_KEY, 0u32.to_le_bytes().to_vec()).unwrap();
            drop(store);
            let (store, compactions) = reopen();
            assert_eq!(compactions, 1);
            assert_eq!(certificate_compacted_below(&store.storage, watermark), watermark);
        }

        /// Ensures a secondary instance opened with a retention window, and a primary opened
        /// without one, neither start a compaction nor write its state, on a store that is due.
        /// The primary and the secondary each run in a child process, as a process holds only one
        /// database outside the test storage mode.
        #[test]
        fn test_secondary_does_not_compact() {
            const ROLE: &str = "SNARKVM_COMPACTION_TEST_ROLE";
            const PRIMARY: &str = "SNARKVM_COMPACTION_TEST_PRIMARY";
            const SECONDARY: &str = "SNARKVM_COMPACTION_TEST_SECONDARY";
            let path = |var| std::path::PathBuf::from(std::env::var(var).unwrap());
            let assert_idle = |store: &Store| {
                assert_eq!(store.authority_pruned_below().unwrap(), Some(DUE));
                assert_eq!(compactions(), 0);
                assert!(!thread_running(store));
                for key in [KEY, CERTIFICATE_KEY] {
                    assert!(store.storage.block_metadata_map().get_confirmed(&key).unwrap().is_none());
                }
            };
            match std::env::var(ROLE).as_deref() {
                Ok("primary") => {
                    let storage_mode = StorageMode::Custom(path(PRIMARY), None);
                    let storage = BlockDB::<CurrentNetwork>::open(storage_mode.clone()).unwrap();
                    atomic_batch_scope!(storage, { set_authority_pruned_below(&storage, DUE) }).unwrap();
                    let (primary, _gate) = with_gate(|| open_with(&storage_mode, None));
                    assert_idle(&primary);
                }
                Ok("secondary") => {
                    let storage_mode = StorageMode::Custom(path(PRIMARY), Some(path(SECONDARY)));
                    let (secondary, _gate) = with_gate(|| open_with(&storage_mode, Some(TEST_RETENTION)));
                    assert_eq!(secondary.authority_retention, None);
                    assert_idle(&secondary);
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

        /// Ensures a deferred insert whose batch is discarded triggers nothing.
        #[test]
        fn test_discarded_deferred_insert_triggers_nothing() {
            let store = open(true);
            let blocks = sample_chain();
            for block in &blocks[..TRIGGER as usize] {
                store.insert(block).unwrap();
            }
            let before = compactions();

            // The VM's path for a block that fails to finalize.
            let block = &blocks[TRIGGER as usize];
            store.pause_atomic_writes().unwrap();
            store.insert_deferring_block_tree(block).unwrap();
            store.abort_atomic();
            store.discard_prepared_block_tree();
            store.unpause_atomic_writes::<true>().unwrap();
            assert_eq!(compactions(), before);

            insert(&store, block, true);
            assert_eq!(compactions(), before + 1);
        }

        /// Checks that insert-time pruning on a store opened empty compacts the authority map once
        /// the watermark has advanced an interval, if the store prunes, and that a store that does
        /// not prune never compacts.
        fn check_insert_time_pruning_compacts_after_interval(prunes: bool, deferred: bool) {
            let store = open(prunes);
            let before = compactions();
            for block in &sample_chain() {
                insert(&store, block, deferred);
                let expected = before + usize::from(prunes && block.height() >= TRIGGER);
                assert_eq!(compactions(), expected, "at block {}", block.height());
            }
            assert_eq!(stored(&store), if prunes { finished(DUE) } else { Default::default() });
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

        /// Ensures the pruning progress towards a compaction survives a reopen: the open starts
        /// nothing, and the insert that completes the interval starts the one run.
        #[test]
        fn test_trigger_counts_across_a_reopen() {
            let storage_mode = new_storage();
            let blocks = sample_chain();
            let (first, second) = blocks.split_at(TRIGGER as usize - 3);
            let before = compactions();
            let store = open_with(&storage_mode, Some(TEST_RETENTION));
            for block in first {
                store.insert(block).unwrap();
            }
            drop(store);
            let store = open_with(&storage_mode, Some(TEST_RETENTION));
            assert_eq!(compactions(), before);
            for block in second {
                store.insert(block).unwrap();
                assert_eq!(
                    compactions(),
                    before + usize::from(block.height() >= TRIGGER),
                    "at block {}",
                    block.height()
                );
            }
        }

        /// Ensures inserts that prune nothing trigger nothing: those after a rollback, and those
        /// after a reopen with a larger window.
        #[test]
        fn test_rollback_and_larger_window_trigger_nothing() {
            let storage_mode = new_storage();
            let blocks = sample_chain();
            let store = open_with(&storage_mode, Some(TEST_RETENTION));
            let before = compactions();
            for block in &blocks[..TRIGGER as usize] {
                store.insert(block).unwrap();
            }
            // Reinserting removed blocks leaves the watermark where it was.
            for _ in 0..DUE {
                store.remove_last_n(2).unwrap();
                for block in &blocks[TRIGGER as usize - 2..TRIGGER as usize] {
                    store.insert(block).unwrap();
                }
            }
            assert_eq!(compactions(), before);
            drop(store);

            // With a larger window the same heights expire later.
            let store = open_with(&storage_mode, Some(TEST_RETENTION + 2));
            store.insert(&blocks[TRIGGER as usize]).unwrap();
            store.insert(&blocks[TRIGGER as usize + 1]).unwrap();
            assert_eq!(compactions(), before);
            store.insert(&blocks[TRIGGER as usize + 2]).unwrap();
            assert_eq!(compactions(), before + 1);
        }

        /// Checks that a trigger at the interval fires nothing while `block` holds, and fires on
        /// the next insert once `release` lifts it.
        fn check_trigger_waits(block: impl FnOnce(&Store), release: impl FnOnce(&Store)) {
            let store = open(true);
            let blocks = sample_chain();
            block(&store);

            let before = compactions();
            for block in &blocks[..=TRIGGER as usize] {
                store.insert(block).unwrap();
            }
            assert_eq!(compactions(), before);

            release(&store);
            store.insert(&blocks[TRIGGER as usize + 1]).unwrap();
            assert_eq!(compactions(), before + 1);
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
                    wait_finished(store);
                },
            );
        }
    }
}
