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

#![allow(clippy::type_complexity)]

use super::*;
use crate::helpers::{Map, MapRead};

use snarkvm_utilities::{bytes::unchecked_deserialize, flatten_error};

use core::{fmt, fmt::Debug, hash::Hash, mem};
use indexmap::IndexMap;
use smallvec::SmallVec;
use std::{borrow::Cow, ops::Deref, path::Path, sync::atomic::Ordering, time::Instant};
use tracing::error;

#[derive(Clone)]
pub struct DataMap<K: Serialize + DeserializeOwned, V: Serialize + DeserializeOwned>(
    pub(super) Arc<InnerDataMap<K, V>>,
);

impl<K: Serialize + DeserializeOwned, V: Serialize + DeserializeOwned> Deref for DataMap<K, V> {
    type Target = InnerDataMap<K, V>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

pub struct InnerDataMap<K: Serialize + DeserializeOwned, V: Serialize + DeserializeOwned> {
    pub(super) database: RocksDB,
    pub(super) context: Vec<u8>,
    /// The tracker for whether a database transaction is in progress.
    pub(super) batch_in_progress: AtomicBool,
    /// Owner of the in-progress atomic batch (`0` = none).
    pub(super) atomic_owner: AtomicU64,
    /// The database transaction.
    pub(super) atomic_batch: Mutex<Vec<(K, Option<V>)>>,
    /// The checkpoint stack for the batched operations within the map.
    pub(super) checkpoints: Mutex<Vec<usize>>,
}

impl<K: Serialize + DeserializeOwned, V: Serialize + DeserializeOwned> InnerDataMap<K, V> {
    pub fn backup_database<P: AsRef<Path>>(&self, path: P) -> Result<(), String> {
        let checkpoint = rocksdb::checkpoint::Checkpoint::new(&self.database)?;
        checkpoint.create_checkpoint(path).map_err(|e| e.into_string())
    }

    /// Catches up with the primary instance; only applicable to secondary instances.
    pub fn catch_up_with_primary(&self) -> Result<()> {
        self.database
            .try_catch_up_with_primary()
            .map_err(|e| anyhow::anyhow!("Failed to catch up with the primary: {e}"))
    }

    /// Reads RocksDB internal properties and publishes them to the metrics registry.
    /// Any map can be used since they all share the same underlying `RocksDB` instance.
    #[cfg(feature = "metrics")]
    pub fn export_rocksdb_metrics(&self) {
        self.database.export_rocksdb_metrics();
    }
}

impl<
    'a,
    K: 'a + Clone + Debug + PartialEq + Eq + Hash + Serialize + DeserializeOwned + Send + Sync,
    V: 'a + Clone + Serialize + DeserializeOwned + Send + Sync,
> Map<'a, K, V> for DataMap<K, V>
{
    ///
    /// Inserts the given key-value pair into the map.
    ///
    fn insert(&self, key: K, value: V) -> Result<()> {
        // Determine if an atomic batch is in progress.
        match self.is_atomic_in_progress() {
            // If a batch is in progress, add the key-value pair to the batch.
            true => {
                let start = Instant::now();
                self.atomic_batch.lock().push((key, Some(value)));
                crate::helpers::atomic_owner::record_lock_wait(start);
            }
            // Otherwise, insert the key-value pair directly into the map.
            false => {
                // Prepare the prefixed key and serialized value.
                let raw_key = self.create_prefixed_key(&key)?;
                let raw_value = bincode::serialize(&value)?;
                self.database.put(raw_key, raw_value)?;
            }
        }

        Ok(())
    }

    ///
    /// Removes the key-value pair for the given key from the map.
    ///
    fn remove(&self, key: &K) -> Result<()> {
        // Determine if an atomic batch is in progress.
        match self.is_atomic_in_progress() {
            // If a batch is in progress, add the key to the batch.
            true => {
                self.atomic_batch.lock().push((key.clone(), None));
            }
            // Otherwise, remove the key-value pair directly from the map.
            false => {
                // Prepare the prefixed key.
                let raw_key = self.create_prefixed_key(key)?;
                self.database.delete(raw_key)?;
            }
        }

        Ok(())
    }

    ///
    /// Begins an atomic operation. Any further calls to `insert` and `remove` will be queued
    /// without an actual write taking place until `finish_atomic` is called.
    ///
    fn start_atomic(&self) {
        // Set the atomic batch flag to `true`.
        self.batch_in_progress.store(true, Ordering::SeqCst);
        crate::helpers::atomic_owner::claim(&self.atomic_owner);
        // Increment the atomic depth index.
        self.database.atomic_depth.fetch_add(1, Ordering::SeqCst);

        // Ensure that the atomic batch is empty.
        assert!(
            self.atomic_batch.lock().is_empty(),
            "Cannot start an atomic batch operation while another one is already in progress"
        );
        // Ensure that the database atomic batch is empty; skip this check if the atomic
        // writes are paused, as there may be pending operations.
        if !self.database.are_atomic_writes_paused() {
            assert!(
                self.database.atomic_batch.lock().is_empty(),
                "Cannot start a database atomic batch operation while another one is already in progress"
            );
        }
    }

    ///
    /// Checks whether an atomic operation is currently in progress. This can be done to ensure
    /// that lower-level operations don't start and finish their individual atomic write batch
    /// if they are already part of a larger one.
    ///
    fn is_atomic_in_progress(&self) -> bool {
        self.batch_in_progress.load(Ordering::SeqCst)
    }

    ///
    /// Saves the current list of pending operations, so that if `atomic_rewind` is called,
    /// we roll back all future operations, and return to the start of this checkpoint.
    ///
    fn atomic_checkpoint(&self) {
        // Push the current length of the atomic batch to the checkpoint stack.
        let batch_len = self.atomic_batch.lock().len();
        self.checkpoints.lock().push(batch_len);
    }

    ///
    /// Removes the latest atomic checkpoint.
    ///
    fn clear_latest_checkpoint(&self) {
        // Removes the latest checkpoint.
        let _ = self.checkpoints.lock().pop();
    }

    ///
    /// Removes all pending operations to the last `atomic_checkpoint`
    /// (or to `start_atomic` if no checkpoints have been created).
    ///
    fn atomic_rewind(&self) {
        // Acquire the write lock on the atomic batch.
        let mut atomic_batch = self.atomic_batch.lock();

        // Retrieve the last checkpoint.
        let checkpoint = self.checkpoints.lock().pop().unwrap_or(0);

        // Remove all operations after the checkpoint.
        atomic_batch.truncate(checkpoint);
    }

    ///
    /// Aborts the current atomic operation.
    ///
    fn abort_atomic(&self) {
        // Clear the atomic batch.
        self.atomic_batch.lock().clear();
        // Clear the checkpoint stack.
        self.checkpoints.lock().clear();
        // Set the atomic batch flag to `false`.
        self.batch_in_progress.store(false, Ordering::SeqCst);
        crate::helpers::atomic_owner::release(&self.atomic_owner);
        // Clear the database-wide atomic batch.
        self.database.atomic_batch.lock().clear();
        // Reset the atomic batch depth.
        self.database.atomic_depth.store(0, Ordering::SeqCst);
    }

    ///
    /// Finishes an atomic operation, performing all the queued writes.
    ///
    fn finish_atomic(&self) -> Result<()> {
        // Retrieve the atomic batch belonging to the map.
        let operations = core::mem::take(&mut *self.atomic_batch.lock());

        if !operations.is_empty() {
            // Insert the operations into an index map to remove any operations that would have been overwritten anyways.
            let operations: IndexMap<_, _> = IndexMap::from_iter(operations);

            // Prepare the key and value for each queued operation.
            //
            // Note: This step is taken to ensure (with 100% certainty) that there will be
            // no chance to fail partway through committing the queued operations.
            //
            // The expected behavior is that either all the operations will be committed
            // or none of them will be.
            let prepared_operations = operations
                .into_iter()
                .map(|(key, value)| match value {
                    Some(value) => Ok((self.create_prefixed_key(&key)?, Some(bincode::serialize(&value)?))),
                    None => Ok((self.create_prefixed_key(&key)?, None)),
                })
                .collect::<Result<Vec<_>>>()?;

            // Enqueue all the operations from the map in the database-wide batch.
            let mut atomic_batch = self.database.atomic_batch.lock();
            for (raw_key, raw_value) in prepared_operations {
                match raw_value {
                    Some(raw_value) => atomic_batch.put(raw_key, raw_value),
                    None => atomic_batch.delete(raw_key),
                };
            }
        }

        // Clear the checkpoint stack.
        self.checkpoints.lock().clear();
        // Set the atomic batch flag to `false`.
        self.batch_in_progress.store(false, Ordering::SeqCst);
        crate::helpers::atomic_owner::release(&self.atomic_owner);

        // Subtract the atomic depth index.
        let previous_atomic_depth = self.database.atomic_depth.fetch_sub(1, Ordering::SeqCst);

        // Ensure that the value of `atomic_depth` doesn't overflow, meaning that all the
        // calls to `start_atomic` have corresponding calls to `finish_atomic`.
        assert_ne!(
            previous_atomic_depth, 0,
            "Atomic depth underflow: finish_atomic called without corresponding start_atomic"
        );

        // If we're at depth 0, it is the final call to `finish_atomic` and the
        // atomic write batch can be physically executed. This is skipped if the
        // atomic writes are paused.
        if previous_atomic_depth == 1 && !self.database.are_atomic_writes_paused() {
            // Empty the collection of pending operations.
            let batch = mem::take(&mut *self.database.atomic_batch.lock());
            // Execute all the operations atomically.
            self.database.rocksdb.write(batch)?;
            // Ensure that the database atomic batch is empty.
            assert!(
                self.database.atomic_batch.lock().is_empty(),
                "The database atomic batch must be empty when finishing a write batch operation"
            );
        }

        Ok(())
    }

    ///
    /// Once called, the subsequent atomic write batches will be queued instead of being executed
    /// at the end of their scope. `unpause_atomic_writes` needs to be called in order to
    /// restore the usual behavior.
    ///
    fn pause_atomic_writes(&self) -> Result<()> {
        self.database.pause_atomic_writes()
    }

    ///
    /// Executes all of the queued writes as a single atomic operation and restores the usual
    /// behavior of atomic write batches that was altered by calling `pause_atomic_writes`.
    ///
    fn unpause_atomic_writes<const DISCARD_BATCH: bool>(&self) -> Result<()> {
        self.database.unpause_atomic_writes::<DISCARD_BATCH>()
    }
}

impl<
    'a,
    K: 'a + Clone + Debug + PartialEq + Eq + Hash + Serialize + DeserializeOwned + Send + Sync,
    V: 'a + Clone + Serialize + DeserializeOwned + Send + Sync,
> MapRead<'a, K, V> for DataMap<K, V>
{
    type Iterator = Iter<'a, K, V>;
    type Keys = Keys<'a, K>;
    type PendingIterator =
        core::iter::Map<indexmap::map::IntoIter<K, Option<V>>, fn((K, Option<V>)) -> (Cow<'a, K>, Option<Cow<'a, V>>)>;
    type Values = Values<'a, V>;

    ///
    /// Returns the number of confirmed entries in the map.
    ///
    fn len_confirmed(&self) -> usize {
        // A raw iterator doesn't allocate.
        let mut iter = self.database.raw_iterator();
        // Find the first key with the map prefix.
        iter.seek(&self.context);

        // Count the number of keys belonging to the map.
        let mut len = 0usize;
        while iter.valid() {
            if let Some(key) = iter.key() {
                // Only compare the map ID - the network ID is guaranteed to
                // remain the same as long as there is more than a single map.
                if key[2..][..2] != self.context[2..][..2] {
                    // If the map ID is different, it's the end of iteration.
                    break;
                }

                // Increment the length and go to the next record.
                len += 1;
                iter.next();
            } else {
                break;
            }
        }

        len
    }

    ///
    /// Returns `true` if the given key exists in the map.
    ///
    fn contains_key_confirmed<Q>(&self, key: &Q) -> Result<bool>
    where
        K: Borrow<Q>,
        Q: PartialEq + Eq + Hash + Serialize + ?Sized,
    {
        self.get_raw(key).map(|v| v.is_some())
    }

    ///
    /// Returns `true` if the given key exists in the map.
    /// This method first checks the atomic batch, and if it does not exist, then checks the map.
    ///
    fn contains_key_speculative<Q>(&self, key: &Q) -> Result<bool>
    where
        K: Borrow<Q>,
        Q: PartialEq + Eq + Hash + Serialize + ?Sized,
    {
        // If this thread owns an in-progress batch, check the atomic batch first.
        if crate::helpers::atomic_owner::consults_atomic_batch(self.is_atomic_in_progress(), &self.atomic_owner) {
            // If the key is present in the atomic batch, then check if the value is 'Some(V)'.
            // We iterate from the back of the `atomic_batch` to find the latest value.
            let start = Instant::now();
            let batch = self.atomic_batch.lock();
            crate::helpers::atomic_owner::record_lock_wait(start);
            if let Some((_, value)) = batch.iter().rev().find(|&(k, _)| k.borrow() == key) {
                // If the value is 'Some(V)', then the key exists.
                // If the value is 'Some(None)', then the key is scheduled to be removed.
                return Ok(value.is_some());
            }
        }

        // Otherwise, check the map for the key.
        self.contains_key_confirmed(key)
    }

    ///
    /// Returns the value for the given key from the map, if it exists.
    ///
    fn get_confirmed<Q>(&'a self, key: &Q) -> Result<Option<Cow<'a, V>>>
    where
        K: Borrow<Q>,
        Q: PartialEq + Eq + Hash + Serialize + ?Sized,
    {
        match self.get_raw(key) {
            Ok(Some(bytes)) => Ok(Some(Cow::Owned(unchecked_deserialize(&bytes)?))),
            Ok(None) => Ok(None),
            Err(e) => Err(e),
        }
    }

    ///
    /// Returns the current value for the given key if it is scheduled
    /// to be inserted as part of an atomic batch.
    ///
    /// If the key does not exist, returns `None`.
    /// If the key is removed in the batch, returns `Some(None)`.
    /// If the key is inserted in the batch, returns `Some(Some(value))`.
    ///
    fn get_pending<Q>(&self, key: &Q) -> Option<Option<V>>
    where
        K: Borrow<Q>,
        Q: PartialEq + Eq + Hash + Serialize + ?Sized,
    {
        // Return early if there is no atomic batch in progress on this thread.
        if crate::helpers::atomic_owner::consults_atomic_batch(self.is_atomic_in_progress(), &self.atomic_owner) {
            // We iterate from the back of the `atomic_batch` to find the latest value.
            let start = Instant::now();
            let batch = self.atomic_batch.lock();
            crate::helpers::atomic_owner::record_lock_wait(start);
            batch.iter().rev().find(|&(k, _)| k.borrow() == key).map(|(_, value)| value).cloned()
        } else {
            None
        }
    }

    ///
    /// Returns the (key, value) pair for the greatest confirmed key ≤ the given key,
    /// or `None` if no such entry exists in this map.
    ///
    /// Uses RocksDB `seek_for_prev` for O(log n) performance.
    ///
    fn get_floor_confirmed<Q>(&'a self, key: &Q) -> Result<Option<(Cow<'a, K>, Cow<'a, V>)>>
    where
        K: Borrow<Q>,
        Q: PartialEq + Eq + Hash + Serialize + ?Sized,
    {
        let raw_key = self.create_prefixed_key(key)?;

        let mut iter = self.database.raw_iterator();
        iter.seek_for_prev(&raw_key);

        if !iter.valid() {
            return Ok(None);
        }

        let (k_bytes, v_bytes) = match iter.item() {
            Some(item) => item,
            None => return Ok(None),
        };

        // Verify this entry belongs to the same map (compare the map-ID bytes in the context).
        if k_bytes.len() < PREFIX_LEN || k_bytes[2..][..2] != self.context[2..][..2] {
            return Ok(None);
        }

        let k: K = unchecked_deserialize(&k_bytes[PREFIX_LEN..])?;
        let v: V = unchecked_deserialize(v_bytes)?;
        Ok(Some((Cow::Owned(k), Cow::Owned(v))))
    }

    ///
    /// Returns an iterator visiting each key-value pair in the atomic batch.
    ///
    fn iter_pending(&'a self) -> Self::PendingIterator {
        let filtered_atomic_batch: IndexMap<_, _> = IndexMap::from_iter(self.atomic_batch.lock().clone());
        filtered_atomic_batch.into_iter().map(|(k, v)| (Cow::Owned(k), v.map(|v| Cow::Owned(v))))
    }

    ///
    /// Returns an iterator visiting each key-value pair in the map.
    ///
    fn iter_confirmed(&'a self) -> Self::Iterator {
        Iter::new(self.database.prefix_iterator(&self.context))
    }

    ///
    /// Returns an iterator over each key in the map.
    ///
    fn keys_confirmed(&'a self) -> Self::Keys {
        Keys::new(self.database.prefix_iterator(&self.context))
    }

    ///
    /// Returns an iterator over each value in the map.
    ///
    fn values_confirmed(&'a self) -> Self::Values {
        Values::new(self.database.prefix_iterator(&self.context))
    }

    ///
    /// Returns the confirmed keys whose serialized form begins with the serialized `prefix`.
    ///
    fn get_keys_confirmed_with_prefix<Q>(&'a self, prefix: &Q) -> Result<Vec<K>>
    where
        Q: Serialize,
    {
        // Build the raw prefix: the map context (network ID + map ID) followed by the serialized prefix.
        let mut raw_prefix = self.context.clone();
        bincode::serialize_into(&mut raw_prefix, prefix)?;

        // Seek to the prefix and collect every key sharing it. The fixed-prefix extractor only spans
        // the map context, so the boundary of the longer prefix is checked explicitly.
        let mut iter = self.database.raw_iterator();
        iter.seek(&raw_prefix);

        let mut keys = Vec::new();
        while iter.valid() {
            let Some(key) = iter.key() else { break };
            if !key.starts_with(&raw_prefix) {
                break;
            }
            keys.push(unchecked_deserialize(&key[PREFIX_LEN..])?);
            iter.next();
        }
        Ok(keys)
    }
}

/// An iterator over all key-value pairs in a data map.
pub struct Iter<
    'a,
    K: 'a + Debug + PartialEq + Eq + Hash + Serialize + DeserializeOwned,
    V: 'a + Serialize + DeserializeOwned,
> {
    db_iter: rocksdb::DBRawIterator<'a>,
    _phantom: PhantomData<(K, V)>,
}

impl<'a, K: 'a + Debug + PartialEq + Eq + Hash + Serialize + DeserializeOwned, V: 'a + Serialize + DeserializeOwned>
    Iter<'a, K, V>
{
    pub(super) fn new(db_iter: rocksdb::DBIterator<'a>) -> Self {
        Self { db_iter: db_iter.into(), _phantom: PhantomData }
    }
}

impl<
    'a,
    K: 'a + Clone + Debug + PartialEq + Eq + Hash + Serialize + DeserializeOwned,
    V: 'a + Clone + Serialize + DeserializeOwned,
> Iterator for Iter<'a, K, V>
{
    type Item = (Cow<'a, K>, Cow<'a, V>);

    fn next(&mut self) -> Option<Self::Item> {
        if !self.db_iter.valid() {
            return None;
        }

        let (key, value) = self.db_iter.item()?;

        // Deserialize the key and value.
        let key = unchecked_deserialize(&key[PREFIX_LEN..])
            .map_err(|err| {
                let err: anyhow::Error = err.into();
                error!("{}", &flatten_error(err.context("RocksDB Iter deserialize(key) error")));
            })
            .ok()?;
        let value = unchecked_deserialize(value)
            .map_err(|err| {
                let err: anyhow::Error = err.into();
                error!("{}", &flatten_error(err.context("RocksDB Iter deserialize(value) error")));
            })
            .ok()?;

        self.db_iter.next();

        Some((Cow::Owned(key), Cow::Owned(value)))
    }
}

/// An iterator over the keys of a prefix.
pub struct Keys<'a, K: 'a + Debug + PartialEq + Eq + Hash + Serialize + DeserializeOwned> {
    db_iter: rocksdb::DBRawIterator<'a>,
    _phantom: PhantomData<K>,
}

impl<'a, K: 'a + Debug + PartialEq + Eq + Hash + Serialize + DeserializeOwned> Keys<'a, K> {
    pub(crate) fn new(db_iter: rocksdb::DBIterator<'a>) -> Self {
        Self { db_iter: db_iter.into(), _phantom: PhantomData }
    }
}

impl<'a, K: 'a + Clone + Debug + PartialEq + Eq + Hash + Serialize + DeserializeOwned> Iterator for Keys<'a, K> {
    type Item = Cow<'a, K>;

    fn next(&mut self) -> Option<Self::Item> {
        if !self.db_iter.valid() {
            return None;
        }

        // Deserialize the key.
        let key = unchecked_deserialize(&self.db_iter.key()?[PREFIX_LEN..])
            .map_err(|err| {
                let err: anyhow::Error = err.into();
                error!("{}", &flatten_error(err.context("RocksDB Keys deserialize(key) error")));
            })
            .ok()?;

        self.db_iter.next();

        Some(Cow::Owned(key))
    }
}

/// An iterator over the values of a prefix.
pub struct Values<'a, V: 'a + Serialize + DeserializeOwned> {
    db_iter: rocksdb::DBRawIterator<'a>,
    _phantom: PhantomData<V>,
}

impl<'a, V: 'a + Serialize + DeserializeOwned> Values<'a, V> {
    pub(crate) fn new(db_iter: rocksdb::DBIterator<'a>) -> Self {
        Self { db_iter: db_iter.into(), _phantom: PhantomData }
    }
}

impl<'a, V: 'a + Clone + Serialize + DeserializeOwned> Iterator for Values<'a, V> {
    type Item = Cow<'a, V>;

    fn next(&mut self) -> Option<Self::Item> {
        if !self.db_iter.valid() {
            return None;
        }

        // Deserialize the value.
        let value = unchecked_deserialize(self.db_iter.value()?)
            .map_err(|err| {
                let err: anyhow::Error = err.into();
                error!("{}", &flatten_error(err.context("RocksDB Values deserialize(value) error")));
            })
            .ok()?;

        self.db_iter.next();

        Some(Cow::Owned(value))
    }
}

impl<K: Serialize + DeserializeOwned, V: Serialize + DeserializeOwned> DataMap<K, V> {
    #[inline]
    fn create_prefixed_key<Q>(&self, key: &Q) -> Result<SmallVec<[u8; 64]>>
    where
        K: Borrow<Q>,
        Q: Serialize + ?Sized,
    {
        let mut raw_key: SmallVec<[u8; 64]> = SmallVec::new();
        raw_key.extend_from_slice(&self.context);
        bincode::serialize_into(&mut raw_key, &key)?;
        Ok(raw_key)
    }

    fn get_raw<Q>(&self, key: &Q) -> Result<Option<rocksdb::DBPinnableSlice<'_>>>
    where
        K: Borrow<Q>,
        Q: Serialize + ?Sized,
    {
        let raw_key = self.create_prefixed_key(key)?;
        match self.database.get_pinned_opt(&raw_key, &self.database.default_readopts)? {
            Some(data) => Ok(Some(data)),
            None => Ok(None),
        }
    }
}

impl<K: Serialize + DeserializeOwned, V: Serialize + DeserializeOwned> fmt::Debug for DataMap<K, V> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DataMap").field("context", &self.context).finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        FinalizeMode,
        atomic_batch_scope,
        atomic_finalize,
        helpers::rocksdb::{MapID, TestMap},
    };
    use console::{
        account::{Address, FromStr},
        network::MainnetV0,
    };

    use aleo_std::StorageMode;
    use anyhow::{anyhow, bail};
    use tracing_test::traced_test;

    type CurrentNetwork = MainnetV0;

    // Below are a few objects that mimic the way our DataMaps are organized,
    // in order to provide a more accurate test setup for some scenarios.

    fn open_map_testing_from_db<K: Serialize + DeserializeOwned, V: Serialize + DeserializeOwned, T: Into<u16>>(
        database: RocksDB,
        map_id: T,
    ) -> DataMap<K, V> {
        // Combine contexts to create a new scope.
        let mut context = database.network_id.to_le_bytes().to_vec();
        context.extend_from_slice(&(map_id.into()).to_le_bytes());

        // Return the DataMap.
        DataMap(Arc::new(InnerDataMap {
            database,
            context,
            atomic_batch: Default::default(),
            batch_in_progress: Default::default(),
            atomic_owner: Default::default(),
            checkpoints: Default::default(),
        }))
    }

    struct TestStorage {
        own_map: DataMap<usize, String>,
        extra_maps: TestStorage2,
    }

    impl TestStorage {
        fn open() -> Self {
            // Initialize a database.
            let database = RocksDB::open(0, StorageMode::new_test(None)).expect("Failed to open a test database");

            Self {
                own_map: open_map_testing_from_db(database.clone(), MapID::Test(TestMap::Test)),
                extra_maps: TestStorage2::open(database),
            }
        }

        fn start_atomic(&self) {
            self.own_map.start_atomic();
            self.extra_maps.start_atomic();
        }

        fn is_atomic_in_progress(&self) -> bool {
            self.own_map.is_atomic_in_progress() || self.extra_maps.is_atomic_in_progress()
        }

        fn atomic_checkpoint(&self) {
            self.own_map.atomic_checkpoint();
            self.extra_maps.atomic_checkpoint();
        }

        fn clear_latest_checkpoint(&self) {
            self.own_map.clear_latest_checkpoint();
            self.extra_maps.clear_latest_checkpoint();
        }

        fn atomic_rewind(&self) {
            self.own_map.atomic_rewind();
            self.extra_maps.atomic_rewind();
        }

        fn finish_atomic(&self) -> Result<()> {
            self.own_map.finish_atomic()?;
            self.extra_maps.finish_atomic()
        }

        fn abort_atomic(&self) {
            self.own_map.abort_atomic();
            self.extra_maps.abort_atomic();
        }

        // While the methods above mimic the typical snarkVM ones, this method is purely for testing.
        fn is_atomic_in_progress_everywhere(&self) -> bool {
            self.own_map.is_atomic_in_progress()
                && self.extra_maps.own_map1.is_atomic_in_progress()
                && self.extra_maps.own_map1.is_atomic_in_progress()
                && self.extra_maps.extra_maps.own_map.is_atomic_in_progress()
        }
    }

    struct TestStorage2 {
        own_map1: DataMap<usize, String>,
        own_map2: DataMap<usize, String>,
        extra_maps: TestStorage3,
    }

    impl TestStorage2 {
        fn open(database: RocksDB) -> Self {
            Self {
                own_map1: open_map_testing_from_db(database.clone(), MapID::Test(TestMap::Test2)),
                own_map2: open_map_testing_from_db(database.clone(), MapID::Test(TestMap::Test3)),
                extra_maps: TestStorage3::open(database),
            }
        }

        fn start_atomic(&self) {
            self.own_map1.start_atomic();
            self.own_map2.start_atomic();
            self.extra_maps.start_atomic();
        }

        fn is_atomic_in_progress(&self) -> bool {
            self.own_map1.is_atomic_in_progress()
                || self.own_map2.is_atomic_in_progress()
                || self.extra_maps.is_atomic_in_progress()
        }

        fn atomic_checkpoint(&self) {
            self.own_map1.atomic_checkpoint();
            self.own_map2.atomic_checkpoint();
            self.extra_maps.atomic_checkpoint();
        }

        fn clear_latest_checkpoint(&self) {
            self.own_map1.clear_latest_checkpoint();
            self.own_map2.clear_latest_checkpoint();
            self.extra_maps.clear_latest_checkpoint();
        }

        fn atomic_rewind(&self) {
            self.own_map1.atomic_rewind();
            self.own_map2.atomic_rewind();
            self.extra_maps.atomic_rewind();
        }

        fn finish_atomic(&self) -> Result<()> {
            self.own_map1.finish_atomic()?;
            self.own_map2.finish_atomic()?;
            self.extra_maps.finish_atomic()
        }

        fn abort_atomic(&self) {
            self.own_map1.abort_atomic();
            self.own_map2.abort_atomic();
            self.extra_maps.abort_atomic();
        }
    }

    struct TestStorage3 {
        own_map: DataMap<usize, String>,
    }

    impl TestStorage3 {
        fn open(database: RocksDB) -> Self {
            Self { own_map: open_map_testing_from_db(database, MapID::Test(TestMap::Test4)) }
        }

        fn start_atomic(&self) {
            self.own_map.start_atomic();
        }

        fn is_atomic_in_progress(&self) -> bool {
            self.own_map.is_atomic_in_progress()
        }

        fn atomic_checkpoint(&self) {
            self.own_map.atomic_checkpoint();
        }

        fn clear_latest_checkpoint(&self) {
            self.own_map.clear_latest_checkpoint();
        }

        fn atomic_rewind(&self) {
            self.own_map.atomic_rewind();
        }

        fn finish_atomic(&self) -> Result<()> {
            self.own_map.finish_atomic()
        }

        fn abort_atomic(&self) {
            self.own_map.abort_atomic();
        }
    }

    #[test]
    fn test_contains_key_sanity_check() {
        // Initialize an address.
        let address =
            Address::<CurrentNetwork>::from_str("aleo1q6qstg8q8shwqf5m6q5fcenuwsdqsvp4hhsgfnx5chzjm3secyzqt9mxm8")
                .unwrap();

        // Initialize a map.
        let map: DataMap<Address<CurrentNetwork>, ()> =
            RocksDB::open_map(0, StorageMode::new_test(None), MapID::Test(TestMap::Test))
                .expect("Failed to open data map");
        map.insert(address, ()).expect("Failed to insert into data map");
        assert!(map.contains_key_confirmed(&address).unwrap());
    }

    #[test]
    #[traced_test]
    fn test_insert_and_get_speculative() {
        // Initialize a map.
        let map: DataMap<usize, String> = RocksDB::open_map(0, StorageMode::new_test(None), MapID::Test(TestMap::Test))
            .expect("Failed to open data map");

        crate::helpers::test_helpers::map::check_insert_and_get_speculative(map);
    }

    #[test]
    #[traced_test]
    fn test_remove_and_get_speculative() {
        // Initialize a map.
        let map: DataMap<usize, String> = RocksDB::open_map(0, StorageMode::new_test(None), MapID::Test(TestMap::Test))
            .expect("Failed to open data map");

        crate::helpers::test_helpers::map::check_remove_and_get_speculative(map);
    }

    #[test]
    #[traced_test]
    fn test_contains_key() {
        // Initialize a map.
        let map: DataMap<usize, String> = RocksDB::open_map(0, StorageMode::new_test(None), MapID::Test(TestMap::Test))
            .expect("Failed to open data map");

        crate::helpers::test_helpers::map::check_contains_key(map);
    }

    #[test]
    #[traced_test]
    fn test_check_iterators_match() {
        // Initialize a map.
        let map: DataMap<usize, String> = RocksDB::open_map(0, StorageMode::new_test(None), MapID::Test(TestMap::Test))
            .expect("Failed to open data map");

        crate::helpers::test_helpers::map::check_iterators_match(map);
    }

    #[test]
    #[traced_test]
    fn test_atomic_writes_are_batched() {
        // Initialize a map.
        let map: DataMap<usize, String> = RocksDB::open_map(0, StorageMode::new_test(None), MapID::Test(TestMap::Test))
            .expect("Failed to open data map");

        crate::helpers::test_helpers::map::check_atomic_writes_are_batched(map);
    }

    #[test]
    #[traced_test]
    fn test_atomic_writes_can_be_aborted() {
        // Initialize a map.
        let map: DataMap<usize, String> = RocksDB::open_map(0, StorageMode::new_test(None), MapID::Test(TestMap::Test))
            .expect("Failed to open data map");

        crate::helpers::test_helpers::map::check_atomic_writes_can_be_aborted(map);
    }

    #[test]
    fn test_checkpoint_and_rewind() {
        // The number of items that will be queued to be inserted into the map.
        const NUM_ITEMS: usize = 10;

        // Initialize a map.
        let map: DataMap<usize, String> = RocksDB::open_map(0, StorageMode::new_test(None), MapID::Test(TestMap::Test))
            .expect("Failed to open data map");
        // Sanity check.
        assert!(map.iter_confirmed().next().is_none());
        // Make sure the checkpoint index is None.
        assert_eq!(map.checkpoints.lock().last(), None);

        // Start an atomic write batch.
        map.start_atomic();

        {
            // Queue (since a batch is in progress) NUM_ITEMS / 2 insertions.
            for i in 0..NUM_ITEMS / 2 {
                map.insert(i, i.to_string()).unwrap();
            }
            // The map should still contain no items.
            assert!(map.iter_confirmed().next().is_none());
            // The pending batch should contain NUM_ITEMS / 2 items.
            assert_eq!(map.iter_pending().count(), NUM_ITEMS / 2);
            // Make sure the checkpoint index is None.
            assert_eq!(map.checkpoints.lock().last(), None);
        }

        // Run the same sequence of checks 3 times.
        for _ in 0..3 {
            // Perform a checkpoint.
            map.atomic_checkpoint();
            // Make sure the checkpoint index is NUM_ITEMS / 2.
            assert_eq!(map.checkpoints.lock().last(), Some(&(NUM_ITEMS / 2)));

            {
                // Queue (since a batch is in progress) another NUM_ITEMS / 2 insertions.
                for i in (NUM_ITEMS / 2)..NUM_ITEMS {
                    map.insert(i, i.to_string()).unwrap();
                }
                // The map should still contain no items.
                assert!(map.iter_confirmed().next().is_none());
                // The pending batch should contain NUM_ITEMS items.
                assert_eq!(map.iter_pending().count(), NUM_ITEMS);
                // Make sure the checkpoint index is NUM_ITEMS / 2.
                assert_eq!(map.checkpoints.lock().last(), Some(&(NUM_ITEMS / 2)));
            }

            // Abort the current atomic write batch.
            map.atomic_rewind();
            // Make sure the checkpoint index is None.
            assert_eq!(map.checkpoints.lock().last(), None);

            {
                // The map should still contain no items.
                assert!(map.iter_confirmed().next().is_none());
                // The pending batch should contain NUM_ITEMS / 2 items.
                assert_eq!(map.iter_pending().count(), NUM_ITEMS / 2);
                // Make sure the checkpoint index is None.
                assert_eq!(map.checkpoints.lock().last(), None);
            }
        }

        // Finish the atomic batch.
        map.finish_atomic().unwrap();
        // The map should contain NUM_ITEMS / 2.
        assert_eq!(map.iter_confirmed().count(), NUM_ITEMS / 2);
        // The pending batch should contain no items.
        assert!(map.iter_pending().next().is_none());
        // Make sure the checkpoint index is None.
        assert_eq!(map.checkpoints.lock().last(), None);
    }

    #[test]
    fn test_nested_atomic_batch_scope() -> Result<()> {
        // The number of items that will be queued to be inserted into the map.
        const NUM_ITEMS: usize = 10;

        // Initialize a map.
        let map: DataMap<usize, String> = RocksDB::open_map(0, StorageMode::new_test(None), MapID::Test(TestMap::Test))
            .expect("Failed to open data map");
        // Sanity check.
        assert!(map.iter_confirmed().next().is_none());
        // Make sure the checkpoint index is None.
        assert_eq!(map.checkpoints.lock().last(), None);

        // Start a nested atomic batch scope that completes successfully.
        atomic_batch_scope!(map, {
            // Queue (since a batch is in progress) NUM_ITEMS / 2 insertions.
            for i in 0..NUM_ITEMS / 2 {
                map.insert(i, i.to_string()).unwrap();
            }
            // The map should still contain no items.
            assert!(map.iter_confirmed().next().is_none());
            // The pending batch should contain NUM_ITEMS / 2 items.
            assert_eq!(map.iter_pending().count(), NUM_ITEMS / 2);
            // Make sure the checkpoint index is None.
            assert_eq!(map.checkpoints.lock().last(), None);

            // Start a nested atomic batch scope that completes successfully.
            atomic_batch_scope!(map, {
                // Queue (since a batch is in progress) another NUM_ITEMS / 2 insertions.
                for i in (NUM_ITEMS / 2)..NUM_ITEMS {
                    map.insert(i, i.to_string()).unwrap();
                }
                // The map should still contain no items.
                assert!(map.iter_confirmed().next().is_none());
                // The pending batch should contain NUM_ITEMS items.
                assert_eq!(map.iter_pending().count(), NUM_ITEMS);
                // Make sure the checkpoint index is NUM_ITEMS / 2.
                assert_eq!(map.checkpoints.lock().last(), Some(&(NUM_ITEMS / 2)));

                Ok(())
            })?;

            // The map should still contain no items.
            assert!(map.iter_confirmed().next().is_none());
            // The pending batch should contain NUM_ITEMS items.
            assert_eq!(map.iter_pending().count(), NUM_ITEMS);
            // Make sure the checkpoint index is None.
            assert_eq!(map.checkpoints.lock().last(), None);

            Ok(())
        })?;

        // The map should contain NUM_ITEMS.
        assert_eq!(map.iter_confirmed().count(), NUM_ITEMS);
        // The pending batch should contain no items.
        assert!(map.iter_pending().next().is_none());
        // Make sure the checkpoint index is None.
        assert_eq!(map.checkpoints.lock().last(), None);

        Ok(())
    }

    #[test]
    fn test_failed_nested_atomic_batch_scope() {
        // The number of items that will be queued to be inserted into the map.
        const NUM_ITEMS: usize = 10;

        // Initialize a map.
        let map: DataMap<usize, String> = RocksDB::open_map(0, StorageMode::new_test(None), MapID::Test(TestMap::Test))
            .expect("Failed to open data map");
        // Sanity check.
        assert!(map.iter_confirmed().next().is_none());
        // Make sure the checkpoint index is None.
        assert_eq!(map.checkpoints.lock().last(), None);

        // Start an atomic write batch.
        let run_nested_atomic_batch_scope = || -> Result<()> {
            // Start an atomic batch scope that fails.
            atomic_batch_scope!(map, {
                // Queue (since a batch is in progress) NUM_ITEMS / 2 insertions.
                for i in 0..NUM_ITEMS / 2 {
                    map.insert(i, i.to_string()).unwrap();
                }
                // The map should still contain no items.
                assert!(map.iter_confirmed().next().is_none());
                // The pending batch should contain NUM_ITEMS / 2 items.
                assert_eq!(map.iter_pending().count(), NUM_ITEMS / 2);
                // Make sure the checkpoint index is None.
                assert_eq!(map.checkpoints.lock().last(), None);

                // Start a nested atomic write batch that completes correctly.
                atomic_batch_scope!(map, {
                    // Queue (since a batch is in progress) another NUM_ITEMS / 2 insertions.
                    for i in (NUM_ITEMS / 2)..NUM_ITEMS {
                        map.insert(i, i.to_string()).unwrap();
                    }
                    // The map should still contain no items.
                    assert!(map.iter_confirmed().next().is_none());
                    // The pending batch should contain NUM_ITEMS items.
                    assert_eq!(map.iter_pending().count(), NUM_ITEMS);
                    // Make sure the checkpoint index is NUM_ITEMS / 2.
                    assert_eq!(map.checkpoints.lock().last(), Some(&(NUM_ITEMS / 2)));

                    bail!("This batch should fail.");
                })?;

                unreachable!("The atomic write batch should fail before reaching this point.")
            })?;

            unreachable!("The atomic write batch should fail before reaching this point.")
        };

        // Ensure that the nested atomic write batch fails.
        assert!(run_nested_atomic_batch_scope().is_err());
    }

    #[test]
    fn test_atomic_finalize() -> Result<()> {
        // The number of items that will be queued to be inserted into the map.
        const NUM_ITEMS: usize = 10;

        // Initialize a map.
        let map: DataMap<usize, String> = RocksDB::open_map(0, StorageMode::new_test(None), MapID::Test(TestMap::Test))
            .expect("Failed to open data map");
        // Sanity check.
        assert!(map.iter_confirmed().next().is_none());
        // Make sure the checkpoint index is None.
        assert_eq!(map.checkpoints.lock().last(), None);

        // Start an atomic finalize.
        let outcome = atomic_finalize!(map, FinalizeMode::RealRun, {
            // Start a nested atomic batch scope that completes successfully.
            atomic_batch_scope!(map, {
                // Queue (since a batch is in progress) NUM_ITEMS / 2 insertions.
                for i in 0..NUM_ITEMS / 2 {
                    map.insert(i, i.to_string()).unwrap();
                }
                // The map should still contain no items.
                assert!(map.iter_confirmed().next().is_none());
                // The pending batch should contain NUM_ITEMS / 2 items.
                assert_eq!(map.iter_pending().count(), NUM_ITEMS / 2);
                // Make sure the checkpoint index is 0.
                assert_eq!(map.checkpoints.lock().last(), Some(&0));

                Ok(())
            })
            .unwrap();

            // The map should still contain no items.
            assert!(map.iter_confirmed().next().is_none());
            // The pending batch should contain NUM_ITEMS / 2 items.
            assert_eq!(map.iter_pending().count(), NUM_ITEMS / 2);
            // Make sure the checkpoint index is None.
            assert_eq!(map.checkpoints.lock().last(), None);

            // Start a nested atomic write batch that completes correctly.
            atomic_batch_scope!(map, {
                // Queue (since a batch is in progress) another NUM_ITEMS / 2 insertions.
                for i in (NUM_ITEMS / 2)..NUM_ITEMS {
                    map.insert(i, i.to_string()).unwrap();
                }
                // The map should still contain no items.
                assert!(map.iter_confirmed().next().is_none());
                // The pending batch should contain NUM_ITEMS items.
                assert_eq!(map.iter_pending().count(), NUM_ITEMS);
                // Make sure the checkpoint index is NUM_ITEMS / 2.
                assert_eq!(map.checkpoints.lock().last(), Some(&(NUM_ITEMS / 2)));

                Ok(())
            })
            .unwrap();

            // The map should still contain no items.
            assert!(map.iter_confirmed().next().is_none());
            // The pending batch should contain NUM_ITEMS items.
            assert_eq!(map.iter_pending().count(), NUM_ITEMS);
            // Make sure the checkpoint index is None.
            assert_eq!(map.checkpoints.lock().last(), None);

            Ok(())
        });

        // The atomic finalize should have succeeded.
        assert!(outcome.is_ok());

        // The map should contain NUM_ITEMS.
        assert_eq!(map.iter_confirmed().count(), NUM_ITEMS);
        // The pending batch should contain no items.
        assert!(map.iter_pending().next().is_none());
        // Make sure the checkpoint index is None.
        assert_eq!(map.checkpoints.lock().last(), None);

        Ok(())
    }

    #[test]
    fn test_atomic_finalize_failing_internal_scope() -> Result<()> {
        // The number of items that will be queued to be inserted into the map.
        const NUM_ITEMS: usize = 10;

        // Initialize a map.
        let map: DataMap<usize, String> = RocksDB::open_map(0, StorageMode::new_test(None), MapID::Test(TestMap::Test))
            .expect("Failed to open data map");
        // Sanity check.
        assert!(map.iter_confirmed().next().is_none());
        // Make sure the checkpoint index is None.
        assert_eq!(map.checkpoints.lock().last(), None);

        // Start an atomic finalize.
        let outcome = atomic_finalize!(map, FinalizeMode::RealRun, {
            // Start a nested atomic batch scope that completes successfully.
            atomic_batch_scope!(map, {
                // Queue (since a batch is in progress) NUM_ITEMS / 2 insertions.
                for i in 0..NUM_ITEMS / 2 {
                    map.insert(i, i.to_string()).unwrap();
                }
                // The map should still contain no items.
                assert!(map.iter_confirmed().next().is_none());
                // The pending batch should contain NUM_ITEMS / 2 items.
                assert_eq!(map.iter_pending().count(), NUM_ITEMS / 2);
                // Make sure the checkpoint index is 0.
                assert_eq!(map.checkpoints.lock().last(), Some(&0));

                Ok(())
            })
            .unwrap();

            // The map should still contain no items.
            assert!(map.iter_confirmed().next().is_none());
            // The pending batch should contain NUM_ITEMS / 2 items.
            assert_eq!(map.iter_pending().count(), NUM_ITEMS / 2);
            // Make sure the checkpoint index is None.
            assert_eq!(map.checkpoints.lock().last(), None);

            // Start a nested atomic write batch that fails.
            let result: Result<()> = atomic_batch_scope!(map, {
                // Queue (since a batch is in progress) another NUM_ITEMS / 2 insertions.
                for i in (NUM_ITEMS / 2)..NUM_ITEMS {
                    map.insert(i, i.to_string()).unwrap();
                }
                // The map should still contain no items.
                assert!(map.iter_confirmed().next().is_none());
                // The pending batch should contain NUM_ITEMS items.
                assert_eq!(map.iter_pending().count(), NUM_ITEMS);
                // Make sure the checkpoint index is NUM_ITEMS / 2.
                assert_eq!(map.checkpoints.lock().last(), Some(&(NUM_ITEMS / 2)));

                bail!("This batch scope should fail.");
            });

            // Ensure that the batch scope failed.
            assert!(result.is_err());

            // The map should still contain no items.
            assert!(map.iter_confirmed().next().is_none());
            // The pending batch should contain NUM_ITEMS / 2 items.
            assert_eq!(map.iter_pending().count(), NUM_ITEMS / 2);
            // Make sure the checkpoint index is None.
            assert_eq!(map.checkpoints.lock().last(), None);

            Ok(())
        });

        // The atomic finalize should have succeeded.
        assert!(outcome.is_ok());

        // The map should contain NUM_ITEMS / 2.
        assert_eq!(map.iter_confirmed().count(), NUM_ITEMS / 2);
        // The pending batch should contain no items.
        assert!(map.iter_pending().next().is_none());
        // Make sure the checkpoint index is None.
        assert_eq!(map.checkpoints.lock().last(), None);

        Ok(())
    }

    #[test]
    fn test_atomic_finalize_fails_to_start() {
        // Initialize a map.
        let map: DataMap<usize, String> = RocksDB::open_map(0, StorageMode::new_test(None), MapID::Test(TestMap::Test))
            .expect("Failed to open data map");
        // Sanity check.
        assert!(map.iter_confirmed().next().is_none());
        // Make sure the checkpoint index is None.
        assert_eq!(map.checkpoints.lock().last(), None);

        // Construct an atomic batch scope.
        let outcome: Result<()> = atomic_batch_scope!(map, {
            // Start an atomic finalize.
            let outcome = atomic_finalize!(map, FinalizeMode::RealRun, { Ok(()) });
            // Ensure that the atomic finalize fails.
            assert!(outcome.is_err());

            unreachable!("The batch scope should fail before we reach this point.");
        });

        // Ensure that the atomic batch scope fails.
        assert!(outcome.is_err());

        // Start an atomic operation.
        map.start_atomic();

        // We need to catch the `atomic_finalize` here, otherwise it will end the test early.
        let outcome = || atomic_finalize!(map, FinalizeMode::RealRun, { Ok(()) });

        // Ensure that the atomic finalize fails if an atomic batch is in progress.
        assert!(outcome().is_err());
    }

    #[test]
    fn test_atomic_checkpoint_truncation() {
        // Initialize a map.
        let map: DataMap<usize, String> = RocksDB::open_map(0, StorageMode::new_test(None), MapID::Test(TestMap::Test))
            .expect("Failed to open data map");
        // Sanity check.
        assert!(map.iter_confirmed().next().is_none());
        // Make sure the checkpoint index is None.
        assert_eq!(map.checkpoints.lock().last(), None);

        // Insert the key.
        map.insert(0, "0".to_string()).unwrap();

        // Start an atomic finalize.
        let outcome = atomic_batch_scope!(map, {
            // Insert the key.
            map.insert(0, "1".to_string()).unwrap();

            assert_eq!(map.checkpoints.lock().last(), None);

            // Create a failing atomic batch scope that will reset the checkpoint.
            let result: Result<()> = atomic_batch_scope!(map, {
                // Make sure the checkpoint index is 1.
                assert_eq!(map.checkpoints.lock().last(), Some(&1));

                // Update the key.
                map.insert(0, "2".to_string()).unwrap();

                bail!("This batch scope should fail.")
            });

            // Ensure that the batch scope failed.
            assert!(result.is_err());
            // The map should contain 1 item.
            assert_eq!(map.iter_confirmed().count(), 1);
            // The pending batch should contain 1 item.
            assert_eq!(map.iter_pending().count(), 1);
            // Ensure the pending operations still has the initial insertion.
            assert_eq!(map.get_pending(&0), Some(Some("1".to_string())));
            // Ensure the confirmed value has not changed.
            assert_eq!(*map.iter_confirmed().next().unwrap().1, "0");
            assert_eq!(map.checkpoints.lock().last(), None);

            Ok(())
        });

        assert!(outcome.is_ok());
        // The map should contain 1 item.
        assert_eq!(map.iter_confirmed().count(), 1);
        // The pending batch should contain no items.
        assert!(map.iter_pending().next().is_none());
        // Make sure the checkpoint index is None.
        assert_eq!(map.checkpoints.lock().last(), None);

        // Ensure that the map value is correct.
        assert_eq!(*map.iter_confirmed().next().unwrap().1, "1");
    }

    #[test]
    fn test_atomic_finalize_with_nested_batch_scope() -> Result<()> {
        // Initialize a map.
        let map: DataMap<usize, String> = RocksDB::open_map(0, StorageMode::new_test(None), MapID::Test(TestMap::Test))
            .expect("Failed to open data map");
        // Sanity check.
        assert!(map.iter_confirmed().next().is_none());
        // Make sure the checkpoint index is None.
        assert_eq!(map.checkpoints.lock().last(), None);

        // Insert the key.
        map.insert(0, "0".to_string()).unwrap();

        // Start an atomic finalize.
        let outcome = atomic_finalize!(map, FinalizeMode::RealRun, {
            // Create an atomic batch scope that will complete correctly.
            // Simulates an accepted transaction.
            let result: Result<()> = atomic_batch_scope!(map, {
                // Make sure the checkpoint index is 0.
                assert_eq!(map.checkpoints.lock().last(), Some(&0));

                // Insert the key.
                map.insert(0, "1".to_string()).unwrap();

                Ok(())
            });

            // Make sure the checkpoint index is None.
            assert_eq!(map.checkpoints.lock().last(), None);

            // The atomic finalize should have succeeded.
            assert!(result.is_ok());
            // The map should contain 1 item.
            assert_eq!(map.iter_confirmed().count(), 1);
            // The pending batch should contain 1 item.
            assert_eq!(map.iter_pending().count(), 1);
            // Make sure the pending operations is correct.
            assert_eq!(map.get_pending(&0), Some(Some("1".to_string())));

            // Create a failing atomic batch scope that will reset the checkpoint.
            // Simulates a rejected transaction.
            let result: Result<()> = atomic_batch_scope!(map, {
                // Make sure the checkpoint index is 1.
                assert_eq!(map.checkpoints.lock().last(), Some(&1));

                // Simulate an instruction
                let result: Result<()> = atomic_batch_scope!(map, {
                    // Make sure the checkpoint index is 1.
                    assert_eq!(map.checkpoints.lock().last(), Some(&1));

                    // Update the key.
                    map.insert(0, "2".to_string()).unwrap();

                    Ok(())
                });
                assert!(result.is_ok());

                // Make sure the checkpoint index is 1.
                assert_eq!(map.checkpoints.lock().last(), Some(&1));
                // Ensure that the atomic batch length is 2.
                assert_eq!(map.atomic_batch.lock().len(), 2);
                // Ensure that the database atomic batch is empty.
                assert!(map.database.atomic_batch.lock().is_empty());
                // Ensure that the database atomic depth is 1.
                assert_eq!(map.database.atomic_depth.load(Ordering::SeqCst), 1);

                // Simulates an instruction that fails.
                let result: Result<()> = atomic_batch_scope!(map, {
                    // Make sure the checkpoint index is 2.
                    assert_eq!(map.checkpoints.lock().last(), Some(&2));

                    // Update the key.
                    map.insert(0, "3".to_string()).unwrap();

                    Ok(())
                });
                assert!(result.is_ok());

                bail!("This batch scope should fail.")
            });

            // Ensure that the batch scope failed.
            assert!(result.is_err());
            // The map should contain 1 item.
            assert_eq!(map.iter_confirmed().count(), 1);
            // The pending batch should contain 1 item.
            assert_eq!(map.iter_pending().count(), 1);
            // Make sure the pending operations still has the initial insertion.
            assert_eq!(map.get_pending(&0), Some(Some("1".to_string())));
            // Make sure the checkpoint index is None.
            assert_eq!(map.checkpoints.lock().last(), None);
            // Ensure that the atomic batch length is 1.
            assert_eq!(map.atomic_batch.lock().len(), 1);
            // Ensure that the database atomic batch is empty.
            assert!(map.database.atomic_batch.lock().is_empty());
            // Ensure that the database atomic depth is 1.
            assert_eq!(map.database.atomic_depth.load(Ordering::SeqCst), 1);

            Ok(())
        });

        assert!(outcome.is_ok());
        // The map should contain 1 item.
        assert_eq!(map.iter_confirmed().count(), 1);
        // The pending batch should contain no items.
        assert!(map.iter_pending().next().is_none());
        // Make sure the checkpoint index is None.
        assert_eq!(map.checkpoints.lock().last(), None);
        // Ensure that the atomic batch is empty.
        assert!(map.atomic_batch.lock().is_empty());
        // Ensure that the database atomic batch is empty.
        assert!(map.database.atomic_batch.lock().is_empty());
        // Ensure that the database atomic depth is 0.
        assert_eq!(map.database.atomic_depth.load(Ordering::SeqCst), 0);

        // Ensure that the map value is correct.
        assert_eq!(*map.iter_confirmed().next().unwrap().1, "1");

        Ok(())
    }

    #[test]
    #[traced_test]
    fn test_nested_atomic_write_batch_success() -> Result<()> {
        // Initialize a multi-layer test storage.
        let test_storage = TestStorage::open();

        // Sanity check.
        assert!(test_storage.own_map.iter_confirmed().next().is_none());
        assert!(test_storage.extra_maps.own_map1.iter_confirmed().next().is_none());
        assert!(test_storage.extra_maps.own_map2.iter_confirmed().next().is_none());
        assert!(test_storage.extra_maps.extra_maps.own_map.iter_confirmed().next().is_none());

        assert_eq!(test_storage.own_map.checkpoints.lock().last(), None);

        // Note: all the checks going through .database can be performed on any one
        // of the objects, as all of them share the same instance of the database.

        assert!(!test_storage.is_atomic_in_progress_everywhere());

        // Start an atomic write batch.
        atomic_batch_scope!(test_storage, {
            assert!(test_storage.is_atomic_in_progress_everywhere());

            assert_eq!(test_storage.own_map.checkpoints.lock().last(), None);

            // Write an item into the first map.
            test_storage.own_map.insert(0, 0.to_string()).unwrap();

            // Start another atomic write batch.
            atomic_batch_scope!(test_storage.extra_maps.own_map1, {
                assert!(test_storage.is_atomic_in_progress_everywhere());

                // Write an item into the second map.
                test_storage.extra_maps.own_map1.insert(1, 1.to_string()).unwrap();

                // Write an item into the third map.
                test_storage.extra_maps.own_map2.insert(2, 2.to_string()).unwrap();

                // Start another atomic write batch.
                atomic_batch_scope!(test_storage.extra_maps.extra_maps.own_map, {
                    assert!(test_storage.extra_maps.extra_maps.own_map.is_atomic_in_progress());

                    // Write an item into the fourth map.
                    test_storage.extra_maps.extra_maps.own_map.insert(3, 3.to_string()).unwrap();

                    Ok(())
                })?;

                assert!(test_storage.is_atomic_in_progress_everywhere());

                Ok(())
            })?;

            assert!(test_storage.is_atomic_in_progress_everywhere());

            Ok(())
        })?;

        assert!(!test_storage.is_atomic_in_progress_everywhere());

        // Ensure that all the items are present.
        assert_eq!(test_storage.own_map.iter_confirmed().count(), 1);
        assert_eq!(test_storage.own_map.len_confirmed(), 1);
        assert_eq!(test_storage.extra_maps.own_map1.iter_confirmed().count(), 1);
        assert_eq!(test_storage.extra_maps.own_map1.len_confirmed(), 1);
        assert_eq!(test_storage.extra_maps.own_map2.iter_confirmed().count(), 1);
        assert_eq!(test_storage.extra_maps.own_map2.len_confirmed(), 1);
        assert_eq!(test_storage.extra_maps.extra_maps.own_map.iter_confirmed().count(), 1);
        assert_eq!(test_storage.extra_maps.extra_maps.own_map.len_confirmed(), 1);

        // The atomic_write_batch macro uses ?, so the test returns a Result for simplicity.
        Ok(())
    }

    #[test]
    #[traced_test]
    fn test_nested_atomic_write_batch_failure() {
        // We'll want to execute the atomic write batch in its own function, in order to be able to
        // inspect the aftermatch after an error, as opposed to returning from the whole test.
        fn execute_atomic_write_batch(test_storage: &TestStorage) -> Result<()> {
            // Start an atomic write batch.
            atomic_batch_scope!(test_storage, {
                assert!(test_storage.is_atomic_in_progress_everywhere());

                // Write an item into the first map.
                test_storage.own_map.insert(0, 0.to_string()).unwrap();

                // Start another atomic write batch.
                atomic_batch_scope!(test_storage.extra_maps.own_map1, {
                    assert!(test_storage.is_atomic_in_progress_everywhere());

                    // Write an item into the second map.
                    test_storage.extra_maps.own_map1.insert(1, 1.to_string()).unwrap();

                    // Write an item into the third map.
                    test_storage.extra_maps.own_map2.insert(2, 2.to_string()).unwrap();

                    // Start another atomic write batch.
                    let result: Result<()> = atomic_batch_scope!(test_storage.extra_maps.extra_maps.own_map, {
                        assert!(test_storage.is_atomic_in_progress_everywhere());

                        // Write an item into the fourth map.
                        test_storage.extra_maps.extra_maps.own_map.insert(3, 3.to_string()).unwrap();

                        // Rewind the atomic batch via a simulated error.
                        bail!("An error that will trigger a single rewind.");
                    });
                    assert!(result.is_err());

                    assert!(test_storage.is_atomic_in_progress_everywhere());

                    Ok(())
                })?;

                assert!(test_storage.is_atomic_in_progress_everywhere());

                Ok(())
            })?;

            Ok(())
        }

        // Initialize a multi-layer test storage.
        let test_storage = TestStorage::open();

        // Sanity check.
        assert!(test_storage.own_map.iter_confirmed().next().is_none());
        assert!(test_storage.extra_maps.own_map1.iter_confirmed().next().is_none());
        assert!(test_storage.extra_maps.own_map2.iter_confirmed().next().is_none());
        assert!(test_storage.extra_maps.extra_maps.own_map.iter_confirmed().next().is_none());

        // Note: all the checks going through .database can be performed on any one
        // of the objects, as all of them share the same instance of the database.

        assert!(!test_storage.is_atomic_in_progress_everywhere());

        // Perform the atomic operations defined in the free function at the beginning of the test.
        assert!(execute_atomic_write_batch(&test_storage).is_ok());

        assert!(!test_storage.is_atomic_in_progress_everywhere());

        // Ensure that all the items up until the last scope are present.
        assert_eq!(test_storage.own_map.iter_confirmed().count(), 1);
        assert_eq!(test_storage.extra_maps.own_map1.iter_confirmed().count(), 1);
        assert_eq!(test_storage.extra_maps.own_map2.iter_confirmed().count(), 1);
        assert_eq!(test_storage.extra_maps.extra_maps.own_map.iter_confirmed().count(), 0);
    }
}
