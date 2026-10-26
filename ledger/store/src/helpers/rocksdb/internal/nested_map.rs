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
use crate::helpers::{NestedMap, NestedMapRead};
use console::prelude::{FromBytes, anyhow, cfg_into_iter};
use snarkvm_utilities::{bytes::unchecked_deserialize, flatten_error};

use anyhow::Context;
use core::{fmt, fmt::Debug, hash::Hash, mem};
use std::{borrow::Cow, sync::atomic::Ordering, time::Instant};
use tracing::error;

#[cfg(not(feature = "serial"))]
use rayon::iter::{IntoParallelIterator, ParallelIterator};

#[derive(Clone)]
pub struct NestedDataMap<
    M: Serialize + DeserializeOwned,
    K: Serialize + DeserializeOwned,
    V: Serialize + DeserializeOwned,
> {
    /// The rocksDB instance.
    pub(super) database: RocksDB,
    /// The context for the map.
    pub(super) context: Vec<u8>,
    /// The tracker for whether a database transaction is in progress.
    pub(super) batch_in_progress: Arc<AtomicBool>,
    /// Owner of the in-progress atomic batch (`0` = none).
    pub(super) atomic_owner: Arc<AtomicU64>,
    /// The database transaction.
    pub(super) atomic_batch: Arc<Mutex<Vec<(M, Option<K>, Option<V>)>>>,
    /// The checkpoint stack for the batched operations within the map.
    pub(super) checkpoints: Arc<Mutex<Vec<usize>>>,
}

impl<M: Serialize + DeserializeOwned, K: Serialize + DeserializeOwned, V: Serialize + DeserializeOwned> Debug
    for NestedDataMap<M, K, V>
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("NestedDataMap").field("context", &self.context).finish()
    }
}

impl<M: Serialize + DeserializeOwned, K: Serialize + DeserializeOwned, V: Serialize + DeserializeOwned>
    NestedDataMap<M, K, V>
{
    #[inline]
    fn create_prefixed_map(&self, map: &M) -> Result<Vec<u8>> {
        let mut raw_map = self.context.clone();

        let map_size: u32 =
            bincode::serialized_size(&map).with_context(|| "Failed to get size of serialize map")?.try_into()?;
        raw_map.extend_from_slice(&map_size.to_le_bytes());

        bincode::serialize_into(&mut raw_map, map).with_context(|| "Failed to serialize map")?;
        Ok(raw_map)
    }

    #[inline]
    fn create_prefixed_map_key(&self, map: &M, key: &K) -> Result<Vec<u8>> {
        let mut raw_map_key = self.create_prefixed_map(map)?;
        bincode::serialize_into(&mut raw_map_key, key)?;
        Ok(raw_map_key)
    }

    #[inline]
    fn get_map_key_raw(&self, map: &M, key: &K) -> Result<Option<rocksdb::DBPinnableSlice<'_>>> {
        let raw_map_key = self.create_prefixed_map_key(map, key)?;
        match self.database.get_pinned_opt(&raw_map_key, &self.database.default_readopts)? {
            Some(data) => Ok(Some(data)),
            None => Ok(None),
        }
    }
}
#[inline]
fn get_map_and_key(map_key: &[u8]) -> Result<(&[u8], &[u8])> {
    // Retrieve the map length.
    let map_len = u32::from_bytes_le(
        map_key.get(PREFIX_LEN..PREFIX_LEN + 4).ok_or_else(|| anyhow!("NestedMap map_len index out of range"))?,
    )? as usize;

    // Retrieve the map bytes.
    let map = map_key
        .get(PREFIX_LEN + 4..PREFIX_LEN + 4 + map_len)
        .ok_or_else(|| anyhow!("NestedMap map index out of range"))?;

    // Retrieve the key bytes.
    let key = map_key.get(PREFIX_LEN + 4 + map_len..).ok_or_else(|| anyhow!("NestedMap key index out of range"))?;

    // Return the map and key bytes.
    Ok((map, key))
}

impl<
    'a,
    M: 'a + Copy + Clone + Debug + PartialEq + Eq + Hash + Serialize + DeserializeOwned + Send + Sync,
    K: 'a + Clone + Debug + PartialEq + Eq + Serialize + DeserializeOwned + Send + Sync,
    V: 'a + Clone + Serialize + DeserializeOwned + Send + Sync,
> NestedMap<'a, M, K, V> for NestedDataMap<M, K, V>
{
    ///
    /// Inserts the given map-key-value pair.
    ///
    fn insert(&self, map: M, key: K, value: V) -> Result<()> {
        // Determine if an atomic batch is in progress.
        match self.is_atomic_in_progress() {
            // If a batch is in progress, add the map-key-value pair to the batch.
            true => {
                let start = Instant::now();
                self.atomic_batch.lock().push((map, Some(key), Some(value)));
                crate::helpers::atomic_owner::record_lock_wait(start);
            }
            // Otherwise, insert the key-value pair directly into the map.
            false => {
                // Prepare the prefixed map-key and serialized value.
                let raw_key = self.create_prefixed_map_key(&map, &key)?;
                let raw_value = bincode::serialize(&value)?;
                self.database.put(raw_key, raw_value)?;
            }
        }
        Ok(())
    }

    ///
    /// Removes the given map.
    ///
    fn remove_map(&self, map: &M) -> Result<()> {
        // Determine if an atomic batch is in progress.
        match self.is_atomic_in_progress() {
            // If a batch is in progress, add the map-None pair to the batch.
            true => self.atomic_batch.lock().push((*map, None, None)),
            // Otherwise, remove the map directly from the map.
            false => {
                // Serialize the map.
                let serialized_map = bincode::serialize(map)?;

                // Batching the delete operations to optimize the write performance and ensure atomicity.
                let mut batch = rocksdb::WriteBatch::default();

                // Construct an iterator over the DB with the specified prefix.
                let iterator = self.database.prefix_iterator(&self.create_prefixed_map(map)?);

                // Iterate over the entries in the DB with the specified prefix.
                for entry in iterator {
                    let (map_key, _) = entry?;

                    // Extract the bytes belonging to the map and the key.
                    let Ok((entry_map, _)) = get_map_and_key(&map_key) else {
                        break;
                    };

                    // If the 'entry_map' matches 'serialized_map', delete the key.
                    if entry_map == serialized_map {
                        batch.delete(map_key);
                    } else {
                        // If the 'entry_map' no longer matches the 'serialized_map',
                        // we've moved past the relevant keys and can break the loop.
                        break;
                    }
                }

                // Deleting the batched keys atomically from RocksDB.
                self.database.write(batch)?;
            }
        }
        Ok(())
    }

    ///
    /// Removes the key-value pair for the given map and key.
    ///
    fn remove_key(&self, map: &M, key: &K) -> Result<()> {
        // Determine if an atomic batch is in progress.
        match self.is_atomic_in_progress() {
            // If a batch is in progress, add the key to the batch.
            true => self.atomic_batch.lock().push((*map, Some(key.clone()), None)),
            // Otherwise, remove the key-value pair directly from the map.
            false => {
                // Prepare the prefixed map-key.
                let map_key = self.create_prefixed_map_key(map, key)?;
                self.database.delete(map_key)?;
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
        self.checkpoints.lock().push(self.atomic_batch.lock().len());
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
            // Enqueue all the operations from the map in the database-wide batch.
            let mut atomic_batch = self.database.atomic_batch.lock();

            for (map, key, value) in operations {
                match (key, value) {
                    (Some(key), Some(value)) => {
                        atomic_batch.put(self.create_prefixed_map_key(&map, &key)?, bincode::serialize(&value)?)
                    }
                    (Some(key), None) => atomic_batch.delete(self.create_prefixed_map_key(&map, &key)?),
                    (None, None) => {
                        // Serialize the map.
                        let serialized_map = bincode::serialize(&map)?;

                        // Construct an iterator over the DB with the specified prefix.
                        let iterator = self.database.prefix_iterator(&self.create_prefixed_map(&map)?);

                        // Iterate over the entries in the DB with the specified prefix.
                        for entry in iterator {
                            let (map_key, _) = entry?;

                            // Extract the bytes belonging to the map and the key.
                            let Ok((entry_map, _)) = get_map_and_key(&map_key) else {
                                break;
                            };

                            // If the 'entry_map' matches 'serialized_map', delete the key.
                            if entry_map == serialized_map {
                                atomic_batch.delete(map_key);
                            } else {
                                // If the 'entry_map' no longer matches the 'serialized_map',
                                // we've moved past the relevant keys and can break the loop.
                                break;
                            }
                        }
                    }
                    (None, Some(_)) => unreachable!("Cannot insert a value without a key"),
                }
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
}

impl<
    'a,
    M: 'a + Copy + Clone + Debug + PartialEq + Eq + Hash + Serialize + DeserializeOwned + Send + Sync,
    K: 'a + Clone + Debug + PartialEq + Eq + Serialize + DeserializeOwned + Send + Sync,
    V: 'a + Clone + Serialize + DeserializeOwned + Send + Sync,
> NestedMapRead<'a, M, K, V> for NestedDataMap<M, K, V>
{
    type Iterator = NestedIter<'a, M, K, V>;
    type Keys = NestedKeys<'a, M, K>;
    type PendingIterator = core::iter::Map<
        std::vec::IntoIter<(M, Option<K>, Option<V>)>,
        fn((M, Option<K>, Option<V>)) -> (Cow<'a, M>, Option<Cow<'a, K>>, Option<Cow<'a, V>>),
    >;
    type Values = NestedValues<'a, V>;

    ///
    /// Returns the number of confirmed entries in the map.
    ///
    fn len_map_confirmed(&self, map: &M) -> Result<usize> {
        // Obtain the nested map prefix and its final part.
        let prefix = self.create_prefixed_map(map)?;
        let serialized_map = &prefix[PREFIX_LEN + 4..];

        // A raw iterator doesn't allocate.
        let mut iter = self.database.raw_iterator();
        // Find the first key with the nested map prefix.
        iter.seek(&prefix);

        // Count the number of keys belonging to the nested map.
        let mut len = 0usize;
        while iter.valid() {
            if let Some(key) = iter.key() {
                // Only compare the nested map - the network ID and the outer map
                // ID are guaranteed to remain the same as long as there is more
                // than a single map in the database.
                if !key[PREFIX_LEN + 4..].starts_with(serialized_map) {
                    // If the nested map ID is different, it's the end of iteration.
                    break;
                }

                // Increment the length and go to the next record.
                len += 1;
                iter.next();
            } else {
                break;
            }
        }

        Ok(len)
    }

    ///
    /// Returns `true` if the given map and key exists.
    ///
    fn contains_key_confirmed(&self, map: &M, key: &K) -> Result<bool> {
        self.get_map_key_raw(map, key).map(|v| v.is_some())
    }

    ///
    /// Returns `true` if the given map and key exists.
    /// This method first checks the atomic batch, and if it does not exist, then checks the map.
    ///
    fn contains_key_speculative(&self, map: &M, key: &K) -> Result<bool> {
        // If this thread owns an in-progress batch, check the atomic batch first.
        if crate::helpers::atomic_owner::consults_atomic_batch(self.is_atomic_in_progress(), &self.atomic_owner) {
            // We iterate from the back of the `atomic_batch` to find the latest value.
            let start = Instant::now();
            let batch = self.atomic_batch.lock();
            crate::helpers::atomic_owner::record_lock_wait(start);
            for (m, k, v) in batch.iter().rev() {
                // If the map does not match the given map, then continue.
                if m != map {
                    continue;
                }
                // If the key is 'None', then the map is scheduled to be removed.
                if k.is_none() {
                    return Ok(false);
                }
                // If the key matches the given key, then return whether the value is 'Some(V)'.
                if k.as_ref().unwrap() == key {
                    // If the value is 'Some(V)', then the key exists.
                    // If the value is 'None', then the key is scheduled to be removed.
                    return Ok(v.is_some());
                }
            }
        }
        // Otherwise, check the map for the key.
        self.contains_key_confirmed(map, key)
    }

    ///
    /// Returns the key-value pairs for the given map, if it exists.
    ///
    fn get_map_confirmed(&'a self, map: &M) -> Result<Vec<(K, V)>> {
        // Serialize the map.
        let serialized_map = bincode::serialize(map)?;

        // Initialize a vector for the entries.
        let mut entries = Vec::new();

        // Construct an iterator over the DB with the specified prefix.
        let iterator = self.database.prefix_iterator(&self.create_prefixed_map(map)?);

        // Iterate over the entries in the DB with the specified prefix.
        for entry in iterator {
            let (map_key, value) = entry?;

            // Extract the bytes belonging to the map and the key.
            let Ok((entry_map, entry_key)) = get_map_and_key(&map_key) else {
                break;
            };

            // If the 'entry_map' matches 'serialized_map', deserialize the key and value.
            if entry_map == serialized_map {
                // Push the key-value pair to the vector.
                entries.push((entry_key.to_owned(), value));
            } else {
                // If the 'entry_map' no longer matches the 'serialized_map',
                // we've moved past the relevant keys and can break the loop.
                break;
            }
        }

        // Possibly deserialize the entries in parallel.
        cfg_into_iter!(entries)
            .map(|(k, v)| {
                let k = unchecked_deserialize::<K>(&k);
                let v = unchecked_deserialize::<V>(&v);

                k.and_then(|k| v.map(|v| (k, v)))
            })
            .collect::<Result<_, bincode::Error>>()
            .with_context(|| "Failed to deserialize map entries")
    }

    ///
    /// Returns the speculative key-value pairs for the given map, if it exists.
    ///
    fn get_map_speculative(&'a self, map: &M) -> Result<Vec<(K, V)>> {
        // Retrieve the confirmed key-value pairs for the given map.
        let mut key_values = self.get_map_confirmed(map)?;

        // If this thread does not own an in-progress batch, return confirmed pairs.
        if !crate::helpers::atomic_owner::consults_atomic_batch(self.is_atomic_in_progress(), &self.atomic_owner) {
            return Ok(key_values);
        }

        // Retrieve the atomic batch.
        let start = Instant::now();
        let operations = self.atomic_batch.lock().clone();
        crate::helpers::atomic_owner::record_lock_wait(start);

        if !operations.is_empty() {
            // Traverse the queued operations.
            for (m, k, v) in operations {
                // If the map does not match the given map, then continue.
                if &m != map {
                    continue;
                }

                // Update the confirmed pairs based on the pending operations.
                match (k, v) {
                    // Insert or update the key-value pair for the key.
                    (Some(k), Some(v)) => {
                        // If the key exists, then update the value.
                        // Otherwise, insert the key-value pair.
                        match key_values.iter_mut().find(|(key, _)| key == &k) {
                            Some((_, value)) => *value = v,
                            None => key_values.push((k, v)),
                        }
                    }
                    // Clear the key-value pairs for the map.
                    (None, None) => key_values.clear(),
                    // Remove the key-value pair for the key.
                    (Some(k), None) => key_values.retain(|(key, _)| key != &k),
                    (None, Some(_)) => unreachable!("Cannot remove a key-value pair from a map without a key."),
                }
            }
        }

        // Return the key-value pairs for the map.
        Ok(key_values)
    }

    ///
    /// Returns the value for the given map and key, if it exists.
    ///
    fn get_value_confirmed(&'a self, map: &M, key: &K) -> Result<Option<Cow<'a, V>>> {
        match self.get_map_key_raw(map, key) {
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
    fn get_value_pending(&self, map: &M, key: &K) -> Option<Option<V>> {
        // Return early if there is no atomic batch in progress on this thread.
        if crate::helpers::atomic_owner::consults_atomic_batch(self.is_atomic_in_progress(), &self.atomic_owner) {
            // We iterate from the back of the `atomic_batch` to find the latest value.
            let start = Instant::now();
            let batch = self.atomic_batch.lock();
            crate::helpers::atomic_owner::record_lock_wait(start);
            for (m, k, v) in batch.iter().rev() {
                // If the map does not match the given map, then continue.
                if m != map {
                    continue;
                }
                // If the key is 'None', then the map is scheduled to be removed.
                if k.is_none() {
                    return Some(None);
                }
                // If the key matches the given key, then return whether the value is 'Some(V)'.
                if k.as_ref().unwrap() == key {
                    // If the value is 'Some(V)', then the key exists.
                    // If the value is 'Some(None)', then the key is scheduled to be removed.
                    return Some(v.clone());
                }
            }
            None
        } else {
            None
        }
    }

    ///
    /// Returns an iterator visiting each key-value pair in the atomic batch.
    ///
    fn iter_pending(&'a self) -> Self::PendingIterator {
        self.atomic_batch.lock().clone().into_iter().map(|(m, k, v)| {
            // Return the map-key-value triple.
            (Cow::Owned(m), k.map(Cow::Owned), v.map(Cow::Owned))
        })
    }

    ///
    /// Returns an iterator visiting each key-value pair in the map.
    ///
    fn iter_confirmed(&'a self) -> Self::Iterator {
        NestedIter::new(self.database.prefix_iterator(&self.context))
    }

    ///
    /// Returns an iterator over each key.
    ///
    fn keys_confirmed(&'a self) -> Self::Keys {
        NestedKeys::new(self.database.prefix_iterator(&self.context))
    }

    ///
    /// Returns an iterator over each value.
    ///
    fn values_confirmed(&'a self) -> Self::Values {
        NestedValues::new(self.database.prefix_iterator(&self.context))
    }
}

/// An iterator over all map-key-value pairs in a data map.
pub struct NestedIter<
    'a,
    M: 'a + Debug + PartialEq + Eq + Hash + Serialize + DeserializeOwned,
    K: 'a + Debug + PartialEq + Eq + Serialize + DeserializeOwned,
    V: 'a + Serialize + DeserializeOwned,
> {
    db_iter: rocksdb::DBRawIterator<'a>,
    _phantom: PhantomData<(M, K, V)>,
}

impl<
    'a,
    M: 'a + Debug + PartialEq + Eq + Hash + Serialize + DeserializeOwned,
    K: 'a + Debug + PartialEq + Eq + Serialize + DeserializeOwned,
    V: 'a + Serialize + DeserializeOwned,
> NestedIter<'a, M, K, V>
{
    pub(super) fn new(db_iter: rocksdb::DBIterator<'a>) -> Self {
        Self { db_iter: db_iter.into(), _phantom: PhantomData }
    }
}

impl<
    'a,
    M: 'a + Clone + Debug + PartialEq + Eq + Hash + Serialize + DeserializeOwned,
    K: 'a + Clone + Debug + PartialEq + Eq + Serialize + DeserializeOwned,
    V: 'a + Clone + Serialize + DeserializeOwned,
> Iterator for NestedIter<'a, M, K, V>
{
    type Item = (Cow<'a, M>, Cow<'a, K>, Cow<'a, V>);

    fn next(&mut self) -> Option<Self::Item> {
        if !self.db_iter.valid() {
            return None;
        }

        let (map_key, value) = self.db_iter.item()?;

        // Extract the bytes belonging to the map and the key.
        let (entry_map, entry_key) = get_map_and_key(map_key)
            .map_err(|err| {
                error!("{}", &flatten_error(err.context("RocksDB Iter deserialize(key) error")));
            })
            .ok()?;

        // Deserialize the map, key, and value.
        let map = unchecked_deserialize(entry_map)
            .map_err(|err| {
                let err: anyhow::Error = err.into();
                error!("{}", &flatten_error(err.context("RocksDB NestedIter deserialize(map) error")));
            })
            .ok()?;
        let key = unchecked_deserialize(entry_key)
            .map_err(|err| {
                let err: anyhow::Error = err.into();
                error!("{}", &flatten_error(err.context("RocksDB NestedIter deserialize(key) error")));
            })
            .ok()?;
        // Deserialize the value.
        let value = unchecked_deserialize(value)
            .map_err(|err| {
                let err: anyhow::Error = err.into();
                error!("{}", &flatten_error(err.context("RocksDB NestedIter deserialize(value) error")));
            })
            .ok()?;

        self.db_iter.next();

        Some((Cow::Owned(map), Cow::Owned(key), Cow::Owned(value)))
    }
}

/// An iterator over the keys of a prefix.
pub struct NestedKeys<
    'a,
    M: 'a + Clone + Debug + PartialEq + Eq + Hash + Serialize + DeserializeOwned,
    K: 'a + Clone + Debug + PartialEq + Eq + Serialize + DeserializeOwned,
> {
    db_iter: rocksdb::DBRawIterator<'a>,
    _phantom: PhantomData<(M, K)>,
}

impl<
    'a,
    M: 'a + Clone + Debug + PartialEq + Eq + Hash + Serialize + DeserializeOwned,
    K: 'a + Clone + Debug + PartialEq + Eq + Serialize + DeserializeOwned,
> NestedKeys<'a, M, K>
{
    pub(crate) fn new(db_iter: rocksdb::DBIterator<'a>) -> Self {
        Self { db_iter: db_iter.into(), _phantom: PhantomData }
    }
}

impl<
    'a,
    M: 'a + Clone + Debug + PartialEq + Eq + Hash + Serialize + DeserializeOwned,
    K: 'a + Clone + Debug + PartialEq + Eq + Serialize + DeserializeOwned,
> Iterator for NestedKeys<'a, M, K>
{
    type Item = (Cow<'a, M>, Cow<'a, K>);

    fn next(&mut self) -> Option<Self::Item> {
        if !self.db_iter.valid() {
            return None;
        }

        let map_key = self.db_iter.key()?;

        // Extract the bytes belonging to the map and the key.
        let (entry_map, entry_key) = get_map_and_key(map_key)
            .map_err(|err| {
                error!("{}", &flatten_error(err.context("RocksDB  NestedKeys get_map_and_key error")));
            })
            .ok()?;

        // Deserialize the map and key.
        let map = unchecked_deserialize(entry_map)
            .map_err(|err| {
                let err: anyhow::Error = err.into();
                error!("{}", &flatten_error(err.context("RocksDB  NestedKeys deserialize(map) error")));
            })
            .ok()?;
        let key = unchecked_deserialize(entry_key)
            .map_err(|err| {
                let err: anyhow::Error = err.into();
                error!("{}", &flatten_error(err.context("RocksDB  NestedKeys deserialize(key) error")));
            })
            .ok()?;

        self.db_iter.next();

        Some((Cow::Owned(map), Cow::Owned(key)))
    }
}

/// An iterator over the values of a prefix.
pub struct NestedValues<'a, V: 'a + Serialize + DeserializeOwned> {
    db_iter: rocksdb::DBRawIterator<'a>,
    _phantom: PhantomData<V>,
}

impl<'a, V: 'a + Serialize + DeserializeOwned> NestedValues<'a, V> {
    pub(crate) fn new(db_iter: rocksdb::DBIterator<'a>) -> Self {
        Self { db_iter: db_iter.into(), _phantom: PhantomData }
    }
}

impl<'a, V: 'a + Clone + Serialize + DeserializeOwned> Iterator for NestedValues<'a, V> {
    type Item = Cow<'a, V>;

    fn next(&mut self) -> Option<Self::Item> {
        if !self.db_iter.valid() {
            return None;
        }

        let value = self.db_iter.value()?;

        // Deserialize the value.
        let value = unchecked_deserialize(value)
            .map_err(|err| {
                let err: anyhow::Error = err.into();
                error!("{}", &flatten_error(err.context("RocksDB  NestedValues deserialize(values) error")));
            })
            .ok()?;

        self.db_iter.next();

        Some(Cow::Owned(value))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        FinalizeMode,
        atomic_batch_scope,
        atomic_finalize,
        helpers::{
            rocksdb::{MapID, TestMap},
            traits::Map,
        },
    };
    use console::{
        account::{Address, FromStr},
        network::MainnetV0,
    };

    use anyhow::{anyhow, bail};
    use tracing_test::traced_test;

    type CurrentNetwork = MainnetV0;

    // Below are a few objects that mimic the way our NestedDataMaps are organized,
    // in order to provide a more accurate test setup for some scenarios.

    fn open_map_testing_from_db<
        M: Serialize + DeserializeOwned,
        K: Serialize + DeserializeOwned,
        V: Serialize + DeserializeOwned,
        T: Into<u16>,
    >(
        database: RocksDB,
        map_id: T,
    ) -> NestedDataMap<M, K, V> {
        // Combine contexts to create a new scope.
        let mut context = database.network_id.to_le_bytes().to_vec();
        context.extend_from_slice(&(map_id.into()).to_le_bytes());

        // Return the NestedDataMap.
        NestedDataMap {
            database,
            context,
            atomic_batch: Default::default(),
            batch_in_progress: Default::default(),
            atomic_owner: Default::default(),
            checkpoints: Default::default(),
        }
    }

    fn open_non_nested_map_testing_from_db<
        K: Serialize + DeserializeOwned,
        V: Serialize + DeserializeOwned,
        T: Into<u16>,
    >(
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
        own_map: NestedDataMap<usize, usize, String>,
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
                && self.extra_maps.extra_maps.own_nested_map.is_atomic_in_progress()
        }
    }

    struct TestStorage2 {
        own_map1: NestedDataMap<usize, usize, String>,
        own_map2: NestedDataMap<usize, usize, String>,
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
        own_nested_map: NestedDataMap<usize, usize, String>,
        own_map: DataMap<usize, String>,
    }

    impl TestStorage3 {
        fn open(database: RocksDB) -> Self {
            Self {
                own_nested_map: open_map_testing_from_db(database.clone(), MapID::Test(TestMap::Test4)),
                own_map: open_non_nested_map_testing_from_db(database, MapID::Test(TestMap::Test5)),
            }
        }

        fn start_atomic(&self) {
            self.own_nested_map.start_atomic();
            self.own_map.start_atomic();
        }

        fn is_atomic_in_progress(&self) -> bool {
            self.own_nested_map.is_atomic_in_progress() || self.own_map.is_atomic_in_progress()
        }

        fn atomic_checkpoint(&self) {
            self.own_nested_map.atomic_checkpoint();
            self.own_map.atomic_checkpoint();
        }

        fn clear_latest_checkpoint(&self) {
            self.own_nested_map.clear_latest_checkpoint();
            self.own_map.clear_latest_checkpoint();
        }

        fn atomic_rewind(&self) {
            self.own_nested_map.atomic_rewind();
            self.own_map.atomic_rewind();
        }

        fn finish_atomic(&self) -> Result<()> {
            self.own_nested_map.finish_atomic()?;
            self.own_map.finish_atomic()
        }

        fn abort_atomic(&self) {
            self.own_nested_map.abort_atomic();
            self.own_map.abort_atomic();
        }
    }

    #[test]
    fn test_contains_key_sanity_check() {
        // Initialize 'm'.
        let m = 0usize;
        // Initialize an address.
        let address =
            Address::<CurrentNetwork>::from_str("aleo1q6qstg8q8shwqf5m6q5fcenuwsdqsvp4hhsgfnx5chzjm3secyzqt9mxm8")
                .unwrap();

        // Initialize a map.
        let map: NestedDataMap<usize, Address<CurrentNetwork>, ()> =
            RocksDB::open_nested_map(0, StorageMode::new_test(None), MapID::Test(TestMap::Test))
                .expect("Failed to open data map");
        map.insert(m, address, ()).expect("Failed to insert into data map");
        assert!(map.contains_key_confirmed(&m, &address).unwrap());
    }

    #[test]
    #[traced_test]
    fn test_insert_and_get_value_speculative() {
        // Initialize a map.
        let map: NestedDataMap<usize, usize, String> =
            RocksDB::open_nested_map(0, StorageMode::new_test(None), MapID::Test(TestMap::Test))
                .expect("Failed to open data map");

        crate::helpers::test_helpers::nested_map::check_insert_and_get_value_speculative(map);
    }

    #[test]
    #[traced_test]
    fn test_remove_key_and_get_value_speculative() {
        // Initialize a map.
        let map: NestedDataMap<usize, usize, String> =
            RocksDB::open_nested_map(0, StorageMode::new_test(None), MapID::Test(TestMap::Test))
                .expect("Failed to open data map");

        crate::helpers::test_helpers::nested_map::check_remove_and_get_value_speculative(map);
    }

    #[test]
    #[traced_test]
    fn test_contains_key() {
        // Initialize a map.
        let map: NestedDataMap<usize, usize, String> =
            RocksDB::open_nested_map(0, StorageMode::new_test(None), MapID::Test(TestMap::Test))
                .expect("Failed to open data map");

        crate::helpers::test_helpers::nested_map::check_contains_key(map);
    }

    #[test]
    #[traced_test]
    fn test_get_map() {
        // Initialize a map.
        let map: NestedDataMap<usize, usize, String> =
            RocksDB::open_nested_map(0, StorageMode::new_test(None), MapID::Test(TestMap::Test))
                .expect("Failed to open data map");

        crate::helpers::test_helpers::nested_map::check_get_map(map);
    }

    #[test]
    #[traced_test]
    fn test_check_iterators_match() {
        // Initialize a map.
        let map: NestedDataMap<usize, usize, String> =
            RocksDB::open_nested_map(0, StorageMode::new_test(None), MapID::Test(TestMap::Test))
                .expect("Failed to open data map");

        crate::helpers::test_helpers::nested_map::check_iterators_match(map);
    }

    #[test]
    #[traced_test]
    fn test_iter_from_nested_to_non_nested() {
        // Open a storage with a DataMap right after a NestedDataMap.
        let database = RocksDB::open(0, StorageMode::new_test(None)).expect("Failed to open a test database");
        let test_storage = TestStorage3::open(database);

        // Insert 5 (confirmed) records into a nested map 77.
        for i in 0..5 {
            test_storage.own_nested_map.insert(77, i, i.to_string()).expect("Failed to insert");
        }

        // Insert 5 (confirmed) records into the neighboring data map; the keys are large on purpose.
        for i in 0..5 {
            test_storage.own_map.insert(usize::MAX - i, (usize::MAX - i).to_string()).expect("Failed to insert");
        }

        // We should be able to collect the 5 records from the nested data map.
        let confirmed = test_storage.own_nested_map.get_map_confirmed(&77).unwrap();
        assert_eq!(confirmed.len(), 5);
    }

    #[test]
    #[traced_test]
    fn test_atomic_writes_are_batched() {
        // Initialize a map.
        let map: NestedDataMap<usize, usize, String> =
            RocksDB::open_nested_map(0, StorageMode::new_test(None), MapID::Test(TestMap::Test))
                .expect("Failed to open data map");

        crate::helpers::test_helpers::nested_map::check_atomic_writes_are_batched(map);
    }

    #[test]
    #[traced_test]
    fn test_atomic_writes_can_be_aborted() {
        // Initialize a map.
        let map: NestedDataMap<usize, usize, String> =
            RocksDB::open_nested_map(0, StorageMode::new_test(None), MapID::Test(TestMap::Test))
                .expect("Failed to open data map");

        crate::helpers::test_helpers::nested_map::check_atomic_writes_can_be_aborted(map);
    }

    #[test]
    fn test_checkpoint_and_rewind() {
        // The number of items that will be queued to be inserted into the map.
        const NUM_ITEMS: usize = 10;

        // Initialize a map.
        let map: NestedDataMap<usize, usize, String> =
            RocksDB::open_nested_map(0, StorageMode::new_test(None), MapID::Test(TestMap::Test))
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
                map.insert(i, i, i.to_string()).unwrap();
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
                    map.insert(i, i, i.to_string()).unwrap();
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
        let map: NestedDataMap<usize, usize, String> =
            RocksDB::open_nested_map(0, StorageMode::new_test(None), MapID::Test(TestMap::Test))
                .expect("Failed to open data map");
        // Sanity check.
        assert!(map.iter_confirmed().next().is_none());
        // Make sure the checkpoint index is None.
        assert_eq!(map.checkpoints.lock().last(), None);

        // Start a nested atomic batch scope that completes successfully.
        atomic_batch_scope!(map, {
            // Queue (since a batch is in progress) NUM_ITEMS / 2 insertions.
            for i in 0..NUM_ITEMS / 2 {
                map.insert(i, i, i.to_string()).unwrap();
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
                    map.insert(i, i, i.to_string()).unwrap();
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
        let map: NestedDataMap<usize, usize, String> =
            RocksDB::open_nested_map(0, StorageMode::new_test(None), MapID::Test(TestMap::Test))
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
                    map.insert(i, i, i.to_string()).unwrap();
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
                        map.insert(i, i, i.to_string()).unwrap();
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
        let map: NestedDataMap<usize, usize, String> =
            RocksDB::open_nested_map(0, StorageMode::new_test(None), MapID::Test(TestMap::Test))
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
                    map.insert(i, i, i.to_string()).unwrap();
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
                    map.insert(i, i, i.to_string()).unwrap();
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
        let map: NestedDataMap<usize, usize, String> =
            RocksDB::open_nested_map(0, StorageMode::new_test(None), MapID::Test(TestMap::Test))
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
                    map.insert(i, i, i.to_string()).unwrap();
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
                    map.insert(i, i, i.to_string()).unwrap();
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
        let map: NestedDataMap<usize, usize, String> =
            RocksDB::open_nested_map(0, StorageMode::new_test(None), MapID::Test(TestMap::Test))
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
        let map: NestedDataMap<usize, usize, String> =
            RocksDB::open_nested_map(0, StorageMode::new_test(None), MapID::Test(TestMap::Test))
                .expect("Failed to open data map");
        // Sanity check.
        assert!(map.iter_confirmed().next().is_none());
        // Make sure the checkpoint index is None.
        assert_eq!(map.checkpoints.lock().last(), None);

        // Insert the key.
        map.insert(0, 0, "0".to_string()).unwrap();

        // Start an atomic finalize.
        let outcome = atomic_batch_scope!(map, {
            // Insert the key.
            map.insert(0, 0, "1".to_string()).unwrap();

            assert_eq!(map.checkpoints.lock().last(), None);

            // Create a failing atomic batch scope that will reset the checkpoint.
            let result: Result<()> = atomic_batch_scope!(map, {
                // Make sure the checkpoint index is 1.
                assert_eq!(map.checkpoints.lock().last(), Some(&1));

                // Update the key.
                map.insert(0, 0, "2".to_string()).unwrap();

                bail!("This batch scope should fail.")
            });

            // Ensure that the batch scope failed.
            assert!(result.is_err());
            // The map should contain 1 item.
            assert_eq!(map.iter_confirmed().count(), 1);
            // The pending batch should contain 1 item.
            assert_eq!(map.iter_pending().count(), 1);
            // Ensure the pending operations still has the initial insertion.
            assert_eq!(map.get_value_pending(&0, &0), Some(Some("1".to_string())));
            // Ensure the confirmed value has not changed.
            assert_eq!(
                map.iter_confirmed().next().unwrap(),
                (Cow::Owned(0), Cow::Owned(0), Cow::Owned("0".to_string()))
            );
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
        assert_eq!(map.iter_confirmed().next().unwrap(), (Cow::Owned(0), Cow::Owned(0), Cow::Owned("1".to_string())));
    }

    #[test]
    fn test_atomic_finalize_with_nested_batch_scope() -> Result<()> {
        // Initialize a map.
        let map: NestedDataMap<usize, usize, String> =
            RocksDB::open_nested_map(0, StorageMode::new_test(None), MapID::Test(TestMap::Test))
                .expect("Failed to open data map");
        // Sanity check.
        assert!(map.iter_confirmed().next().is_none());
        // Make sure the checkpoint index is None.
        assert_eq!(map.checkpoints.lock().last(), None);

        // Insert the key.
        map.insert(0, 0, "0".to_string()).unwrap();

        // Start an atomic finalize.
        let outcome = atomic_finalize!(map, FinalizeMode::RealRun, {
            // Create an atomic batch scope that will complete correctly.
            // Simulates an accepted transaction.
            let result: Result<()> = atomic_batch_scope!(map, {
                // Make sure the checkpoint index is 0.
                assert_eq!(map.checkpoints.lock().last(), Some(&0));

                // Insert the key.
                map.insert(0, 0, "1".to_string()).unwrap();

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
            assert_eq!(map.get_value_pending(&0, &0), Some(Some("1".to_string())));

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
                    map.insert(0, 0, "2".to_string()).unwrap();

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
                    map.insert(0, 0, "3".to_string()).unwrap();

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
            assert_eq!(map.get_value_pending(&0, &0), Some(Some("1".to_string())));
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
        assert_eq!(map.iter_confirmed().next().unwrap(), (Cow::Owned(0), Cow::Owned(0), Cow::Owned("1".to_string())));

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
        assert!(test_storage.extra_maps.extra_maps.own_nested_map.iter_confirmed().next().is_none());

        assert_eq!(test_storage.own_map.checkpoints.lock().last(), None);

        // Note: all the checks going through .database can be performed on any one
        // of the objects, as all of them share the same instance of the database.

        assert!(!test_storage.is_atomic_in_progress_everywhere());

        // Start an atomic write batch.
        atomic_batch_scope!(test_storage, {
            assert!(test_storage.is_atomic_in_progress_everywhere());

            assert_eq!(test_storage.own_map.checkpoints.lock().last(), None);

            // Write an item into the first map.
            test_storage.own_map.insert(0, 0, 0.to_string()).unwrap();

            // Start another atomic write batch.
            atomic_batch_scope!(test_storage.extra_maps.own_map1, {
                assert!(test_storage.is_atomic_in_progress_everywhere());

                // Write an item into the second map.
                test_storage.extra_maps.own_map1.insert(1, 1, 1.to_string()).unwrap();

                // Write an item into the third map.
                test_storage.extra_maps.own_map2.insert(2, 2, 2.to_string()).unwrap();

                // Start another atomic write batch.
                atomic_batch_scope!(test_storage.extra_maps.extra_maps.own_nested_map, {
                    assert!(test_storage.extra_maps.extra_maps.own_nested_map.is_atomic_in_progress());

                    // Write an item into the fourth map.
                    test_storage.extra_maps.extra_maps.own_nested_map.insert(3, 3, 3.to_string()).unwrap();

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
        assert_eq!(test_storage.extra_maps.own_map1.iter_confirmed().count(), 1);
        assert_eq!(test_storage.extra_maps.own_map2.iter_confirmed().count(), 1);
        assert_eq!(test_storage.extra_maps.extra_maps.own_nested_map.iter_confirmed().count(), 1);

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
                test_storage.own_map.insert(0, 0, 0.to_string()).unwrap();

                // Start another atomic write batch.
                atomic_batch_scope!(test_storage.extra_maps.own_map1, {
                    assert!(test_storage.is_atomic_in_progress_everywhere());

                    // Write an item into the second map.
                    test_storage.extra_maps.own_map1.insert(1, 1, 1.to_string()).unwrap();

                    // Write an item into the third map.
                    test_storage.extra_maps.own_map2.insert(2, 2, 2.to_string()).unwrap();

                    // Start another atomic write batch.
                    let result: Result<()> = atomic_batch_scope!(test_storage.extra_maps.extra_maps.own_nested_map, {
                        assert!(test_storage.is_atomic_in_progress_everywhere());

                        // Write an item into the fourth map.
                        test_storage.extra_maps.extra_maps.own_nested_map.insert(3, 3, 3.to_string()).unwrap();

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
        assert!(test_storage.extra_maps.extra_maps.own_nested_map.iter_confirmed().next().is_none());

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
        assert_eq!(test_storage.extra_maps.extra_maps.own_nested_map.iter_confirmed().count(), 0);
    }
}
