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

use crate::helpers::{NestedMap, NestedMapRead};
use console::network::prelude::*;
use snarkvm_utilities::bytes::unchecked_deserialize;

use anyhow::Context;
#[cfg(feature = "locktick")]
use locktick::parking_lot::{Mutex, RwLock};
#[cfg(not(feature = "locktick"))]
use parking_lot::{Mutex, RwLock};
use std::{
    borrow::Cow,
    collections::{BTreeMap, BTreeSet, btree_map},
    hash::Hash,
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
    time::Instant,
};

#[derive(Clone)]
pub struct NestedMemoryMap<
    M: Copy + Clone + PartialEq + Eq + Hash + Serialize + for<'de> Deserialize<'de> + Send + Sync,
    K: Clone + PartialEq + Eq + Serialize + for<'de> Deserialize<'de> + Send + Sync,
    V: Clone + Serialize + for<'de> Deserialize<'de> + Send + Sync,
> {
    // The reason for using BTreeMap with binary keys is for the order of items to be the same as
    // the one in the RocksDB-backed DataMap; if not for that, it could be any map
    // with fast lookups and the keys could be typed (i.e. just `K` instead of `Vec<u8>`).
    map: Arc<RwLock<BTreeMap<Vec<u8>, BTreeSet<Vec<u8>>>>>, // map -> keys
    map_inner: Arc<RwLock<BTreeMap<Vec<u8>, V>>>,           // map-key -> value
    batch_in_progress: Arc<AtomicBool>,
    /// Owner of the in-progress atomic batch (`0` = none).
    atomic_owner: Arc<AtomicU64>,
    atomic_batch: Arc<Mutex<Vec<(M, Option<K>, Option<V>)>>>,
    checkpoint: Arc<Mutex<Vec<usize>>>,
}

impl<
    M: Copy + Clone + PartialEq + Eq + Hash + Serialize + for<'de> Deserialize<'de> + Send + Sync,
    K: Clone + PartialEq + Eq + Serialize + for<'de> Deserialize<'de> + Send + Sync,
    V: Clone + Serialize + for<'de> Deserialize<'de> + Send + Sync,
> Default for NestedMemoryMap<M, K, V>
{
    fn default() -> Self {
        Self {
            map: Default::default(),
            map_inner: Default::default(),
            batch_in_progress: Default::default(),
            atomic_owner: Default::default(),
            atomic_batch: Default::default(),
            checkpoint: Default::default(),
        }
    }
}

impl<
    M: Copy + Clone + PartialEq + Eq + Hash + Serialize + for<'de> Deserialize<'de> + Send + Sync,
    K: Clone + PartialEq + Eq + Serialize + for<'de> Deserialize<'de> + Send + Sync,
    V: Clone + Serialize + for<'de> Deserialize<'de> + Send + Sync,
> FromIterator<(M, K, V)> for NestedMemoryMap<M, K, V>
{
    /// Initializes a new `NestedMemoryMap` from the given iterator.
    fn from_iter<I: IntoIterator<Item = (M, K, V)>>(iter: I) -> Self {
        // Initialize the maps.
        let mut map = BTreeMap::new();
        let mut map_inner = BTreeMap::new();

        // Insert each map-key-value pair into the map.
        for (m, k, v) in iter.into_iter() {
            insert(&mut map, &mut map_inner, &m, &k, v);
        }

        // Return the new map.
        Self {
            map: Arc::new(RwLock::new(map)),
            map_inner: Arc::new(RwLock::new(map_inner)),
            batch_in_progress: Default::default(),
            atomic_owner: Default::default(),
            atomic_batch: Default::default(),
            checkpoint: Default::default(),
        }
    }
}

impl<
    'a,
    M: 'a + Copy + Clone + PartialEq + Eq + Hash + Serialize + for<'de> Deserialize<'de> + Send + Sync,
    K: 'a + Clone + PartialEq + Eq + Serialize + for<'de> Deserialize<'de> + Send + Sync,
    V: 'a + Clone + Serialize + for<'de> Deserialize<'de> + Send + Sync,
> NestedMap<'a, M, K, V> for NestedMemoryMap<M, K, V>
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
            false => insert(&mut self.map.write(), &mut self.map_inner.write(), &map, &key, value),
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
            false => remove_map(&mut self.map.write(), &mut self.map_inner.write(), map),
        }
        Ok(())
    }

    ///
    /// Removes the key-value pair for the given map and key.
    ///
    fn remove_key(&self, map: &M, key: &K) -> Result<()> {
        // Determine if an atomic batch is in progress.
        match self.is_atomic_in_progress() {
            // If a batch is in progress, add the key-None pair to the batch.
            true => self.atomic_batch.lock().push((*map, Some(key.clone()), None)),
            // Otherwise, remove the key-value pair directly from the map.
            false => remove_key(&mut self.map.write(), &mut self.map_inner.write(), map, key),
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
        // Ensure that the atomic batch is empty.
        assert!(
            self.atomic_batch.lock().is_empty(),
            "Cannot start an atomic operation while another one is already in progress"
        );
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
        self.checkpoint.lock().push(self.atomic_batch.lock().len());
    }

    ///
    /// Removes the latest atomic checkpoint.
    ///
    fn clear_latest_checkpoint(&self) {
        // Removes the latest checkpoint.
        let _ = self.checkpoint.lock().pop();
    }

    ///
    /// Removes all pending operations to the last `atomic_checkpoint`
    /// (or to `start_atomic` if no checkpoints have been created).
    ///
    fn atomic_rewind(&self) {
        // Acquire the write lock on the atomic batch.
        let mut atomic_batch = self.atomic_batch.lock();

        // Retrieve the last checkpoint.
        let checkpoint = self.checkpoint.lock().pop().unwrap_or(0);

        // Remove all operations after the checkpoint.
        atomic_batch.truncate(checkpoint);
    }

    ///
    /// Aborts the current atomic operation.
    ///
    fn abort_atomic(&self) {
        // Clear the atomic batch.
        *self.atomic_batch.lock() = Default::default();
        // Clear the checkpoint stack.
        *self.checkpoint.lock() = Default::default();
        // Set the atomic batch flag to `false`.
        self.batch_in_progress.store(false, Ordering::SeqCst);
        crate::helpers::atomic_owner::release(&self.atomic_owner);
    }

    ///
    /// Finishes an atomic operation, performing all the queued writes.
    ///
    fn finish_atomic(&self) -> Result<()> {
        // Retrieve the atomic batch.
        let operations = core::mem::take(&mut *self.atomic_batch.lock());

        if !operations.is_empty() {
            // Acquire a write lock on the map.
            let mut map = self.map.write();
            let mut map_inner = self.map_inner.write();

            // Perform all the queued operations.
            for (m, k, v) in operations {
                match (k, v) {
                    (Some(k), Some(v)) => insert(&mut map, &mut map_inner, &m, &k, v),
                    (None, None) => remove_map(&mut map, &mut map_inner, &m),
                    (Some(k), None) => remove_key(&mut map, &mut map_inner, &m, &k),
                    (None, Some(_)) => unreachable!("Cannot remove a key-value pair from a map without a key."),
                }
            }
        }

        // Clear the checkpoint stack.
        *self.checkpoint.lock() = Default::default();
        // Set the atomic batch flag to `false`.
        self.batch_in_progress.store(false, Ordering::SeqCst);
        crate::helpers::atomic_owner::release(&self.atomic_owner);

        Ok(())
    }
}

impl<
    'a,
    M: 'a + Copy + Clone + PartialEq + Eq + Hash + Serialize + for<'de> Deserialize<'de> + Send + Sync,
    K: 'a + Clone + PartialEq + Eq + Serialize + for<'de> Deserialize<'de> + Send + Sync,
    V: 'a + Clone + Serialize + for<'de> Deserialize<'de> + Send + Sync,
> NestedMapRead<'a, M, K, V> for NestedMemoryMap<M, K, V>
{
    // type Iterator = core::iter::FlatMap<
    //     btree_map::IntoIter<Vec<u8>, BTreeSet<Vec<u8>>>,
    //     core::iter::Map<btree_set::IntoIter<Vec<u8>>, fn(Vec<u8>) -> (Cow<'a, M>, Cow<'a, K>, Cow<'a, V>)>,
    //     fn((Vec<u8>, BTreeSet<Vec<u8>>)) -> core::iter::Map<btree_set::IntoIter<Vec<u8>>, fn(Vec<u8>) -> (Cow<'a, M>, Cow<'a, K>, Cow<'a, V>)>
    // >;
    type Iterator = std::vec::IntoIter<(Cow<'a, M>, Cow<'a, K>, Cow<'a, V>)>;
    // type Keys = core::iter::FlatMap<
    //     btree_map::IntoIter<Vec<u8>, BTreeSet<Vec<u8>>>,
    //     core::iter::Map<btree_set::IntoIter<Vec<u8>>, fn(Vec<u8>) -> (Cow<'a, M>, Cow<'a, K>)>,
    //     fn((Vec<u8>, BTreeSet<Vec<u8>>)) -> core::iter::Map<btree_set::IntoIter<Vec<u8>>, fn(Vec<u8>) -> (Cow<'a, M>, Cow<'a, K>)>
    // >;
    type Keys = std::vec::IntoIter<(Cow<'a, M>, Cow<'a, K>)>;
    // type Keys = core::iter::Flatten<
    //     core::iter::Map<btree_map::IntoIter<Vec<u8>, BTreeSet<Vec<u8>>>, fn((Vec<u8>, BTreeSet<Vec<u8>>)) -> core::iter::Map<btree_set::IntoIter<Vec<u8>>,
    //         fn(Vec<u8>) -> (Cow<'a, M>, Cow<'a, K>)>>
    // >;
    type PendingIterator = core::iter::Map<
        std::vec::IntoIter<(M, Option<K>, Option<V>)>,
        fn((M, Option<K>, Option<V>)) -> (Cow<'a, M>, Option<Cow<'a, K>>, Option<Cow<'a, V>>),
    >;
    type Values = core::iter::Map<btree_map::IntoValues<Vec<u8>, V>, fn(V) -> Cow<'a, V>>;

    ///
    /// Returns the number of confirmed entries in the map.
    ///
    fn len_map_confirmed(&self, map: &M) -> Result<usize> {
        // Serialize 'm'.
        let m = bincode::serialize(map)?;
        // Retrieve the keys for the serialized map.
        Ok(self.map.read().get(&m).map(|keys| keys.len()).unwrap_or_default())
    }

    ///
    /// Returns `true` if the given key exists in the map.
    ///
    fn contains_key_confirmed(&self, map: &M, key: &K) -> Result<bool> {
        // Serialize 'm'.
        let m = bincode::serialize(map).with_context(|| "Failed to serialize map")?;
        // Concatenate 'm' and 'k' with a 0-byte separator.
        let mk = to_map_key(&m, &bincode::serialize(key).with_context(|| "Failed to serialize map key")?);
        // Return whether the concatenated key exists in the map.
        Ok(self.map_inner.read().contains_key(&mk))
    }

    ///
    /// Returns `true` if the given key exists in the map.
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
    /// Returns the confirmed key-value pairs for the given map, if it exists.
    ///
    fn get_map_confirmed(&'a self, map: &M) -> Result<Vec<(K, V)>> {
        // Serialize 'm'.
        let m = bincode::serialize(map)?;
        // Retrieve the keys for the serialized map.
        let Some(keys) = self.map.read().get(&m).cloned() else {
            return Ok(Default::default());
        };

        // Acquire the read lock on 'map_inner'.
        let map_inner = self.map_inner.read();
        // Return an iterator over each key.
        let key_values = keys
            .into_iter()
            .map(|k| {
                // Deserialize 'k'.
                let key: K = unchecked_deserialize(&k).unwrap();
                // Concatenate 'm' and 'k' with a 0-byte separator.
                let mk = to_map_key(&m, &k);
                // Return the key-value pair.
                (key, map_inner.get(&mk).unwrap().clone())
            })
            .collect::<Vec<_>>();

        // Return the key-value pairs for the serialized map.
        Ok(key_values)
    }

    ///
    /// Returns the speculative key-value pairs for the given map, if it exists.
    ///
    fn get_map_speculative(&'a self, map: &M) -> Result<Vec<(K, V)>> {
        // If there is no atomic batch in progress on this thread, then return the confirmed key-value pairs.
        if !crate::helpers::atomic_owner::consults_atomic_batch(self.is_atomic_in_progress(), &self.atomic_owner) {
            return self.get_map_confirmed(map);
        }

        // Retrieve the confirmed key-value pairs for the given map.
        let mut key_values = self.get_map_confirmed(map)?;

        // Retrieve the atomic batch.
        let operations = self.atomic_batch.lock().clone();

        if !operations.is_empty() {
            // Perform all the queued operations.
            for (m, k, v) in operations {
                // If the map does not match the given map, then continue.
                if &m != map {
                    continue;
                }

                // Perform the operation.
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
    /// Returns the value for the given key from the map, if it exists.
    ///
    fn get_value_confirmed(&'a self, map: &M, key: &K) -> Result<Option<Cow<'a, V>>> {
        // Serialize 'm'.
        let m = bincode::serialize(map)?;
        // Concatenate 'm' and 'k' with a 0-byte separator.
        let mk = to_map_key(&m, &bincode::serialize(key)?);
        // Return the value for the concatenated key.
        Ok(self.map_inner.read().get(&mk).cloned().map(Cow::Owned))
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
    /// Returns an iterator visiting each map-key-value pair in the atomic batch.
    ///
    fn iter_pending(&'a self) -> Self::PendingIterator {
        self.atomic_batch.lock().clone().into_iter().map(|(m, k, v)| {
            // Return the map-key-value triple.
            (Cow::Owned(m), k.map(Cow::Owned), v.map(Cow::Owned))
        })
    }

    ///
    /// Returns an iterator visiting each confirmed map-key-value pair.
    ///
    fn iter_confirmed(&'a self) -> Self::Iterator {
        // Note: The 'unwrap' is safe here, because the maps and keys are defined by us.
        self.map
            .read()
            .clone()
            .into_iter()
            .flat_map(|(map, keys)| {
                // Acquire the read lock on 'map_inner'.
                let map_inner = self.map_inner.read();
                // Deserialize 'map'.
                let m = unchecked_deserialize(&map).unwrap();
                // Return an iterator over each key.
                keys.into_iter().map(move |k| {
                    // Deserialize 'k'.
                    let key = unchecked_deserialize(&k).unwrap();
                    // Concatenate 'm' and 'k' with a 0-byte separator.
                    let mk = to_map_key(&map, &k);
                    // Return the map-key-value triple.
                    (Cow::Owned(m), Cow::Owned(key), Cow::Owned(map_inner.get(&mk).unwrap().clone()))
                })
            })
            .collect::<Vec<_>>()
            .into_iter()
    }

    ///
    /// Returns an iterator over each confirmed key.
    ///
    fn keys_confirmed(&'a self) -> Self::Keys {
        // Note: The 'unwrap' is safe here, because the maps and keys are defined by us.
        self.map
            .read()
            .clone()
            .into_iter()
            .flat_map(|(map, keys)| {
                // Deserialize 'map'.
                let m: M = unchecked_deserialize(&map).unwrap();
                // Return an iterator over each key.
                keys.into_iter().map(move |k| (Cow::Owned(m), Cow::Owned(unchecked_deserialize(&k).unwrap())))
            })
            .collect_vec()
            .into_iter()
    }

    ///
    /// Returns an iterator over each confirmed value.
    ///
    fn values_confirmed(&'a self) -> Self::Values {
        self.map_inner.read().clone().into_values().map(Cow::Owned)
    }
}

/// Inserts the given map-key-value pair.
fn insert<
    M: Copy + Clone + PartialEq + Eq + Hash + Serialize + for<'de> Deserialize<'de> + Send + Sync,
    K: Clone + PartialEq + Eq + Serialize + for<'de> Deserialize<'de> + Send + Sync,
    V: Clone + Serialize + for<'de> Deserialize<'de> + Send + Sync,
>(
    map: &mut BTreeMap<Vec<u8>, BTreeSet<Vec<u8>>>,
    map_inner: &mut BTreeMap<Vec<u8>, V>,
    m: &M,
    k: &K,
    v: V,
) {
    // Note: The 'unwrap' is safe here, because the maps and keys are defined by us.

    // Serialize 'm'.
    let m = bincode::serialize(m).unwrap();
    // Serialize 'k'.
    let k = bincode::serialize(k).unwrap();
    // Concatenate 'm' and 'k' with a 0-byte separator.
    let mk = to_map_key(&m, &k);

    map.entry(m).or_default().insert(k);
    map_inner.insert(mk, v);
}

/// Removes the given map-key pair.
fn remove_map<
    M: Copy + Clone + PartialEq + Eq + Hash + Serialize + for<'de> Deserialize<'de> + Send + Sync,
    V: Clone + Serialize + for<'de> Deserialize<'de> + Send + Sync,
>(
    map: &mut BTreeMap<Vec<u8>, BTreeSet<Vec<u8>>>,
    map_inner: &mut BTreeMap<Vec<u8>, V>,
    m: &M,
) {
    // Note: The 'unwrap' is safe here, because the maps and keys are defined by us.

    // Serialize 'm'.
    let m = bincode::serialize(m).unwrap();
    // Remove 'm'.
    let keys = map.remove(&m);
    // Iteratively remove the key-value pairs.
    if let Some(keys) = keys {
        for k in keys {
            // Concatenate 'm' and 'k' with a 0-byte separator.
            let mk = to_map_key(&m, &k);
            map_inner.remove(&mk);
        }
    }
}

/// Removes the given map-key pair.
fn remove_key<
    M: Copy + Clone + PartialEq + Eq + Hash + Serialize + for<'de> Deserialize<'de> + Send + Sync,
    K: Clone + PartialEq + Eq + Serialize + for<'de> Deserialize<'de> + Send + Sync,
    V: Clone + Serialize + for<'de> Deserialize<'de> + Send + Sync,
>(
    map: &mut BTreeMap<Vec<u8>, BTreeSet<Vec<u8>>>,
    map_inner: &mut BTreeMap<Vec<u8>, V>,
    m: &M,
    k: &K,
) {
    // Note: The 'unwrap' is safe here, because the maps and keys are defined by us.

    // Serialize 'm'.
    let m = bincode::serialize(m).unwrap();
    // Serialize 'k'.
    let k = bincode::serialize(k).unwrap();
    // Concatenate 'm' and 'k' with a 0-byte separator.
    let mk = to_map_key(&m, &k);

    map.entry(m).or_default().remove(&k);
    map_inner.remove(&mk);
}

/// Returns the concatenated map-key.
fn to_map_key(m: &[u8], k: &[u8]) -> Vec<u8> {
    // Concatenate 'm' and 'k' with a 0-byte separator.
    let mut mk = Vec::with_capacity(m.len() + 1 + k.len());
    mk.extend_from_slice(m);
    mk.push(0u8);
    mk.extend_from_slice(k);
    // Return 'mk'.
    mk
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{FinalizeMode, atomic_batch_scope, atomic_finalize};
    use console::{account::Address, network::MainnetV0};

    type CurrentNetwork = MainnetV0;

    #[test]
    fn test_contains_key_sanity_check() {
        use indexmap::IndexMap;

        // Initialize 'm'.
        let m = 0;
        // Initialize an address.
        let address =
            Address::<CurrentNetwork>::from_str("aleo1q6qstg8q8shwqf5m6q5fcenuwsdqsvp4hhsgfnx5chzjm3secyzqt9mxm8")
                .unwrap();

        // Sanity check.
        let addresses: IndexMap<(usize, Address<CurrentNetwork>), ()> = [((m, address), ())].into_iter().collect();
        assert!(addresses.contains_key(&(m, address)));

        // Initialize a map.
        let map: NestedMemoryMap<usize, Address<CurrentNetwork>, ()> = [(m, address, ())].into_iter().collect();
        assert!(map.contains_key_confirmed(&m, &address).unwrap());
    }

    #[test]
    fn test_insert_and_get_value_speculative() {
        // Initialize a map.
        let map: NestedMemoryMap<usize, usize, String> = Default::default();

        crate::helpers::test_helpers::nested_map::check_insert_and_get_value_speculative(map);
    }

    #[test]
    fn test_remove_and_get_value_speculative() {
        // Initialize a map.
        let map: NestedMemoryMap<usize, usize, String> = Default::default();

        crate::helpers::test_helpers::nested_map::check_remove_and_get_value_speculative(map);
    }

    #[test]
    fn test_contains_key() {
        // Initialize a map.
        let map: NestedMemoryMap<usize, usize, String> = Default::default();

        crate::helpers::test_helpers::nested_map::check_contains_key(map);
    }

    #[test]
    fn test_get_map() {
        // Initialize a map.
        let map: NestedMemoryMap<usize, usize, String> = Default::default();

        crate::helpers::test_helpers::nested_map::check_get_map(map);
    }

    #[test]
    fn test_check_iterators_match() {
        // Initialize a map.
        let map: NestedMemoryMap<usize, usize, String> = Default::default();

        crate::helpers::test_helpers::nested_map::check_iterators_match(map);
    }

    #[test]
    fn test_atomic_writes_are_batched() {
        // Initialize a map.
        let map: NestedMemoryMap<usize, usize, String> = Default::default();

        crate::helpers::test_helpers::nested_map::check_atomic_writes_are_batched(map);
    }

    #[test]
    fn test_atomic_writes_can_be_aborted() {
        // Initialize a map.
        let map: NestedMemoryMap<usize, usize, String> = Default::default();

        crate::helpers::test_helpers::nested_map::check_atomic_writes_can_be_aborted(map);
    }

    #[test]
    fn test_checkpoint_and_rewind() {
        // The number of items that will be queued to be inserted into the map.
        const NUM_ITEMS: usize = 10;

        // Initialize a map.
        let map: NestedMemoryMap<usize, usize, String> = Default::default();
        // Sanity check.
        assert!(map.iter_confirmed().next().is_none());
        // Make sure the checkpoint index is None.
        assert_eq!(map.checkpoint.lock().last(), None);

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
            assert_eq!(map.checkpoint.lock().last(), None);
        }

        // Run the same sequence of checks 3 times.
        for _ in 0..3 {
            // Perform a checkpoint.
            map.atomic_checkpoint();
            // Make sure the checkpoint index is NUM_ITEMS / 2.
            assert_eq!(map.checkpoint.lock().last(), Some(&(NUM_ITEMS / 2)));

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
                assert_eq!(map.checkpoint.lock().last(), Some(&(NUM_ITEMS / 2)));
            }

            // Abort the current atomic write batch.
            map.atomic_rewind();
            // Make sure the checkpoint index is None.
            assert_eq!(map.checkpoint.lock().last(), None);

            {
                // The map should still contain no items.
                assert!(map.iter_confirmed().next().is_none());
                // The pending batch should contain NUM_ITEMS / 2 items.
                assert_eq!(map.iter_pending().count(), NUM_ITEMS / 2);
                // Make sure the checkpoint index is None.
                assert_eq!(map.checkpoint.lock().last(), None);
            }
        }

        // Finish the atomic batch.
        map.finish_atomic().unwrap();
        // The map should contain NUM_ITEMS / 2.
        assert_eq!(map.iter_confirmed().count(), NUM_ITEMS / 2);
        // The pending batch should contain no items.
        assert!(map.iter_pending().next().is_none());
        // Make sure the checkpoint index is None.
        assert_eq!(map.checkpoint.lock().last(), None);
    }

    #[test]
    fn test_nested_atomic_batch_scope() -> Result<()> {
        // The number of items that will be queued to be inserted into the map.
        const NUM_ITEMS: usize = 10;

        // Initialize a map.
        let map: NestedMemoryMap<usize, usize, String> = Default::default();
        // Sanity check.
        assert!(map.iter_confirmed().next().is_none());
        // Make sure the checkpoint index is None.
        assert_eq!(map.checkpoint.lock().last(), None);

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
            assert_eq!(map.checkpoint.lock().last(), None);

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
                assert_eq!(map.checkpoint.lock().last(), Some(&(NUM_ITEMS / 2)));

                Ok(())
            })?;

            // The map should still contain no items.
            assert!(map.iter_confirmed().next().is_none());
            // The pending batch should contain NUM_ITEMS items.
            assert_eq!(map.iter_pending().count(), NUM_ITEMS);
            // Make sure the checkpoint index is None.
            assert_eq!(map.checkpoint.lock().last(), None);

            Ok(())
        })?;

        // The map should contain NUM_ITEMS.
        assert_eq!(map.iter_confirmed().count(), NUM_ITEMS);
        // The pending batch should contain no items.
        assert!(map.iter_pending().next().is_none());
        // Make sure the checkpoint index is None.
        assert_eq!(map.checkpoint.lock().last(), None);

        Ok(())
    }

    #[test]
    fn test_failed_nested_atomic_batch_scope() {
        // The number of items that will be queued to be inserted into the map.
        const NUM_ITEMS: usize = 10;

        // Initialize a map.
        let map: NestedMemoryMap<usize, usize, String> = Default::default();
        // Sanity check.
        assert!(map.iter_confirmed().next().is_none());
        // Make sure the checkpoint index is None.
        assert_eq!(map.checkpoint.lock().last(), None);

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
                assert_eq!(map.checkpoint.lock().last(), None);

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
                    assert_eq!(map.checkpoint.lock().last(), Some(&(NUM_ITEMS / 2)));

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
        let map: NestedMemoryMap<usize, usize, String> = Default::default();
        // Sanity check.
        assert!(map.iter_confirmed().next().is_none());
        // Make sure the checkpoint index is None.
        assert_eq!(map.checkpoint.lock().last(), None);

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
                assert_eq!(map.checkpoint.lock().last(), Some(&0));

                Ok(())
            })
            .unwrap();

            // The map should still contain no items.
            assert!(map.iter_confirmed().next().is_none());
            // The pending batch should contain NUM_ITEMS / 2 items.
            assert_eq!(map.iter_pending().count(), NUM_ITEMS / 2);
            // Make sure the checkpoint index is None.
            assert_eq!(map.checkpoint.lock().last(), None);

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
                assert_eq!(map.checkpoint.lock().last(), Some(&(NUM_ITEMS / 2)));

                Ok(())
            })
            .unwrap();

            // The map should still contain no items.
            assert!(map.iter_confirmed().next().is_none());
            // The pending batch should contain NUM_ITEMS items.
            assert_eq!(map.iter_pending().count(), NUM_ITEMS);
            // Make sure the checkpoint index is None.
            assert_eq!(map.checkpoint.lock().last(), None);

            Ok((true, 0, "a"))
        });

        // The atomic finalize should have passed the result through.
        assert_eq!(outcome.unwrap(), (true, 0, "a"));

        // The map should contain NUM_ITEMS.
        assert_eq!(map.iter_confirmed().count(), NUM_ITEMS);
        // The pending batch should contain no items.
        assert!(map.iter_pending().next().is_none());
        // Make sure the checkpoint index is None.
        assert_eq!(map.checkpoint.lock().last(), None);

        Ok(())
    }

    #[test]
    fn test_atomic_finalize_failing_internal_scope() -> Result<()> {
        // The number of items that will be queued to be inserted into the map.
        const NUM_ITEMS: usize = 10;

        // Initialize a map.
        let map: NestedMemoryMap<usize, usize, String> = Default::default();
        // Sanity check.
        assert!(map.iter_confirmed().next().is_none());
        // Make sure the checkpoint index is None.
        assert_eq!(map.checkpoint.lock().last(), None);

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
                assert_eq!(map.checkpoint.lock().last(), Some(&0));

                Ok(())
            })
            .unwrap();

            // The map should still contain no items.
            assert!(map.iter_confirmed().next().is_none());
            // The pending batch should contain NUM_ITEMS / 2 items.
            assert_eq!(map.iter_pending().count(), NUM_ITEMS / 2);
            // Make sure the checkpoint index is None.
            assert_eq!(map.checkpoint.lock().last(), None);

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
                assert_eq!(map.checkpoint.lock().last(), Some(&(NUM_ITEMS / 2)));

                bail!("This batch scope should fail.");
            });

            // Ensure that the batch scope failed.
            assert!(result.is_err());

            // The map should still contain no items.
            assert!(map.iter_confirmed().next().is_none());
            // The pending batch should contain NUM_ITEMS / 2 items.
            assert_eq!(map.iter_pending().count(), NUM_ITEMS / 2);
            // Make sure the checkpoint index is None.
            assert_eq!(map.checkpoint.lock().last(), None);

            Ok(())
        });

        // The atomic finalize should have succeeded.
        assert!(outcome.is_ok());

        // The map should contain NUM_ITEMS / 2.
        assert_eq!(map.iter_confirmed().count(), NUM_ITEMS / 2);
        // The pending batch should contain no items.
        assert!(map.iter_pending().next().is_none());
        // Make sure the checkpoint index is None.
        assert_eq!(map.checkpoint.lock().last(), None);

        Ok(())
    }

    #[test]
    fn test_atomic_finalize_fails_to_start() {
        // Initialize a map.
        let map: NestedMemoryMap<usize, usize, String> = Default::default();
        // Sanity check.
        assert!(map.iter_confirmed().next().is_none());
        // Make sure the checkpoint index is None.
        assert_eq!(map.checkpoint.lock().last(), None);

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
        let map: NestedMemoryMap<usize, usize, String> = Default::default();
        // Sanity check.
        assert!(map.iter_confirmed().next().is_none());
        // Make sure the checkpoint index is None.
        assert_eq!(map.checkpoint.lock().last(), None);

        // Insert the key.
        map.insert(0, 0, "0".to_string()).unwrap();

        // Start an atomic finalize.
        let outcome = atomic_batch_scope!(map, {
            // Insert the key.
            map.insert(0, 0, "1".to_string()).unwrap();

            // Create a failing atomic batch scope that will reset the checkpoint.
            let result: Result<()> = atomic_batch_scope!(map, {
                // Make sure the checkpoint index is 1.
                assert_eq!(map.checkpoint.lock().last(), Some(&1));

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

            Ok(())
        });

        assert!(outcome.is_ok());
        // The map should contain 1 item.
        assert_eq!(map.iter_confirmed().count(), 1);
        // The pending batch should contain no items.
        assert!(map.iter_pending().next().is_none());
        // Make sure the checkpoint index is None.
        assert_eq!(map.checkpoint.lock().last(), None);

        // Ensure that the map value is correct.
        assert_eq!(map.iter_confirmed().next().unwrap(), (Cow::Owned(0), Cow::Owned(0), Cow::Owned("1".to_string())));
    }

    #[test]
    fn test_atomic_finalize_with_nested_batch_scope() -> Result<()> {
        // Initialize a map.
        let map: NestedMemoryMap<usize, usize, String> = Default::default();
        // Sanity check.
        assert!(map.iter_confirmed().next().is_none());
        // Make sure the checkpoint index is None.
        assert_eq!(map.checkpoint.lock().last(), None);

        // Insert the key.
        map.insert(0, 0, "0".to_string()).unwrap();

        // Start an atomic finalize.
        let outcome = atomic_finalize!(map, FinalizeMode::RealRun, {
            // Create an atomic batch scope that will complete correctly.
            // Simulates an accepted transaction.
            let result: Result<()> = atomic_batch_scope!(map, {
                // Make sure the checkpoint index is 0.
                assert_eq!(map.checkpoint.lock().last(), Some(&0));

                // Insert the key.
                map.insert(0, 0, "1".to_string()).unwrap();

                Ok(())
            });

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
                assert_eq!(map.checkpoint.lock().last(), Some(&1));

                // Simulate an instruction
                let result: Result<()> = atomic_batch_scope!(map, {
                    // Update the key.
                    map.insert(0, 0, "2".to_string()).unwrap();

                    Ok(())
                });
                assert!(result.is_ok());

                // Simulates an instruction that fails.
                let result: Result<()> = atomic_batch_scope!(map, {
                    // Make sure the checkpoint index is 2.
                    assert_eq!(map.checkpoint.lock().last(), Some(&2));

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

            Ok(())
        });

        assert!(outcome.is_ok());
        // The map should contain 1 item.
        assert_eq!(map.iter_confirmed().count(), 1);
        // The pending batch should contain no items.
        assert!(map.iter_pending().next().is_none());
        // Make sure the checkpoint index is None.
        assert_eq!(map.checkpoint.lock().last(), None);

        // Ensure that the map value is correct.
        assert_eq!(map.iter_confirmed().next().unwrap(), (Cow::Owned(0), Cow::Owned(0), Cow::Owned("1".to_string())));

        Ok(())
    }

    #[test]
    fn test_speculative_reads_from_other_threads_ignore_atomic_batch() {
        let map: NestedMemoryMap<usize, usize, String> = Default::default();
        map.start_atomic();
        map.insert(0, 1, "pending".to_string()).unwrap();

        assert_eq!(map.get_value_pending(&0, &1), Some(Some("pending".to_string())));
        assert_eq!(map.get_value_speculative(&0, &1).unwrap().as_deref(), Some(&"pending".to_string()));

        let map_for_reader = map.clone();
        let pending = std::thread::spawn(move || map_for_reader.get_value_pending(&0, &1)).join().unwrap();
        assert_eq!(pending, None);

        let map_for_reader = map.clone();
        let speculative = std::thread::spawn(move || {
            map_for_reader.get_value_speculative(&0, &1).unwrap().map(|cow| cow.into_owned())
        })
        .join()
        .unwrap();
        assert_eq!(speculative, None);

        map.abort_atomic();
    }

    #[test]
    fn test_off_thread_speculative_reads_do_not_block_atomic_writer() {
        const BATCH_SIZE: usize = 20_000;
        const WRITER_INSERTS: usize = 5_000;
        const READERS: usize = 8;

        let map: NestedMemoryMap<usize, usize, usize> = Default::default();
        map.start_atomic();
        for i in 0..BATCH_SIZE {
            map.insert(0, i, i).unwrap();
        }

        let stop = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let readers: Vec<_> = (0..READERS)
            .map(|_| {
                let map = map.clone();
                let stop = stop.clone();
                std::thread::spawn(move || {
                    while !stop.load(std::sync::atomic::Ordering::Relaxed) {
                        let _ = map.get_value_speculative(&0, &0);
                    }
                })
            })
            .collect();

        let start = std::time::Instant::now();
        for i in BATCH_SIZE..BATCH_SIZE + WRITER_INSERTS {
            map.insert(0, i, i).unwrap();
        }
        let elapsed = start.elapsed();

        stop.store(true, std::sync::atomic::Ordering::Relaxed);
        for reader in readers {
            reader.join().unwrap();
        }
        map.abort_atomic();

        assert!(
            elapsed < std::time::Duration::from_millis(500),
            "atomic writer stalled for {elapsed:?} under concurrent speculative reads"
        );
    }
}
