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

use console::network::prelude::{Deserialize, Result, Serialize};

use core::hash::Hash;
use std::borrow::Cow;

/// A trait representing 'nested map'-like storage operations with read-write capabilities.
///
/// This trait is sealed. Only snarkVM implements it.
pub trait NestedMap<
    'a,
    M: 'a + Copy + Clone + PartialEq + Eq + Hash + Serialize + Deserialize<'a> + Send + Sync,
    K: 'a + Clone + PartialEq + Eq + Serialize + Deserialize<'a> + Send + Sync,
    V: 'a + Clone + Serialize + Deserialize<'a> + Send + Sync,
>: crate::sealed::SealedNestedMap<M, K, V> + Clone + NestedMapRead<'a, M, K, V> + Send + Sync
{
    ///
    /// Inserts the given key-value pair.
    ///
    fn insert(&self, map: M, key: K, value: V) -> Result<()>;

    ///
    /// Removes the given map.
    ///
    fn remove_map(&self, map: &M) -> Result<()>;

    ///
    /// Removes the key-value pair for the given map and key.
    ///
    fn remove_key(&self, map: &M, key: &K) -> Result<()>;

    ///
    /// Begins an atomic operation. Any further calls to `insert` and `remove` will be queued
    /// without an actual write taking place until `finish_atomic` is called.
    ///
    fn start_atomic(&self);

    ///
    /// Checks whether an atomic operation is currently in progress. This can be done to ensure
    /// that lower-level operations don't start or finish their individual atomic write batch
    /// if they are already part of a larger one.
    ///
    fn is_atomic_in_progress(&self) -> bool;

    ///
    /// Saves the current list of pending operations, so that if `atomic_rewind` is called,
    /// we roll back all future operations, and return to the start of this checkpoint.
    ///
    fn atomic_checkpoint(&self);

    ///
    /// Removes the latest atomic checkpoint.
    ///
    fn clear_latest_checkpoint(&self);

    ///
    /// Removes all pending operations to the last `atomic_checkpoint`
    /// (or to `start_atomic` if no checkpoints have been created).
    ///
    fn atomic_rewind(&self);

    ///
    /// Aborts the current atomic operation.
    ///
    fn abort_atomic(&self);

    ///
    /// Finishes an atomic operation, performing all the queued writes.
    ///
    fn finish_atomic(&self) -> Result<()>;
}

/// A trait representing 'nested map'-like storage operations with read-only capabilities.
///
/// This trait is sealed. Only snarkVM implements it.
pub trait NestedMapRead<
    'a,
    M: 'a + Copy + Clone + PartialEq + Eq + Hash + Serialize + Deserialize<'a> + Sync,
    K: 'a + Clone + PartialEq + Eq + Serialize + Deserialize<'a> + Sync,
    V: 'a + Clone + Serialize + Deserialize<'a> + Sync,
>: crate::sealed::SealedNestedMap<M, K, V>
{
    type PendingIterator: Iterator<Item = (Cow<'a, M>, Option<Cow<'a, K>>, Option<Cow<'a, V>>)>;
    type Iterator: Iterator<Item = (Cow<'a, M>, Cow<'a, K>, Cow<'a, V>)>;
    type Keys: Iterator<Item = (Cow<'a, M>, Cow<'a, K>)>;
    type Values: Iterator<Item = Cow<'a, V>>;

    ///
    /// Returns the number of confirmed entries in the map.
    ///
    fn len_map_confirmed(&self, map: &M) -> Result<usize>;

    ///
    /// Checks whether there are any confirmed entries in the map.
    ///
    fn is_empty_map_confirmed(&self, map: &M) -> Result<bool> {
        Ok(self.len_map_confirmed(map)? == 0)
    }

    ///
    /// Returns `true` if the given key exists in the map.
    ///
    fn contains_key_confirmed(&self, map: &M, key: &K) -> Result<bool>;

    ///
    /// Returns `true` if the given key exists in the map.
    /// This method first checks the atomic batch, and if it does not exist, then checks the confirmed.
    ///
    fn contains_key_speculative(&self, map: &M, key: &K) -> Result<bool>;

    ///
    /// Returns the confirmed key-value pairs for the given map, if it exists.
    ///
    fn get_map_confirmed(&'a self, map: &M) -> Result<Vec<(K, V)>>;

    ///
    /// Returns the speculative key-value pairs for the given map, if it exists.
    ///
    fn get_map_speculative(&'a self, map: &M) -> Result<Vec<(K, V)>>;

    ///
    /// Returns the value for the given key from the map, if it exists.
    ///
    fn get_value_confirmed(&'a self, map: &M, key: &K) -> Result<Option<Cow<'a, V>>>;

    ///
    /// Returns the current value for the given key if it is scheduled
    /// to be inserted as part of an atomic batch.
    ///
    /// If the key does not exist, returns `None`.
    /// If the key is removed in the batch, returns `Some(None)`.
    /// If the key is inserted in the batch, returns `Some(Some(value))`.
    ///
    fn get_value_pending(&self, map: &M, key: &K) -> Option<Option<V>>;

    ///
    /// Returns the value for the given key from the atomic batch first, if it exists,
    /// or return from the map, otherwise.
    ///
    fn get_value_speculative(&'a self, map: &M, key: &K) -> Result<Option<Cow<'a, V>>> {
        // Return the atomic batch value, if it exists, or the map value, otherwise.
        match self.get_value_pending(map, key) {
            Some(Some(value)) => Ok(Some(Cow::Owned(value))),
            Some(None) => Ok(None),
            None => Ok(self.get_value_confirmed(map, key)?),
        }
    }

    ///
    /// Returns an iterator visiting each map-key-value pair in the atomic batch.
    ///
    fn iter_pending(&'a self) -> Self::PendingIterator;

    ///
    /// Returns an iterator visiting each confirmed map-key-value pair.
    ///
    fn iter_confirmed(&'a self) -> Self::Iterator;

    ///
    /// Returns an iterator over each confirmed key.
    ///
    fn keys_confirmed(&'a self) -> Self::Keys;

    ///
    /// Returns an iterator over each confirmed value.
    ///
    fn values_confirmed(&'a self) -> Self::Values;
}
