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

#![forbid(unsafe_code)]
#![warn(clippy::cast_possible_truncation)]

extern crate snarkvm_console as console;

pub mod helpers;

mod block;
pub use block::*;

mod consensus;
pub use consensus::*;

mod program;
pub use program::*;

mod transaction;
pub use transaction::*;

mod transition;
pub use transition::*;

pub use snarkvm_utilities::storage::{StorageMode, aleo_dir, aleo_ledger_dir, aleo_secondary_ledger_dir};

/// Seals the storage, map and database traits. Only the storage backends of this crate implement them.
///
/// ```compile_fail,E0277
/// use snarkvm_console::network::MainnetV0;
/// use snarkvm_ledger_store::{
///     BlockStore,
///     ConsensusStorage,
///     FinalizeStore,
///     StorageMode,
///     helpers::memory::{BlockMemory, ConsensusMemory, FinalizeMemory, TransactionMemory, TransitionMemory},
/// };
///
/// #[derive(Clone)]
/// struct Wrapper(ConsensusMemory<MainnetV0>);
///
/// impl ConsensusStorage<MainnetV0> for Wrapper {
///     type FinalizeStorage = FinalizeMemory<MainnetV0>;
///     type BlockStorage = BlockMemory<MainnetV0>;
///     type TransactionStorage = TransactionMemory<MainnetV0>;
///     type TransitionStorage = TransitionMemory<MainnetV0>;
///
///     fn open_with_authority_retention<S: Into<StorageMode>>(
///         storage: S,
///         authority_retention: Option<u32>,
///     ) -> anyhow::Result<Self> {
///         ConsensusMemory::open_with_authority_retention(storage, authority_retention).map(Self)
///     }
///
///     fn finalize_store(&self) -> &FinalizeStore<MainnetV0, Self::FinalizeStorage> {
///         self.0.finalize_store()
///     }
///
///     fn block_store(&self) -> &BlockStore<MainnetV0, Self::BlockStorage> {
///         self.0.block_store()
///     }
/// }
/// ```
///
/// ```compile_fail,E0277
/// use snarkvm_console::prelude::{Result, Serialize};
/// use snarkvm_ledger_store::helpers::MapRead;
/// use std::{
///     borrow::{Borrow, Cow},
///     hash::Hash,
///     iter::Empty,
/// };
///
/// struct EmptyMap;
///
/// impl<'a> MapRead<'a, u8, u8> for EmptyMap {
///     type PendingIterator = Empty<(Cow<'a, u8>, Option<Cow<'a, u8>>)>;
///     type Iterator = Empty<(Cow<'a, u8>, Cow<'a, u8>)>;
///     type Keys = Empty<Cow<'a, u8>>;
///     type Values = Empty<Cow<'a, u8>>;
///
///     fn len_confirmed(&self) -> usize {
///         0
///     }
///
///     fn contains_key_confirmed<Q>(&self, _key: &Q) -> Result<bool>
///     where
///         u8: Borrow<Q>,
///         Q: PartialEq + Eq + Hash + Serialize + ?Sized,
///     {
///         Ok(false)
///     }
///
///     fn contains_key_speculative<Q>(&self, _key: &Q) -> Result<bool>
///     where
///         u8: Borrow<Q>,
///         Q: PartialEq + Eq + Hash + Serialize + ?Sized,
///     {
///         Ok(false)
///     }
///
///     fn get_confirmed<Q>(&'a self, _key: &Q) -> Result<Option<Cow<'a, u8>>>
///     where
///         u8: Borrow<Q>,
///         Q: PartialEq + Eq + Hash + Serialize + ?Sized,
///     {
///         Ok(None)
///     }
///
///     fn get_pending<Q>(&self, _key: &Q) -> Option<Option<u8>>
///     where
///         u8: Borrow<Q>,
///         Q: PartialEq + Eq + Hash + Serialize + ?Sized,
///     {
///         None
///     }
///
///     fn get_floor_confirmed<Q>(&'a self, _key: &Q) -> Result<Option<(Cow<'a, u8>, Cow<'a, u8>)>>
///     where
///         u8: Borrow<Q>,
///         Q: PartialEq + Eq + Hash + Serialize + ?Sized,
///     {
///         Ok(None)
///     }
///
///     fn iter_pending(&'a self) -> Self::PendingIterator {
///         std::iter::empty()
///     }
///
///     fn iter_confirmed(&'a self) -> Self::Iterator {
///         std::iter::empty()
///     }
///
///     fn keys_confirmed(&'a self) -> Self::Keys {
///         std::iter::empty()
///     }
///
///     fn values_confirmed(&'a self) -> Self::Values {
///         std::iter::empty()
///     }
/// }
/// ```
///
/// ```compile_fail,E0277
/// use serde::{Deserialize, Deserializer, Serialize, Serializer};
/// use snarkvm_console::prelude::Result;
/// use snarkvm_ledger_store::helpers::{MapRead, memory::MemoryMap};
/// use std::{
///     borrow::{Borrow, Cow},
///     hash::Hash,
///     iter::Empty,
/// };
///
/// #[derive(Clone, PartialEq, Eq, Hash)]
/// struct Key;
///
/// impl Serialize for Key {
///     fn serialize<S: Serializer>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error> {
///         serializer.serialize_unit()
///     }
/// }
///
/// impl<'de> Deserialize<'de> for Key {
///     fn deserialize<D: Deserializer<'de>>(deserializer: D) -> std::result::Result<Self, D::Error> {
///         <()>::deserialize(deserializer).map(|()| Key)
///     }
/// }
///
/// impl<'a> MapRead<'a, Key, Key> for MemoryMap<u8, u8> {
///     type PendingIterator = Empty<(Cow<'a, Key>, Option<Cow<'a, Key>>)>;
///     type Iterator = Empty<(Cow<'a, Key>, Cow<'a, Key>)>;
///     type Keys = Empty<Cow<'a, Key>>;
///     type Values = Empty<Cow<'a, Key>>;
///
///     fn len_confirmed(&self) -> usize {
///         0
///     }
///
///     fn contains_key_confirmed<Q>(&self, _key: &Q) -> Result<bool>
///     where
///         Key: Borrow<Q>,
///         Q: PartialEq + Eq + Hash + Serialize + ?Sized,
///     {
///         Ok(false)
///     }
///
///     fn contains_key_speculative<Q>(&self, _key: &Q) -> Result<bool>
///     where
///         Key: Borrow<Q>,
///         Q: PartialEq + Eq + Hash + Serialize + ?Sized,
///     {
///         Ok(false)
///     }
///
///     fn get_confirmed<Q>(&'a self, _key: &Q) -> Result<Option<Cow<'a, Key>>>
///     where
///         Key: Borrow<Q>,
///         Q: PartialEq + Eq + Hash + Serialize + ?Sized,
///     {
///         Ok(None)
///     }
///
///     fn get_pending<Q>(&self, _key: &Q) -> Option<Option<Key>>
///     where
///         Key: Borrow<Q>,
///         Q: PartialEq + Eq + Hash + Serialize + ?Sized,
///     {
///         None
///     }
///
///     fn get_floor_confirmed<Q>(&'a self, _key: &Q) -> Result<Option<(Cow<'a, Key>, Cow<'a, Key>)>>
///     where
///         Key: Borrow<Q>,
///         Q: PartialEq + Eq + Hash + Serialize + ?Sized,
///     {
///         Ok(None)
///     }
///
///     fn iter_pending(&'a self) -> Self::PendingIterator {
///         std::iter::empty()
///     }
///
///     fn iter_confirmed(&'a self) -> Self::Iterator {
///         std::iter::empty()
///     }
///
///     fn keys_confirmed(&'a self) -> Self::Keys {
///         std::iter::empty()
///     }
///
///     fn values_confirmed(&'a self) -> Self::Values {
///         std::iter::empty()
///     }
/// }
/// ```
mod sealed {
    pub trait Sealed {}

    /// Seals the map traits for the key and value types of each map, so that an outside crate cannot implement them
    /// for a map of this crate with its own key or value type.
    ///
    /// Each map implements this marker with the same bounds as its `Map` and `MapRead` impls. With looser bounds, an
    /// outside crate can implement those traits for the map with a key or value type that the impls do not cover.
    pub trait SealedMap<K, V> {}

    /// Seals the nested map traits for the map, key and value types of each nested map.
    ///
    /// Each nested map implements this marker with the same bounds as its `NestedMap` and `NestedMapRead` impls.
    pub trait SealedNestedMap<M, K, V> {}
}

use console::prelude::{Result, bail};

/// A store whose schema is newer than this build. Nothing is wrong with it, so do not delete it.
#[derive(Debug)]
pub struct IncompatibleStore(pub String);

impl std::fmt::Display for IncompatibleStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for IncompatibleStore {}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum FinalizeMode {
    /// Invoke finalize as a real run.
    RealRun,
    /// Invoke finalize as a dry run.
    DryRun,
}

impl FinalizeMode {
    /// Returns the u8 value of the finalize mode.
    #[inline]
    pub const fn to_u8(self) -> u8 {
        match self {
            Self::RealRun => 0,
            Self::DryRun => 1,
        }
    }

    /// Returns a finalize mode from a given u8.
    #[inline]
    pub fn from_u8(value: u8) -> Result<Self> {
        match value {
            0 => Ok(Self::RealRun),
            1 => Ok(Self::DryRun),
            _ => bail!("Invalid finalize mode of '{value}'"),
        }
    }
}
