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

//! The storage schema version recorded in each ledger database.
//!
//! `RocksDB::open` reads the version before anything else uses the database. A version from a
//! newer build is refused.
//!
//! Ledgers written before this record existed have no version key. Those databases are
//! [`StorageVersion::V0`], and so is a new database. A database is stamped with a later version only
//! when it first needs it, so until then the builds that know only the earlier version can open it.

use super::{MapID, MetadataMap, PREFIX_LEN};

use anyhow::{Result, anyhow, bail};

/// The on-disk schema versions a ledger can be at.
///
/// `V0` is the version of every database that has no schema record. A database only moves to a
/// later variant, never back.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
#[repr(u32)]
pub enum StorageVersion {
    /// No schema record, or a database stamped by the build that introduced the record.
    V0 = 0,
    /// The block metadata map may hold the authority-pruning marker. A database is stamped `V1` when
    /// it is first opened with authority pruning, before anything is pruned, so a `V0` database is
    /// never pruned. `V0` builds refuse this version; builds from before the version record open a
    /// pruned store without noticing.
    V1 = 1,
}

/// The newest storage schema version this build understands.
pub const STORAGE_VERSION: StorageVersion = StorageVersion::V1;

/// The well-known keys of the storage metadata map.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub(crate) enum MetadataKey {
    /// The [`StorageVersion`] the database was last written under, as a little-endian `u32`.
    StorageVersion = 0,
}

impl StorageVersion {
    /// Decodes a version this build knows how to open.
    fn from_u32(version: u32) -> Result<Self> {
        match version {
            0 => Ok(Self::V0),
            1 => Ok(Self::V1),
            version => bail!("Unknown storage schema version {version}"),
        }
    }

    /// Encodes this version for the metadata map.
    fn to_bytes(self) -> [u8; 4] {
        (self as u32).to_le_bytes()
    }
}

/// Returns the raw key prefix under which every entry of the given map is stored.
pub(crate) fn map_prefix(network_id: u16, map_id: MapID) -> [u8; PREFIX_LEN] {
    let mut prefix = [0u8; PREFIX_LEN];
    prefix[..2].copy_from_slice(&network_id.to_le_bytes());
    prefix[2..].copy_from_slice(&u16::from(map_id).to_le_bytes());
    prefix
}

/// Returns the raw database key for a metadata entry.
fn metadata_key(network_id: u16, key: MetadataKey) -> Vec<u8> {
    let mut raw = map_prefix(network_id, MapID::Metadata(MetadataMap::Metadata)).to_vec();
    raw.push(key as u8);
    raw
}

/// Reads the stored version as a `u32`. A missing record is `0` ([`StorageVersion::V0`]).
fn read_storage_version(database: &rocksdb::DB, network_id: u16) -> Result<u32> {
    match database.get(metadata_key(network_id, MetadataKey::StorageVersion))? {
        Some(bytes) => {
            let bytes: [u8; 4] =
                bytes.as_slice().try_into().map_err(|_| anyhow!("Malformed storage version record"))?;
            Ok(u32::from_le_bytes(bytes))
        }
        None => Ok(0),
    }
}

/// Reads the storage schema version. A missing record is [`StorageVersion::V0`], and a version newer
/// than this build is an [`IncompatibleStore`](crate::IncompatibleStore) error.
pub(crate) fn get_storage_version(database: &rocksdb::DB, network_id: u16) -> Result<StorageVersion> {
    let version = read_storage_version(database, network_id)?;
    if version > STORAGE_VERSION as u32 {
        return Err(crate::IncompatibleStore(format!(
            "This ledger was written by a newer version of snarkVM (storage schema v{version}; this build understands \
             v{}). Upgrade snarkVM, or resync from genesis.",
            STORAGE_VERSION as u32,
        ))
        .into());
    }
    StorageVersion::from_u32(version)
}

/// Writes the storage schema version.
pub(crate) fn set_storage_version(database: &rocksdb::DB, network_id: u16, version: StorageVersion) -> Result<()> {
    Ok(database.put(metadata_key(network_id, MetadataKey::StorageVersion), version.to_bytes())?)
}

/// Checks the version of `database` and stamps a database that has none.
///
/// A version newer than this build is an error. `V0` is written when the record is absent, which
/// is the state of every database created before the record existed and of a database this build
/// has just created.
pub(crate) fn migrate_storage(database: &rocksdb::DB, network_id: u16) -> Result<()> {
    get_storage_version(database, network_id)?;
    // The stamp is `V0`, matching the implicit version of an absent record, so a second open
    // observes the same version.
    if database.get(metadata_key(network_id, MetadataKey::StorageVersion))?.is_none() {
        set_storage_version(database, network_id, StorageVersion::V0)?;
    }
    Ok(())
}

/// Stamps `database` with `version` unless it is already at that version or a later one. The stamp
/// is synced to disk, so it outlasts a crash that any later write survives.
pub(crate) fn raise_storage_version(database: &rocksdb::DB, network_id: u16, version: StorageVersion) -> Result<()> {
    if get_storage_version(database, network_id)? < version {
        set_storage_version(database, network_id, version)?;
        database.flush_wal(true)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::helpers::rocksdb::{Database, ProgramMap, RocksDB};
    use snarkvm_utilities::StorageMode;

    const NETWORK_ID: u16 = 0;

    /// Returns the stored version record, which is what a `V0` build compares with its own version.
    fn raw_version(db: &RocksDB, network_id: u16) -> Vec<u8> {
        db.get(metadata_key(network_id, MetadataKey::StorageVersion)).unwrap().unwrap()
    }

    #[test]
    fn test_fresh_database_is_stamped_v0() {
        let db = RocksDB::open(NETWORK_ID, StorageMode::new_test(None)).unwrap();
        assert_eq!(get_storage_version(&db, NETWORK_ID).unwrap(), StorageVersion::V0);
        assert_eq!(raw_version(&db, NETWORK_ID), 0u32.to_le_bytes());
    }

    #[test]
    fn test_raise_storage_version_never_lowers() {
        let db = RocksDB::open(NETWORK_ID, StorageMode::new_test(None)).unwrap();
        raise_storage_version(&db, NETWORK_ID, StorageVersion::V1).unwrap();
        assert_eq!(raw_version(&db, NETWORK_ID), 1u32.to_le_bytes());
        // Neither a lower version nor a later open lowers it.
        raise_storage_version(&db, NETWORK_ID, StorageVersion::V0).unwrap();
        migrate_storage(&db, NETWORK_ID).unwrap();
        assert_eq!(get_storage_version(&db, NETWORK_ID).unwrap(), StorageVersion::V1);
    }

    /// Ensures a block store is stamped `V1` only when it is opened with authority pruning, before
    /// anything is pruned, and that a `V1` store opens with pruning off.
    #[test]
    fn test_only_a_pruning_block_store_is_stamped_v1() {
        use crate::{BlockStore, helpers::rocksdb::BlockDB};
        type CurrentNetwork = console::network::MainnetV0;
        const ID: u16 = <CurrentNetwork as console::network::Network>::ID;

        let storage = StorageMode::new_test(Some(std::sync::Arc::new(tempfile::tempdir().unwrap())));
        let open = |retention| {
            BlockStore::<CurrentNetwork, BlockDB<_>>::open_with_authority_retention(storage.clone(), retention).unwrap()
        };
        let version = || raw_version(&RocksDB::open(ID, storage.clone()).unwrap(), ID);

        drop(open(None));
        assert_eq!(version(), 0u32.to_le_bytes());

        let block_store = open(Some(100));
        assert_eq!(version(), 1u32.to_le_bytes());
        assert_eq!(block_store.authority_pruned_below().unwrap(), None);
        drop(block_store);

        drop(open(None));
        assert_eq!(version(), 1u32.to_le_bytes());
    }

    /// A build that predates `V1` takes this path on a `V1` store: the version is newer than it knows.
    #[test]
    fn test_newer_version_is_refused() {
        let db = RocksDB::open(NETWORK_ID, StorageMode::new_test(None)).unwrap();
        let newer = STORAGE_VERSION as u32 + 1;
        db.put(metadata_key(NETWORK_ID, MetadataKey::StorageVersion), newer.to_le_bytes()).unwrap();
        let error = migrate_storage(&db, NETWORK_ID).unwrap_err();
        assert!(error.is::<crate::IncompatibleStore>(), "{error}");
        assert!(error.to_string().contains("newer version"), "{error}");
        // A secondary instance only reads the version, and refuses it the same way.
        assert!(get_storage_version(&db, NETWORK_ID).unwrap_err().is::<crate::IncompatibleStore>());
        // `from_bytes` rejects the unknown version, so the raw record is what remains.
        let raw = db.get(metadata_key(NETWORK_ID, MetadataKey::StorageVersion)).unwrap().unwrap();
        assert_eq!(raw, newer.to_le_bytes());
    }

    #[test]
    fn test_delete_legacy_mapping_history_keeps_other_prefixes() {
        let db = RocksDB::open(NETWORK_ID, StorageMode::new_test(None)).unwrap();
        let legacy =
            [ProgramMap::MappingUpdate, ProgramMap::MappingUpdateHeights, ProgramMap::StakingRewards].map(|map| {
                let mut key = map_prefix(NETWORK_ID, MapID::Program(map)).to_vec();
                key.push(1);
                db.put(&key, b"old").unwrap();
                key
            });
        let mut kept = map_prefix(NETWORK_ID, MapID::Program(ProgramMap::ProgramID)).to_vec();
        kept.push(1);
        db.put(&kept, b"program").unwrap();

        db.delete_legacy_mapping_history().unwrap();
        for key in &legacy {
            assert!(db.get(key).unwrap().is_none(), "{key:?}");
        }
        assert_eq!(db.get(&kept).unwrap().unwrap(), b"program");
    }

    #[test]
    fn test_absent_version_is_v0() {
        let db = RocksDB::open(NETWORK_ID, StorageMode::new_test(None)).unwrap();
        db.delete(metadata_key(NETWORK_ID, MetadataKey::StorageVersion)).unwrap();
        assert_eq!(get_storage_version(&db, NETWORK_ID).unwrap(), StorageVersion::V0);
        migrate_storage(&db, NETWORK_ID).unwrap();
        assert_eq!(get_storage_version(&db, NETWORK_ID).unwrap(), StorageVersion::V0);
        assert_eq!(raw_version(&db, NETWORK_ID), 0u32.to_le_bytes());
    }
}
