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
//! newer build is refused. An older version is brought forward by the migrations between it and
//! [`STORAGE_VERSION`].
//!
//! Ledgers written before this record existed have no version key. Those databases are
//! [`StorageVersion::V0`].

use super::{MapID, MetadataMap, PREFIX_LEN};

use anyhow::{Result, anyhow, bail};

/// The on-disk schema versions a ledger can be at.
///
/// `V0` is the version of every database that has no schema record. Later variants are produced
/// by migrations, in order.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
#[repr(u32)]
pub enum StorageVersion {
    /// No schema record, or a database stamped by the build that introduced the record.
    V0 = 0,
}

/// The storage schema version this build writes and understands.
pub const STORAGE_VERSION: StorageVersion = StorageVersion::V0;

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

/// Reads the storage schema version. A missing record is [`StorageVersion::V0`].
pub(crate) fn get_storage_version(database: &rocksdb::DB, network_id: u16) -> Result<StorageVersion> {
    StorageVersion::from_u32(read_storage_version(database, network_id)?)
}

/// Writes the storage schema version.
pub(crate) fn set_storage_version(database: &rocksdb::DB, network_id: u16, version: StorageVersion) -> Result<()> {
    Ok(database.put(metadata_key(network_id, MetadataKey::StorageVersion), version.to_bytes())?)
}

/// Brings `database` up to [`STORAGE_VERSION`].
///
/// A version newer than this build is an error. `V0` is written when the record is absent, which
/// is the state of every database created before the record existed and of a database this build
/// has just created.
pub(crate) fn migrate_storage(database: &rocksdb::DB, network_id: u16) -> Result<()> {
    let version = read_storage_version(database, network_id)?;
    if version > STORAGE_VERSION as u32 {
        bail!(
            "This ledger was written by a newer version of snarkVM (storage schema v{version}; this build understands \
             v{}). Upgrade snarkVM, or resync from genesis.",
            STORAGE_VERSION as u32,
        );
    }
    let version = get_storage_version(database, network_id)?;
    if version < STORAGE_VERSION {
        bail!("Storage schema v{} has no migration to v{}", version as u32, STORAGE_VERSION as u32);
    }
    // Stamp a database that has not recorded a version yet. The stamp is `V0`, matching the
    // implicit version of an absent record, so a second open observes the same version.
    if database.get(metadata_key(network_id, MetadataKey::StorageVersion))?.is_none() {
        set_storage_version(database, network_id, StorageVersion::V0)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::helpers::rocksdb::{Database, ProgramMap, RocksDB};

    use aleo_std::StorageMode;

    const NETWORK_ID: u16 = 0;

    #[test]
    fn test_fresh_database_is_stamped_v0() {
        let db = RocksDB::open(NETWORK_ID, StorageMode::new_test(None)).unwrap();
        assert_eq!(get_storage_version(&db, NETWORK_ID).unwrap(), StorageVersion::V0);
        assert!(db.get(metadata_key(NETWORK_ID, MetadataKey::StorageVersion)).unwrap().is_some());
    }

    #[test]
    fn test_newer_version_is_refused() {
        let db = RocksDB::open(NETWORK_ID, StorageMode::new_test(None)).unwrap();
        db.put(metadata_key(NETWORK_ID, MetadataKey::StorageVersion), 1u32.to_le_bytes()).unwrap();
        let error = migrate_storage(&db, NETWORK_ID).unwrap_err().to_string();
        assert!(error.contains("newer version"), "{error}");
        // `from_bytes` rejects the unknown version, so the raw record is what remains.
        let raw = db.get(metadata_key(NETWORK_ID, MetadataKey::StorageVersion)).unwrap().unwrap();
        assert_eq!(raw, 1u32.to_le_bytes());
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
    }
}
