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

use crate::{MapKey, OpCounts, SstFile, map_prefix, unflushed_ops};

use anyhow::{Context, Result};
use std::collections::BTreeMap;

impl From<rocksdb::LiveFile> for SstFile {
    fn from(file: rocksdb::LiveFile) -> Self {
        // `LiveFile::size` is the SST size in bytes and fits in `u64`.
        let size = u64::try_from(file.size).expect("SST file size fits in u64");
        Self {
            start_key: file.start_key,
            end_key: file.end_key,
            num_entries: file.num_entries,
            num_deletions: file.num_deletions,
            size,
        }
    }
}

/// Counts puts and deletes still in the memtable, by map prefix.
///
/// The counts come from the retained write-ahead log. `entries` and `deletions` select the newest
/// log suffix that matches the memtable properties, so flushed batches still sitting in the log
/// are left out.
pub fn count_memtable_ops(db: &rocksdb::DB, entries: u64, deletions: u64) -> Result<BTreeMap<MapKey, OpCounts>> {
    if entries == 0 && deletions == 0 {
        return Ok(BTreeMap::new());
    }

    let mut batches = Vec::new();
    let mut iter = db.get_updates_since(0).context("Failed to read the write-ahead log")?;
    for batch in iter.by_ref() {
        let (_sequence, batch) = batch.context("Failed to read a write-ahead log batch")?;
        let mut counts = OpCounter::default();
        batch.iterate(&mut counts);
        batches.push(counts.maps);
    }
    iter.status().context("Failed to read the write-ahead log")?;
    Ok(unflushed_ops(&batches, entries, deletions))
}

#[derive(Default)]
struct OpCounter {
    maps: BTreeMap<MapKey, OpCounts>,
}

impl rocksdb::WriteBatchIterator for OpCounter {
    fn put(&mut self, key: &[u8], _value: &[u8]) {
        self.record(key, false);
    }

    fn delete(&mut self, key: &[u8]) {
        self.record(key, true);
    }
}

impl OpCounter {
    fn record(&mut self, key: &[u8], deletion: bool) {
        let map_key = match map_prefix(key) {
            Some((network_id, map_id)) => MapKey::Map { network_id, map_id },
            None => MapKey::Unattributed,
        };
        let counts = self.maps.entry(map_key).or_default();
        counts.entries += 1;
        if deletion {
            counts.deletions += 1;
        }
    }
}

/// Counts live user keys in `[start, end]` by map prefix.
///
/// The ledger database installs a 4-byte prefix extractor, so the iterator uses a total-order
/// seek. A prefix seek would stop at the first map boundary and drop the rest of a spanning file.
pub fn count_live_keys(db: &rocksdb::DB, start: &[u8], end: &[u8]) -> Result<BTreeMap<MapKey, u64>> {
    let mut options = rocksdb::ReadOptions::default();
    options.set_total_order_seek(true);
    options.fill_cache(false);

    let mut counts = BTreeMap::new();
    let mut iter = db.raw_iterator_opt(options);
    iter.seek(start);
    while iter.valid() {
        let key = iter.key().context("RocksDB iterator is valid without a key")?;
        if key > end {
            break;
        }
        let map_key = match map_prefix(key) {
            Some((network_id, map_id)) => MapKey::Map { network_id, map_id },
            None => MapKey::Unattributed,
        };
        *counts.entry(map_key).or_default() += 1;
        iter.next();
    }
    iter.status().context("RocksDB iterator failed while reading a spanning SST")?;
    Ok(counts)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{MapKey, SstFile, attribute_ssts, estimate_num_keys, sst_estimated_active_keys};
    use snarkvm_ledger_store::helpers::rocksdb::{BlockMap, ProgramMap};

    use anyhow::Result;

    fn prefixed(network_id: u16, map_id: u16, suffix: u8) -> Vec<u8> {
        let mut key = Vec::with_capacity(5);
        key.extend_from_slice(&network_id.to_le_bytes());
        key.extend_from_slice(&map_id.to_le_bytes());
        key.push(suffix);
        key
    }

    #[test]
    fn live_file_metadata_reproduces_estimate_num_keys() -> Result<()> {
        let dir = tempfile::tempdir()?;
        let mut options = rocksdb::Options::default();
        options.create_if_missing(true);
        options.set_prefix_extractor(rocksdb::SliceTransform::create_fixed_prefix(4));
        options.set_stats_dump_period_sec(0);

        let header = BlockMap::Header as u16;
        let program = ProgramMap::KeyValueID as u16;
        {
            let db = rocksdb::DB::open(&options, dir.path())?;
            for suffix in [1, 2, 3] {
                db.put(prefixed(0, header, suffix), b"header")?;
            }
            db.put(prefixed(0, program, 1), b"program")?;
            db.compact_range::<&[u8], &[u8]>(None, None);
            db.flush()?;
        }

        let db = rocksdb::DB::open_for_read_only(&options, dir.path(), false)?;
        let files = db.live_files()?.into_iter().map(SstFile::from).collect::<Vec<_>>();
        assert!(!files.is_empty());

        let attribution = attribute_ssts(&files, true, |file| {
            let start = file.start_key.as_deref().context("SST is missing its smallest key")?;
            let end = file.end_key.as_deref().context("SST is missing its largest key")?;
            count_live_keys(&db, start, end)
        })?;

        let header_keys = count_live_keys(&db, &prefixed(0, header, 0), &prefixed(0, header, 255))?;
        let program_keys = count_live_keys(&db, &prefixed(0, program, 0), &prefixed(0, program, 255))?;
        assert_eq!(header_keys[&MapKey::Map { network_id: 0, map_id: header }], 3);
        assert_eq!(program_keys[&MapKey::Map { network_id: 0, map_id: program }], 1);

        let totals = attribution.totals();
        assert_eq!(totals.entries, files.iter().map(|file| file.num_entries).sum::<u64>());
        assert_eq!(totals.deletions, files.iter().map(|file| file.num_deletions).sum::<u64>());

        let header_stats =
            attribution.maps.get(&MapKey::Map { network_id: 0, map_id: header }).context(format!("{attribution:?}"))?;
        let program_stats = attribution
            .maps
            .get(&MapKey::Map { network_id: 0, map_id: program })
            .context(format!("{attribution:?}"))?;
        assert!(header_stats.entries >= program_stats.entries);
        assert_eq!(header_stats.entries + program_stats.entries, totals.entries);

        let property = db.property_int_value("rocksdb.estimate-num-keys")?.context("missing estimate-num-keys")?;
        let mem_entries = property_or_zero(&db, "rocksdb.num-entries-active-mem-table")?
            + property_or_zero(&db, "rocksdb.num-entries-imm-mem-tables")?;
        let mem_deletions = property_or_zero(&db, "rocksdb.num-deletes-active-mem-table")?
            + property_or_zero(&db, "rocksdb.num-deletes-imm-mem-tables")?;
        let recomputed =
            estimate_num_keys(sst_estimated_active_keys(totals.entries, totals.deletions), mem_entries, mem_deletions);
        assert_eq!(property, recomputed, "live SST metadata did not reproduce rocksdb.estimate-num-keys");
        Ok(())
    }

    fn property_or_zero(db: &rocksdb::DB, name: &str) -> Result<u64> {
        Ok(db.property_int_value(name)?.unwrap_or(0))
    }

    #[test]
    fn wal_replay_attributes_unflushed_memtable_ops() -> Result<()> {
        let dir = tempfile::tempdir()?;
        let mut options = rocksdb::Options::default();
        options.create_if_missing(true);
        options.set_stats_dump_period_sec(0);
        let header = BlockMap::Header as u16;
        let program = ProgramMap::KeyValueID as u16;
        let db = rocksdb::DB::open(&options, dir.path())?;

        db.put(prefixed(0, header, 1), b"flushed")?;
        db.flush()?;
        db.put(prefixed(0, program, 1), b"live")?;
        db.put(prefixed(0, program, 2), b"live")?;
        db.delete(prefixed(0, program, 1))?;

        let entries = property_or_zero(&db, "rocksdb.num-entries-active-mem-table")?
            + property_or_zero(&db, "rocksdb.num-entries-imm-mem-tables")?;
        let deletions = property_or_zero(&db, "rocksdb.num-deletes-active-mem-table")?
            + property_or_zero(&db, "rocksdb.num-deletes-imm-mem-tables")?;
        assert_eq!(entries, 3);
        assert_eq!(deletions, 1);

        let counts = count_memtable_ops(&db, entries, deletions)?;
        assert!(!counts.contains_key(&MapKey::Map { network_id: 0, map_id: header }));
        let program_counts = counts[&MapKey::Map { network_id: 0, map_id: program }];
        assert_eq!(program_counts.entries, 3);
        assert_eq!(program_counts.deletions, 1);
        assert_eq!(program_counts.estimated_active_keys(), 1);
        Ok(())
    }
}
