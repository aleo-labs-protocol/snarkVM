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

use std::collections::{BTreeMap, BTreeSet};

/// Ledger map addressed by the first four bytes of a RocksDB key.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum MapKey {
    /// `network_id` and `map_id`, both little-endian `u16`.
    Map { network_id: u16, map_id: u16 },
    /// The key range had no 4-byte map prefix, or a spanning file's scan found no keys.
    Unattributed,
    /// The file crosses map prefixes and the scan was skipped.
    SpanningNotScanned,
}

/// Physical SST counters attributed to one map.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct MapStats {
    /// SST files whose entire key range sits in this map.
    pub files: u64,
    /// Spanning SST files that contributed a share of their counters to this map.
    pub split_files: u64,
    pub entries: u64,
    pub deletions: u64,
    pub bytes: u64,
}

impl MapStats {
    /// `entries - 2 * deletions`, the per-map piece of the SST term in `rocksdb.estimate-num-keys`.
    pub fn estimated_active_keys(self) -> i128 {
        i128::from(self.entries) - 2 * i128::from(self.deletions)
    }
}

/// Puts and deletes that feed `rocksdb.estimate-num-keys`.
///
/// A delete is one entry and one deletion. The gauge subtracts each deletion twice.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct OpCounts {
    pub entries: u64,
    pub deletions: u64,
}

impl OpCounts {
    /// `entries - 2 * deletions`. The value is negative when deletions are more than half the entries.
    pub fn estimated_active_keys(self) -> i128 {
        i128::from(self.entries) - 2 * i128::from(self.deletions)
    }

    pub(crate) fn add(&mut self, other: Self) {
        self.entries += other.entries;
        self.deletions += other.deletions;
    }
}

/// Drops already-flushed write-ahead batches.
///
/// A retained log can still contain batches that are already in SST files. The returned suffix is
/// the newest range whose entry and deletion totals equal the memtable counters. The full log is
/// returned when no such suffix exists.
pub fn unflushed_ops(
    batches: &[BTreeMap<MapKey, OpCounts>],
    entries: u64,
    deletions: u64,
) -> BTreeMap<MapKey, OpCounts> {
    let mut prefix_entries = Vec::with_capacity(batches.len() + 1);
    let mut prefix_deletions = Vec::with_capacity(batches.len() + 1);
    prefix_entries.push(0);
    prefix_deletions.push(0);
    for batch in batches {
        let batch_entries = batch.values().map(|counts| counts.entries).sum::<u64>();
        let batch_deletions = batch.values().map(|counts| counts.deletions).sum::<u64>();
        prefix_entries.push(prefix_entries.last().copied().unwrap_or(0) + batch_entries);
        prefix_deletions.push(prefix_deletions.last().copied().unwrap_or(0) + batch_deletions);
    }

    let total_entries = prefix_entries.last().copied().unwrap_or(0);
    let total_deletions = prefix_deletions.last().copied().unwrap_or(0);
    let start = (0..=batches.len())
        .find(|&index| {
            total_entries - prefix_entries[index] == entries && total_deletions - prefix_deletions[index] == deletions
        })
        .unwrap_or(0);

    let mut merged: BTreeMap<MapKey, OpCounts> = BTreeMap::new();
    for batch in &batches[start..] {
        for (key, counts) in batch {
            merged.entry(*key).or_default().add(*counts);
        }
    }
    merged
}

/// One live SST file, reduced to the fields that feed the key estimate.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SstFile {
    pub start_key: Option<Vec<u8>>,
    pub end_key: Option<Vec<u8>>,
    pub num_entries: u64,
    pub num_deletions: u64,
    pub size: u64,
}

/// Per-map totals produced from live SST metadata.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Attribution {
    pub maps: BTreeMap<MapKey, MapStats>,
    pub spanning_files: u64,
    pub scanned_live_keys: u64,
}

impl Attribution {
    pub fn totals(&self) -> MapStats {
        self.maps.values().fold(MapStats::default(), |mut total, stats| {
            total.files += stats.files;
            total.split_files += stats.split_files;
            total.entries += stats.entries;
            total.deletions += stats.deletions;
            total.bytes += stats.bytes;
            total
        })
    }
}

/// Network id and map id stored in the first four bytes of a ledger key.
pub fn map_prefix(key: &[u8]) -> Option<(u16, u16)> {
    let bytes: [u8; 4] = key.get(..4)?.try_into().ok()?;
    let network_id = u16::from_le_bytes([bytes[0], bytes[1]]);
    let map_id = u16::from_le_bytes([bytes[2], bytes[3]]);
    Some((network_id, map_id))
}

/// SST term of `rocksdb.estimate-num-keys` when every live file has table statistics.
///
/// RocksDB subtracts deletions twice: once inside `num_entries - num_deletions`, then once more.
/// The result is 0 when deletions are at least half of the entries.
pub fn sst_estimated_active_keys(entries: u64, deletions: u64) -> u64 {
    let non_deletions = entries.saturating_sub(deletions);
    non_deletions.saturating_sub(deletions)
}

/// `rocksdb.estimate-num-keys` from the SST term plus memtable entry and deletion counts.
///
/// Memtable deletions are subtracted twice. Memtable entries are added whole.
pub fn estimate_num_keys(sst_active: u64, mem_entries: u64, mem_deletions: u64) -> u64 {
    let keys = sst_active.saturating_add(mem_entries);
    let doubled_deletions = mem_deletions.saturating_mul(2);
    keys.saturating_sub(doubled_deletions)
}

/// Attributes each SST file to the ledger map that owns its key range.
///
/// `scan` is called only for files whose smallest and largest keys belong to different maps.
/// Its weights apportion that file's entries, deletions, and bytes. Weights come back from a
/// live-key scan; the physical counters being split still include obsolete SST entries.
pub fn attribute_ssts<E, F>(files: &[SstFile], scan_spanning: bool, mut scan: F) -> Result<Attribution, E>
where
    F: FnMut(&SstFile) -> Result<BTreeMap<MapKey, u64>, E>,
{
    let mut attribution = Attribution::default();
    for file in files {
        match file_range(file) {
            FileRange::Single(network_id, map_id) => {
                add_whole(&mut attribution, MapKey::Map { network_id, map_id }, file);
            }
            FileRange::Unparsed => add_whole(&mut attribution, MapKey::Unattributed, file),
            FileRange::Spanning => {
                attribution.spanning_files += 1;
                if !scan_spanning {
                    add_whole(&mut attribution, MapKey::SpanningNotScanned, file);
                    continue;
                }
                let weights = scan(file)?;
                attribution.scanned_live_keys += weights.values().sum::<u64>();
                if weights.values().all(|weight| *weight == 0) {
                    add_whole(&mut attribution, MapKey::Unattributed, file);
                    continue;
                }
                add_split(&mut attribution, file, &weights);
            }
        }
    }
    Ok(attribution)
}

enum FileRange {
    Single(u16, u16),
    Spanning,
    Unparsed,
}

/// Reports whether the SST's smallest and largest keys belong to different maps.
pub fn spans_maps(file: &SstFile) -> bool {
    matches!(file_range(file), FileRange::Spanning)
}

fn file_range(file: &SstFile) -> FileRange {
    let start = file.start_key.as_deref().and_then(map_prefix);
    let end = file.end_key.as_deref().and_then(map_prefix);
    match (start, end) {
        (Some(start), Some(end)) if start == end => FileRange::Single(start.0, start.1),
        (Some(_), Some(_)) => FileRange::Spanning,
        _ => FileRange::Unparsed,
    }
}

fn add_whole(attribution: &mut Attribution, key: MapKey, file: &SstFile) {
    let stats = attribution.maps.entry(key).or_default();
    stats.files += 1;
    stats.entries += file.num_entries;
    stats.deletions += file.num_deletions;
    stats.bytes += file.size;
}

fn add_split(attribution: &mut Attribution, file: &SstFile, weights: &BTreeMap<MapKey, u64>) {
    let entries = split_proportional(file.num_entries, weights);
    let deletions = split_proportional(file.num_deletions, weights);
    let bytes = split_proportional(file.size, weights);
    let mut keys = BTreeSet::new();
    keys.extend(entries.keys().copied());
    keys.extend(deletions.keys().copied());
    keys.extend(bytes.keys().copied());
    for key in keys {
        let entry_share = entries.get(&key).copied().unwrap_or(0);
        let deletion_share = deletions.get(&key).copied().unwrap_or(0);
        let byte_share = bytes.get(&key).copied().unwrap_or(0);
        if entry_share == 0 && deletion_share == 0 && byte_share == 0 {
            continue;
        }
        let stats = attribution.maps.entry(key).or_default();
        stats.split_files += 1;
        stats.entries += entry_share;
        stats.deletions += deletion_share;
        stats.bytes += byte_share;
    }
}

/// Splits `total` across `weights`, preserving the sum.
///
/// Remainder units go to the largest fractional parts. Equal fractions break toward the smaller key.
fn split_proportional(total: u64, weights: &BTreeMap<MapKey, u64>) -> BTreeMap<MapKey, u64> {
    let weight_sum: u64 = weights.values().sum();
    if total == 0 || weight_sum == 0 {
        return BTreeMap::new();
    }

    let mut parts: Vec<(MapKey, u64, u128)> = weights
        .iter()
        .filter(|(_, weight)| **weight > 0)
        .map(|(key, weight)| {
            let product = u128::from(total) * u128::from(*weight);
            let divisor = u128::from(weight_sum);
            // `product / divisor` is at most `total`, so it fits in `u64`.
            let base = u64::try_from(product / divisor).expect("proportional share fits in u64");
            (key, base, product % divisor)
        })
        .map(|(key, base, remainder)| (*key, base, remainder))
        .collect();

    let assigned: u64 = parts.iter().map(|(_, base, _)| *base).sum();
    let mut leftover = total - assigned;
    parts.sort_by(|left, right| right.2.cmp(&left.2).then(left.0.cmp(&right.0)));
    for part in &mut parts {
        if leftover == 0 {
            break;
        }
        part.1 += 1;
        leftover -= 1;
    }

    parts.into_iter().filter(|(_, base, _)| *base > 0).map(|(key, base, _)| (key, base)).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(network_id: u16, map_id: u16, suffix: &[u8]) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(4 + suffix.len());
        bytes.extend_from_slice(&network_id.to_le_bytes());
        bytes.extend_from_slice(&map_id.to_le_bytes());
        bytes.extend_from_slice(suffix);
        bytes
    }

    fn file(start: &[u8], end: &[u8], entries: u64, deletions: u64, size: u64) -> SstFile {
        SstFile {
            start_key: Some(start.to_vec()),
            end_key: Some(end.to_vec()),
            num_entries: entries,
            num_deletions: deletions,
            size,
        }
    }

    #[test]
    fn prefix_is_two_little_endian_u16s() {
        assert_eq!(map_prefix(&key(1, 2, b"abc")), Some((1, 2)));
        assert_eq!(map_prefix(&[1, 0, 2]), None);
    }

    #[test]
    fn single_prefix_files_keep_their_counters() {
        let header = key(0, 4, b"a");
        let program = key(0, 9, b"a");
        let files = vec![file(&header, &header, 10, 1, 100), file(&program, &program, 4, 0, 40)];
        let mut scans = 0;
        let attribution = attribute_ssts(&files, true, |_| {
            scans += 1;
            Ok::<_, ()>(BTreeMap::new())
        })
        .expect("scan is not used");
        assert_eq!(scans, 0);
        let header_stats = attribution.maps[&MapKey::Map { network_id: 0, map_id: 4 }];
        assert_eq!(header_stats.entries, 10);
        assert_eq!(header_stats.deletions, 1);
        assert_eq!(header_stats.estimated_active_keys(), 8);
        assert_eq!(attribution.totals().entries, 14);
    }

    #[test]
    fn spanning_files_split_by_live_key_weight() {
        let start = key(0, 1, b"a");
        let end = key(0, 2, b"z");
        let files = vec![file(&start, &end, 10, 3, 100)];
        let attribution = attribute_ssts(&files, true, |_| {
            Ok::<_, ()>(BTreeMap::from([
                (MapKey::Map { network_id: 0, map_id: 1 }, 1),
                (MapKey::Map { network_id: 0, map_id: 2 }, 3),
            ]))
        })
        .expect("scan result");

        let first = attribution.maps[&MapKey::Map { network_id: 0, map_id: 1 }];
        let second = attribution.maps[&MapKey::Map { network_id: 0, map_id: 2 }];
        assert_eq!(first.entries + second.entries, 10);
        assert_eq!(first.deletions + second.deletions, 3);
        assert_eq!(first.bytes + second.bytes, 100);
        assert_eq!(first.split_files, 1);
        // 10 * 1/4 and 10 * 3/4, with the leftover unit going to the smaller key on a tie.
        assert_eq!(first.entries, 3);
        assert_eq!(second.entries, 7);
        assert_eq!(attribution.scanned_live_keys, 4);
        assert_eq!(attribution.spanning_files, 1);
    }

    #[test]
    fn equal_fractions_break_toward_the_smaller_key() {
        let weights = BTreeMap::from([
            (MapKey::Map { network_id: 0, map_id: 1 }, 1),
            (MapKey::Map { network_id: 0, map_id: 2 }, 1),
        ]);
        let parts = split_proportional(5, &weights);
        assert_eq!(parts[&MapKey::Map { network_id: 0, map_id: 1 }], 3);
        assert_eq!(parts[&MapKey::Map { network_id: 0, map_id: 2 }], 2);
    }

    #[test]
    fn skipped_scan_keeps_spanning_files_together() {
        let start = key(0, 1, b"a");
        let end = key(0, 2, b"z");
        let files = vec![file(&start, &end, 7, 0, 70)];
        let attribution = attribute_ssts(&files, false, |_| -> Result<_, ()> { panic!("scan") }).expect("no scan");
        assert_eq!(attribution.maps[&MapKey::SpanningNotScanned].entries, 7);
    }

    #[test]
    fn unflushed_suffix_drops_batches_already_in_sst_files() {
        let older = MapKey::Map { network_id: 0, map_id: 1 };
        let newer = MapKey::Map { network_id: 0, map_id: 2 };
        let flushed = BTreeMap::from([(older, OpCounts { entries: 4, deletions: 1 })]);
        let live = BTreeMap::from([(newer, OpCounts { entries: 3, deletions: 1 })]);
        let kept = unflushed_ops(&[flushed, live], 3, 1);
        assert_eq!(kept.len(), 1);
        assert_eq!(kept[&newer], OpCounts { entries: 3, deletions: 1 });
    }

    #[test]
    fn estimate_matches_the_rocksdb_formula() {
        assert_eq!(sst_estimated_active_keys(10, 1), 8);
        assert_eq!(sst_estimated_active_keys(10, 6), 0);
        assert_eq!(estimate_num_keys(8, 5, 2), 9);
        assert_eq!(estimate_num_keys(1, 0, 1), 0);
    }
}
