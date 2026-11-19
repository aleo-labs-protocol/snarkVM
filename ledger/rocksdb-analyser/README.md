# rocksdb-analyser

`rocksdb-analyser` opens a snarkVM ledger as a secondary RocksDB instance and prints the per-map composition of `snarkvm_rocksdb_estimate_num_keys`.

The node can keep the primary instance open. The secondary instance does not take the primary lock and does not write the primary. This is the same open path as `sidecar-indexer`: `StorageMode::Custom(primary, Some(secondary))`, which calls `DB::open_as_secondary`, then `try_catch_up_with_primary` before reading.

```bash
cargo run -p snarkvm-rocksdb-analyser --release -- \
  --primary-path ~/.aleo/storage/ledger-0
```

`--secondary-path` sets the secondary directory. When it is omitted, the process uses a temporary directory and deletes it on exit. `--network` is the network id stored on the handle (`0` mainnet, `1` testnet, `2` canary). With `--primary-path`, the directory read is that path. `--skip-spanning-scan` skips the key walk and leaves every SST whose range crosses a map boundary as one unsplit row.

## What the gauge is

`snarkvm_rocksdb_estimate_num_keys` is the RocksDB property `rocksdb.estimate-num-keys` on the ledger's single column family. In RocksDB 10.4 (the version linked by the `rocksdb` 0.24 crate), `InternalStats::HandleEstimateNumKeys` computes it as:

1. SST term = `VersionStorageInfo::GetEstimatedActiveKeys()`. For each SST with table statistics, RocksDB adds `num_entries - num_deletions` to a non-deletion total and `num_deletions` to a deletion total. The SST term is `non_deletions - deletions` (that is, `entries - 2 * deletions`). It is 0 when deletions are at least half of the entries. When some live files have no statistics, that difference is scaled by `file_count / files_with_statistics`.
2. Add the number of entries in the active memtable and the unflushed immutable memtables.
3. Subtract twice the number of deletions in those memtables.
4. Clamp the result to 0.

The property is one integer. It is an estimate: overwritten keys and deletions of keys that are not present make it diverge from a count of live user keys.

## There is no native per-map metric

RocksDB integer properties are per database or per column family. snarkVM stores every map in the default column family. A key starts with a 4-byte prefix: network id (`u16`, little-endian) and map id (`u16`, little-endian). Nothing in the property list groups `estimate-num-keys` by that prefix.

These native values are real and still describe the whole column family:

| Property | What it reports |
| --- | --- |
| `rocksdb.estimate-num-keys` | The gauge above |
| `rocksdb.num-entries-active-mem-table` | Entries in the active memtable |
| `rocksdb.num-entries-imm-mem-tables` | Entries in unflushed immutable memtables |
| `rocksdb.num-deletes-active-mem-table` | Deletions in the active memtable |
| `rocksdb.num-deletes-imm-mem-tables` | Deletions in unflushed immutable memtables |
| `rocksdb.estimate-live-data-size` | Estimated live bytes, not a key count |
| `rocksdb.live-sst-files-size` | Bytes of SST files in the current LSM version |
| `GetApproximateSizes` | Bytes in a key range, not a key count |

`DB::GetLiveFilesMetaData` (`live_files` in the Rust crate) is the closest native data. Each SST carries `num_entries`, `num_deletions`, and its smallest and largest user key. Those entry counts are the inputs of `GetEstimatedActiveKeys`. When both endpoints share a map prefix, the file's counters belong to that map with no further I/O. When they do not, RocksDB has no API that splits `num_entries` inside the file.

A custom `TablePropertiesCollector` could record per-prefix counts while an SST is flushed or compacted. That collector is not part of RocksDB's built-in property set, the ledger does not install one, and it would describe only files written after it was added. Giving each map its own column family would make `estimate-num-keys` per map, because the property is per column family. The on-disk ledger is one column family.

Reading live-file metadata, scanning only the SST files whose key range crosses a map prefix, and replaying the unflushed write-ahead log is how an existing ledger can be broken down. This binary is that utility. RocksDB does not publish a per-prefix memtable counter.

## How to read the table

`est. keys` for a map is `entries - 2 * deletions` over the SST counters and the memtable operations attributed to it. A delete counts as one entry and one deletion, so it reduces the estimate by two. The sum of those signed values is the gauge when every live SST file has table statistics, `live_files` matches the current LSM version, and the memtable suffix matches `rocksdb.num-entries-*-mem-table`.

Memtable operations come from the retained write-ahead log. RocksDB has no property that splits memtable entries by key prefix. A log file can still hold batches that were already flushed; the tool keeps the newest suffix whose entry and deletion totals equal the memtable properties.

A spanning SST file is split by the number of live user keys in its range. `num_entries` also counts obsolete versions and deletion tombstones, which the iterator collapses, so that split is an apportionment of the file's physical counters. A file that sits entirely inside one map is charged exactly.

`share` is that row's `est. keys` divided by the sum of `est. keys` across maps.
