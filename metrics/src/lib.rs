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

const GAUGE_NAMES: &[&str] = &[
    committee::TOTAL_STAKE,
    rocksdb::COMPACTION_PENDING,
    rocksdb::ESTIMATE_PENDING_COMPACTION_BYTES,
    rocksdb::NUM_RUNNING_COMPACTIONS,
    rocksdb::NUM_RUNNING_FLUSHES,
    rocksdb::MEM_TABLE_FLUSH_PENDING,
    rocksdb::TOTAL_SST_FILES_SIZE,
    rocksdb::LIVE_SST_FILES_SIZE,
    rocksdb::NUM_SNAPSHOTS,
    rocksdb::NUM_FILES_AT_LEVEL[0],
    rocksdb::NUM_FILES_AT_LEVEL[1],
    rocksdb::NUM_FILES_AT_LEVEL[2],
    rocksdb::NUM_FILES_AT_LEVEL[3],
    rocksdb::NUM_FILES_AT_LEVEL[4],
    rocksdb::NUM_FILES_AT_LEVEL[5],
    rocksdb::NUM_FILES_AT_LEVEL[6],
];

pub mod committee {
    pub const TOTAL_STAKE: &str = "snarkvm_ledger_committee_total_stake";
}

/// Per-map atomic-batch contention.
///
/// Overlay `ATOMIC_BATCH_LOCK_WAIT_SECONDS` with `ATOMIC_BATCH_OFF_THREAD_SPECULATIVE_READ_TOTAL`
/// to detect off-thread speculative readers stalling the sequential dry-run thread.
pub mod store {
    /// Wall time spent waiting to acquire a per-map atomic-batch mutex, in seconds.
    /// Recorded only for waits of at least 1ms.
    pub const ATOMIC_BATCH_LOCK_WAIT_SECONDS: &str = "snarkvm_store_atomic_batch_lock_wait_seconds";
    /// Speculative reads that skipped the pending batch because they ran off the owner thread.
    pub const ATOMIC_BATCH_OFF_THREAD_SPECULATIVE_READ_TOTAL: &str =
        "snarkvm_store_atomic_batch_off_thread_speculative_read_total";
}

/// RocksDB internal database metrics.
///
/// Polled and published by calling `BlockStore::export_rocksdb_metrics()` from an existing
/// background loop (e.g. the auto-checkpoint task in snarkOS). All sizes are in bytes;
/// counts are dimensionless. Requires the `rocks` and `metrics` features on `snarkvm-ledger-store`.
pub mod rocksdb {
    /// 1 if a compaction is pending (background compaction requested but not yet running), else 0.
    pub const COMPACTION_PENDING: &str = "snarkvm_rocksdb_compaction_pending";
    /// Estimated total bytes of data to be compacted. A sustained non-zero value signals backpressure.
    pub const ESTIMATE_PENDING_COMPACTION_BYTES: &str = "snarkvm_rocksdb_estimate_pending_compaction_bytes";
    /// Number of compactions currently running in the background.
    pub const NUM_RUNNING_COMPACTIONS: &str = "snarkvm_rocksdb_num_running_compactions";
    /// Number of memtable flushes currently running.
    pub const NUM_RUNNING_FLUSHES: &str = "snarkvm_rocksdb_num_running_flushes";
    /// 1 if a memtable flush is pending (memtable full but flush not yet started), else 0.
    pub const MEM_TABLE_FLUSH_PENDING: &str = "snarkvm_rocksdb_mem_table_flush_pending";
    /// Total size of all SST files on disk (includes files pending deletion).
    pub const TOTAL_SST_FILES_SIZE: &str = "snarkvm_rocksdb_total_sst_files_size_bytes";
    /// Size of live (referenced) SST files only.
    pub const LIVE_SST_FILES_SIZE: &str = "snarkvm_rocksdb_live_sst_files_size_bytes";
    /// Cumulative bytes read by compaction.
    pub const COMPACT_READ_BYTES: &str = "snarkvm_rocksdb_compact_read_bytes_total";
    /// Cumulative bytes written by compaction.
    pub const COMPACT_WRITE_BYTES: &str = "snarkvm_rocksdb_compact_write_bytes_total";
    /// Cumulative bytes written by memtable flushes.
    pub const FLUSH_WRITE_BYTES: &str = "snarkvm_rocksdb_flush_write_bytes_total";
    /// Number of snapshots currently held (non-zero blocks deletion of old SST files).
    pub const NUM_SNAPSHOTS: &str = "snarkvm_rocksdb_num_snapshots";
    /// Number of SST files per LSM level (levels 0–6).
    pub const NUM_FILES_AT_LEVEL: [&str; 7] = [
        "snarkvm_rocksdb_num_files_at_level0",
        "snarkvm_rocksdb_num_files_at_level1",
        "snarkvm_rocksdb_num_files_at_level2",
        "snarkvm_rocksdb_num_files_at_level3",
        "snarkvm_rocksdb_num_files_at_level4",
        "snarkvm_rocksdb_num_files_at_level5",
        "snarkvm_rocksdb_num_files_at_level6",
    ];
}

/// Registers all snarkVM metrics.
pub fn register_metrics() {
    for name in GAUGE_NAMES {
        register_gauge(name);
    }
}

/******** Counter ********/

/// Registers a counter with the given name.
pub fn register_counter(name: &'static str) {
    let _counter = ::metrics::counter!(name);
}

/// Updates a counter with the given name to the given value.
///
/// Counters represent a single monotonic value, which means the value can only be incremented,
/// not decremented, and always starts out with an initial value of zero.
pub fn counter<V: Into<u64>>(name: &'static str, value: V) {
    let counter = ::metrics::counter!(name);
    counter.absolute(value.into());
}

/// Increments a counter with the given name by one.
///
/// Counters represent a single monotonic value, which means the value can only be incremented,
/// not decremented, and always starts out with an initial value of zero.
pub fn increment_counter(name: &'static str) {
    let counter = ::metrics::counter!(name);
    counter.increment(1);
}

/******** Gauge ********/

/// Registers a gauge with the given name.
pub fn register_gauge(name: &'static str) {
    let _gauge = ::metrics::gauge!(name);
}

/// Updates a gauge with the given name to the given value.
///
/// Gauges represent a single value that can go up or down over time,
/// and always starts out with an initial value of zero.
pub fn gauge<V: Into<f64>>(name: &'static str, value: V) {
    let gauge = ::metrics::gauge!(name);
    gauge.set(value.into());
}

/// Increments a gauge with the given name by the given value.
///
/// Gauges represent a single value that can go up or down over time,
/// and always starts out with an initial value of zero.
pub fn increment_gauge<V: Into<f64>>(name: &'static str, value: V) {
    let gauge = ::metrics::gauge!(name);
    gauge.increment(value.into());
}

/// Decrements a gauge with the given name by the given value.
///
/// Gauges represent a single value that can go up or down over time,
/// and always starts out with an initial value of zero.
pub fn decrement_gauge<V: Into<f64>>(name: &'static str, value: V) {
    let gauge = ::metrics::gauge!(name);
    gauge.decrement(value.into());
}

/******** Histogram ********/

/// Registers a histogram with the given name.
pub fn register_histogram(name: &'static str) {
    let _histogram = ::metrics::histogram!(name);
}

/// Updates a histogram with the given name to the given value.
pub fn histogram<V: Into<f64>>(name: &'static str, value: V) {
    let histogram = ::metrics::histogram!(name);
    histogram.record(value.into());
}

pub fn histogram_label<V: Into<f64>>(name: &'static str, label_key: &'static str, label_value: String, value: V) {
    ::metrics::histogram!(name, label_key => label_value).record(value.into());
}
