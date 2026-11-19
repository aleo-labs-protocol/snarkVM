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

//! Read a snarkVM ledger RocksDB as a secondary instance and print what
//! `snarkvm_rocksdb_estimate_num_keys` is made of.

#![forbid(unsafe_code)]

use snarkvm_rocksdb_analyser::{
    Gauge,
    ReportHeader,
    SstFile,
    attribute_ssts,
    count_live_keys,
    count_memtable_ops,
    render,
    spans_maps,
};

use aleo_std_storage::StorageMode;
use anyhow::{Context, Result};
use clap::Parser;
use snarkvm_ledger_store::helpers::rocksdb::{Database, RocksDB};
use std::{ops::Deref, path::PathBuf};

/// Attribute `snarkvm_rocksdb_estimate_num_keys` to ledger maps.
#[derive(Parser, Debug)]
#[command(version, about)]
struct Args {
    /// Path to the primary (snarkOS-owned) ledger directory.
    #[arg(long)]
    primary_path: PathBuf,
    /// Directory for the secondary instance. A temporary directory is used when omitted.
    #[arg(long)]
    secondary_path: Option<PathBuf>,
    /// Network id recorded on the secondary handle (0 = mainnet, 1 = testnet, 2 = canary).
    ///
    /// With `--primary-path`, the directory is that path. Map ids are read from the keys.
    #[arg(long, default_value_t = 0)]
    network: u16,
    /// Leave SST files that cross a map boundary as one unsplit row.
    #[arg(long)]
    skip_spanning_scan: bool,
}

fn main() -> Result<()> {
    let args = Args::parse();
    let (secondary_path, _tempdir) = match args.secondary_path {
        Some(path) => (path, None),
        None => {
            let tempdir = tempfile::tempdir().context("Failed to create a temporary secondary directory")?;
            (tempdir.path().to_path_buf(), Some(tempdir))
        }
    };

    eprintln!("Opening a secondary instance of {}", args.primary_path.display());
    let storage = StorageMode::Custom(args.primary_path.clone(), Some(secondary_path.clone()));
    let db = RocksDB::open(args.network, storage).context("Failed to open the secondary RocksDB instance")?;
    rocks(&db).try_catch_up_with_primary().context("Failed to catch up with the primary instance")?;

    let gauge = read_gauge(rocks(&db))?;
    eprintln!("Reading live SST metadata");
    let files = rocks(&db)
        .live_files()
        .context("Failed to read live SST metadata")?
        .into_iter()
        .map(SstFile::from)
        .collect::<Vec<_>>();
    let spanning = files.iter().filter(|file| spans_maps(file)).count();
    if spanning > 0 && !args.skip_spanning_scan {
        eprintln!("Scanning {spanning} SST file(s) whose key range crosses a map boundary");
    }

    let mut scanned = 0u64;
    let attribution = attribute_ssts(&files, !args.skip_spanning_scan, |file| {
        scanned += 1;
        let start = file.start_key.as_deref().context("Spanning SST is missing its smallest key")?;
        let end = file.end_key.as_deref().context("Spanning SST is missing its largest key")?;
        eprintln!("Scanning spanning SST {scanned}/{spanning} ({} entries)", file.num_entries);
        count_live_keys(rocks(&db), start, end)
    })?;

    let mem_entries = gauge.active_mem_entries.saturating_add(gauge.imm_mem_entries);
    let mem_deletions = gauge.active_mem_deletions.saturating_add(gauge.imm_mem_deletions);
    if mem_entries > 0 || mem_deletions > 0 {
        eprintln!("Replaying the write-ahead log for {mem_entries} memtable entries");
    }
    let memtable =
        count_memtable_ops(rocks(&db), mem_entries, mem_deletions).context("Failed to attribute memtable entries")?;

    let text = render(
        &ReportHeader {
            primary_path: args.primary_path.display().to_string(),
            secondary_path: secondary_path.display().to_string(),
            network_id: args.network,
        },
        &gauge,
        &attribution,
        &memtable,
    );
    print!("{text}");
    Ok(())
}

fn rocks(db: &RocksDB) -> &rocksdb::DB {
    db.deref().deref()
}

fn read_gauge(db: &rocksdb::DB) -> Result<Gauge> {
    Ok(Gauge {
        estimate_num_keys: db
            .property_int_value("rocksdb.estimate-num-keys")
            .context("Failed to read rocksdb.estimate-num-keys")?,
        active_mem_entries: property_or_zero(db, "rocksdb.num-entries-active-mem-table")?,
        imm_mem_entries: property_or_zero(db, "rocksdb.num-entries-imm-mem-tables")?,
        active_mem_deletions: property_or_zero(db, "rocksdb.num-deletes-active-mem-table")?,
        imm_mem_deletions: property_or_zero(db, "rocksdb.num-deletes-imm-mem-tables")?,
        num_snapshots: property_or_zero(db, "rocksdb.num-snapshots")?,
        num_live_versions: property_or_zero(db, "rocksdb.num-live-versions")?,
        live_sst_files_size: db
            .property_int_value("rocksdb.live-sst-files-size")
            .context("Failed to read rocksdb.live-sst-files-size")?,
    })
}

fn property_or_zero(db: &rocksdb::DB, name: &str) -> Result<u64> {
    Ok(db.property_int_value(name).with_context(|| format!("Failed to read {name}"))?.unwrap_or(0))
}
