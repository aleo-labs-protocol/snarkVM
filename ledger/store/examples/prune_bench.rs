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

//! Drives authority pruning and the background authority map compaction on a synthetic full-size
//! store, through the entry points a node uses. Run with `--help` for the commands.

#[cfg(not(feature = "rocks"))]
fn main() {
    eprintln!("prune_bench needs the `rocks` feature: --features rocks --example prune_bench");
}

#[cfg(feature = "rocks")]
fn main() -> anyhow::Result<()> {
    bench::main()
}

#[cfg(feature = "rocks")]
mod bench {
    use anyhow::{Context, Result, bail, ensure};
    use snarkvm_console::{
        network::{MainnetV0, Network},
        prelude::FromBytes,
        types::Field,
    };
    use snarkvm_ledger_authority::Authority;
    use snarkvm_ledger_block::{Block, ConfirmedTransaction, Header, Metadata, Ratifications, Solutions, Transactions};
    use snarkvm_ledger_store::{
        AUTHORITY_RETENTION_BLOCKS,
        BlockStorage,
        BlockStore,
        StorageMode,
        aleo_ledger_dir,
        helpers::{
            MapRead,
            rocksdb::{BlockDB, BlockMap, Database, MapID, PREFIX_LEN, RocksDB},
        },
    };
    use snarkvm_utilities::bytes::unchecked_deserialize;
    use std::{
        fmt::Write as _,
        io::{BufRead, BufReader, Read, Seek, SeekFrom, Write as _},
        path::{Path, PathBuf},
        sync::{
            Arc,
            Condvar,
            Mutex,
            OnceLock,
            atomic::{AtomicBool, AtomicU64, Ordering},
        },
        time::{Duration, Instant, SystemTime, UNIX_EPOCH},
    };

    type N = MainnetV0;
    type Store = BlockStore<N, BlockDB<N>>;

    const HELP: &str = "\
prune_bench: authority pruning and the background authority map compaction, as a node runs them.

Every command that opens the store as a node calls BlockStore::open_with_authority_retention on
StorageMode::Custom(<db_dir>), so the startup pruning pass and the compaction thread are the
production ones, and the database handle is never closed, as in a node.

Dataset commands (raw writes, bench only):
  sample <bundle_dir> <out_file> [min_height]
        Decodes CDN block bundles (*.blocks), prints size distributions, and saves the authority bytes
        and certificate counts of the blocks at or above <min_height> (default 22000000).
  build <db_dir> <source> <heights> [old_source] [split] [--no-seal]
        Writes id, reverse-id, authority and certificate rows for every height in 0..<heights>, waits
        for compaction to settle, then seals the tip (--no-seal: as the older bench left it). <source> is a sample file, or
        synthetic:<authority_bytes>[:<certs_per_height>] for random authority bytes. Heights below
        <split> use <old_source>. No watermark is set, so the first `prune` is a first enable.
  extend <db_dir> <source> <count>
        Appends <count> heights after the tip, settles and seals the new tip: the state of a node
        <count> blocks later. The next `compact-authorities` prunes the heights that left the window.
  seal <db_dir>
        Stores complete blocks at the last 10 heights (empty except for the authority, synthetic
        headers), which a block store reads when it opens. `build` and `extend` do this; run it once
        on a dataset built by an older bench.
  settle <db_dir>              Flushes and waits for RocksDB's own compactions to finish.
  status <db_dir>              Prints the watermark, the compaction plan and the level layout. Opens
                               the storage only, so it prunes nothing and starts no thread.

Node commands (all take [--retention <blocks>], default the network's window):
  prune | compact-authorities | restart <db_dir> [--stop-after-secs <s>] [--settle] [--tree-cache]
        One code path under three names: opens the store as a pruning node, then waits for the
        compaction thread to end. Prints the open (block tree, block cache, startup pruning, whose
        own log lines time the authority walk and the certificate pass) and the compaction (slices
        compacted and skipped, wall time, disk bytes, ledger directory size) separately.
        --stop-after-secs calls stop_background_work() that long after the thread starts.
  exit-mid-slice <db_dir> --max-delay <s> [--stop-first] [--delay <s>] [--tree-cache]
        Opens as a node, sleeps a uniform random time in [0, max-delay) after the compaction thread
        starts, then calls std::process::exit(0) with the thread running and the store alive.
        --stop-first calls stop_background_work() before the exit and prints how long it took.
        Prints a RESULT line: the delay, whether a RocksDB compaction was running, the slice.
  stop-latency <db_dir> --max-delay <s> [--delay <s>] [--tree-cache]
        As exit-mid-slice --stop-first, but returns from main instead of calling process::exit.
  fault-watch <db_dir> --duration <s> [--probe-ms <ms>] [--flush-every <n>]
        Opens as a node and, while the compaction thread runs, writes and periodically flushes a
        probe key, printing each change in the result, in rocksdb.background-errors and in the
        thread's state. Break the disk from outside while it runs.
  --tree-cache writes the block tree cache, as a node does at shutdown, so the next open does not
  rebuild the tree: after the open in exit-mid-slice and stop-latency, at the end in the others.

Certificate pass candidates (raw writes to the certificate map, bench only; the store's own pass is
`restart`). 256 key-range slices on 4 threads with the store's read options, one WriteBatch per slice:
  cert-pass <db_dir> --below <height> --mode none|scan|point|rewrite|design|design-early [--cap <keys>]
            [--threads <n>] [--flush] [--compact plain|force] [--then-open] [--bg-compact plain|force]
            [--load none|scan|write:<heights_per_sec>] [--source <sample>]
        Removes the rows of heights in 1..<below>. scan: counts only. rewrite: the store's write, a
        range delete of the slice and puts of the kept rows. point: one delete per removed row.
        design: collects delete keys up to --cap (default 262144); writes them if the slice loses at
        most half its rows and no more than the cap, otherwise scans again and rewrites.
        design-early: as design, but the first scan of a slice ends once it passes the cap.
        --flush flushes after the pass, timed apart. --compact compacts the certificate prefix after
        it: plain is the store's compact_range, force also rewrites the bottom level.
        --then-open then opens the store as a node, prints the time since the process started, and
        stops the compaction thread. --bg-compact runs the compaction on a thread while --load runs:
        scan repeats the certificate scan; write stores heights after the tip, one batch each.
  cert-state <db_dir>          The certificate prefix: live files by level and approximate bytes.
  slice-bench <db_dir> --belows <h,h,..> [--reps <n>] [--big-keys <n> --big-slices <k> --big-below <h>]
        One slice at a time from a warm page cache, a different slice for every write: the scan
        alone, the scan that fills the batch, the write, the batch size, for point and rewrite.
        --big-keys builds and writes one batch of that many deletes, then of that many puts, from
        rows collected over <k> slices.
  fault-cert <db_dir> --below <height> --kind none|chmod|cmd [--fault-on <sh>] [--fault-off <sh>]
             [--stop-by-flush] [--skip-force]
        Point-deletes below <height>, flushes, breaks the disk (chmod: the ledger directory loses
        write permission; cmd: runs the shell commands), then starts manual compactions one after
        the other, printing for each the time to return, rocksdb.background-errors and a probe put.

Output: production log lines are printed as `[UTC +seconds since start] LEVEL message`; the bench's
own figures start with `===` or `RESULT`. Disk bytes come from /proc/self/io (Linux only).

Build:
  cargo build --release -p snarkvm-ledger-store --features rocks --example prune_bench
";

    // ---------------------------------------------------------------------------------------------
    // Production log lines.

    /// How the compaction thread's run ended, from its log line.
    #[derive(Clone, Debug)]
    enum Ending {
        Compacted { marked: usize, total: usize, skipped: usize, secs: f64 },
        NothingToReclaim { total: usize },
        Stopped { before: usize, total: usize },
        Failed(String),
    }

    /// What the compaction thread has logged so far.
    #[derive(Clone, Debug, Default)]
    struct Compaction {
        /// When the thread logged its plan, with the marked and the total slices.
        started: Option<(Instant, usize, usize)>,
        /// The marked slices done, from the last progress line (one about every 10 s).
        progress_done: usize,
        ended: Option<(Instant, Ending)>,
        /// The seconds `stop_background_work` reported waiting.
        waited: Option<f64>,
    }

    struct Events {
        start: Instant,
        compaction: Mutex<Compaction>,
        changed: Condvar,
        /// Every production log line of this process.
        lines: Mutex<Vec<String>>,
    }

    static EVENTS: OnceLock<Events> = OnceLock::new();

    fn events() -> &'static Events {
        EVENTS.get_or_init(|| Events {
            start: Instant::now(),
            compaction: Default::default(),
            changed: Condvar::new(),
            lines: Default::default(),
        })
    }

    impl Events {
        fn compaction(&self) -> Compaction {
            self.compaction.lock().expect("no panic while the lock is held").clone()
        }

        /// Forgets the last run, before another one starts in this process.
        fn reset(&self) {
            *self.compaction.lock().expect("no panic while the lock is held") = Compaction::default();
        }

        /// Waits until `done` accepts the state, or for `timeout`. Returns the state.
        fn wait(&self, timeout: Option<Duration>, done: impl Fn(&Compaction) -> bool) -> Compaction {
            let deadline = timeout.map(|timeout| Instant::now() + timeout);
            let mut state = self.compaction.lock().expect("no panic while the lock is held");
            while !done(&state) {
                let step = match deadline {
                    Some(deadline) if Instant::now() >= deadline => break,
                    Some(deadline) => deadline - Instant::now(),
                    None => Duration::from_secs(3600),
                };
                state = self.changed.wait_timeout(state, step).expect("no panic while the lock is held").0;
            }
            state.clone()
        }

        /// The last number of the last log line that starts with `prefix`.
        fn logged_number(&self, prefix: &str) -> Option<f64> {
            let lines = self.lines.lock().expect("no panic while the lock is held");
            lines.iter().rev().find(|line| line.starts_with(prefix)).and_then(|line| numbers(line).last().copied())
        }

        fn update(&self, message: &str) {
            self.lines.lock().expect("no panic while the lock is held").push(message.to_string());
            let n = numbers(message);
            let at = |i: usize| n.get(i).copied().unwrap_or(0.0);
            let now = Instant::now();
            let mut state = self.compaction.lock().expect("no panic while the lock is held");
            if message.starts_with("Compacting ") && message.contains("authority slices") {
                state.started = Some((now, at(0) as usize, at(1) as usize));
            } else if message.starts_with("Nothing to reclaim in the authority map") {
                state.started.get_or_insert((now, 0, at(0) as usize));
                state.ended = Some((now, Ending::NothingToReclaim { total: at(0) as usize }));
            } else if message.starts_with("Compacted ") && message.contains("marked slices") {
                state.progress_done = at(0) as usize;
            } else if message.starts_with("Compacted ") && message.contains("authority slices, skipped") {
                let ending = Ending::Compacted {
                    marked: at(0) as usize,
                    total: at(1) as usize,
                    skipped: at(2) as usize,
                    secs: at(3),
                };
                state.ended = Some((now, ending));
            } else if message.starts_with("Stopped the authority map compaction before slice") {
                state.ended = Some((now, Ending::Stopped { before: at(0) as usize, total: at(1) as usize }));
            } else if message.starts_with("Failed to compact the authority map")
                || message.starts_with("Failed to start the authority map compaction")
                || message.starts_with("The authority map compaction panicked")
            {
                state.ended = Some((now, Ending::Failed(message.to_string())));
            } else if message.starts_with("Waited ") && message.contains("authority map compaction") {
                state.waited = Some(at(0));
            } else {
                return;
            }
            self.changed.notify_all();
        }
    }

    /// The decimal numbers in `text`, in order.
    fn numbers(text: &str) -> Vec<f64> {
        text.split(|c: char| !c.is_ascii_digit() && c != '.')
            .filter_map(|token| token.trim_matches('.').parse().ok())
            .collect()
    }

    /// The time of day in UTC, to match the RocksDB LOG and the wrapper scripts.
    fn utc() -> String {
        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default();
        let secs = now.as_secs() % 86_400;
        format!("{:02}:{:02}:{:02}.{:03}", secs / 3600, secs / 60 % 60, secs % 60, now.subsec_millis())
    }

    fn stamp() -> String {
        format!("[{} +{:.3}]", utc(), events().start.elapsed().as_secs_f64())
    }

    /// Prints the log lines of the store, at debug level and above, and records the compaction
    /// thread's. A global subscriber, so it sees the compaction thread.
    struct Logger;

    struct Message(String);

    impl tracing::field::Visit for Message {
        fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
            // Writing to a `String` cannot fail.
            let _ = if field.name() == "message" {
                write!(self.0, "{value:?}")
            } else {
                write!(self.0, " {}={value:?}", field.name())
            };
        }
    }

    impl tracing::Subscriber for Logger {
        fn enabled(&self, metadata: &tracing::Metadata<'_>) -> bool {
            *metadata.level() <= tracing::Level::INFO
                || (*metadata.level() == tracing::Level::DEBUG && metadata.target().starts_with("snarkvm_ledger_store"))
        }

        fn new_span(&self, _: &tracing::span::Attributes<'_>) -> tracing::span::Id {
            tracing::span::Id::from_u64(1)
        }

        fn record(&self, _: &tracing::span::Id, _: &tracing::span::Record<'_>) {}

        fn record_follows_from(&self, _: &tracing::span::Id, _: &tracing::span::Id) {}

        fn event(&self, event: &tracing::Event<'_>) {
            let mut message = Message(String::new());
            event.record(&mut message);
            println!("{} {:>5} {}", stamp(), event.metadata().level(), message.0);
            events().update(&message.0);
        }

        fn enter(&self, _: &tracing::span::Id) {}

        fn exit(&self, _: &tracing::span::Id) {}
    }

    // ---------------------------------------------------------------------------------------------
    // Measurements.

    #[derive(Clone, Copy, Default)]
    struct DiskIo {
        read: u64,
        write: u64,
    }

    /// The bytes this process has read from and written to storage; zero where `/proc` is absent.
    fn disk_io() -> DiskIo {
        let mut io = DiskIo::default();
        for line in std::fs::read_to_string("/proc/self/io").unwrap_or_default().lines() {
            if let Some(v) = line.strip_prefix("read_bytes:") {
                io.read = v.trim().parse().unwrap_or(0);
            } else if let Some(v) = line.strip_prefix("write_bytes:") {
                io.write = v.trim().parse().unwrap_or(0);
            }
        }
        io
    }

    fn gb(bytes: u64) -> f64 {
        bytes as f64 / 1e9
    }

    fn stall_count(log: &Path) -> usize {
        let Ok(file) = std::fs::File::open(log) else { return 0 };
        BufReader::new(file)
            .lines()
            .map_while(Result::ok)
            .filter(|l| l.contains("Stalling writes") || l.contains("Stopping writes"))
            .count()
    }

    /// The apparent size of every file under `dir`, like `du -sb`. Files that vanish meanwhile, as a
    /// compaction's inputs do, count as nothing.
    fn dir_size(dir: &Path) -> u64 {
        let Ok(entries) = std::fs::read_dir(dir) else { return 0 };
        entries
            .filter_map(Result::ok)
            .map(|entry| match entry.metadata() {
                Ok(metadata) if metadata.is_dir() => dir_size(&entry.path()),
                Ok(metadata) => metadata.len(),
                Err(_) => 0,
            })
            .sum()
    }

    fn property(db: &RocksDB, name: &str) -> u64 {
        db.property_int_value(name).ok().flatten().unwrap_or(0)
    }

    fn print_props(db: &RocksDB, label: &str, full: bool) {
        println!("--- rocksdb {label}");
        for p in [
            "rocksdb.num-running-compactions",
            "rocksdb.estimate-pending-compaction-bytes",
            "rocksdb.num-files-at-level0",
            "rocksdb.is-write-stopped",
            "rocksdb.background-errors",
            "rocksdb.total-sst-files-size",
            "rocksdb.estimate-num-keys",
        ] {
            println!("{p} = {}", property(db, p));
        }
        let mut props = vec!["rocksdb.levelstats"];
        if full {
            props.push("rocksdb.stats");
        }
        for p in props {
            println!("{p}:\n{}", db.property_value(p).ok().flatten().unwrap_or_default());
        }
    }

    /// A measurement window: wall time, disk bytes and write stalls since it was taken.
    struct Window {
        timer: Instant,
        io: DiskIo,
        stalls: usize,
    }

    impl Window {
        fn start(log: &Path) -> Self {
            Self { timer: Instant::now(), io: disk_io(), stalls: stall_count(log) }
        }

        fn report(&self, label: &str, log: &Path) -> f64 {
            let (secs, io) = (self.timer.elapsed().as_secs_f64(), disk_io());
            println!(
                "=== {label}: {secs:.1} s, disk read {:.2} GB, disk write {:.2} GB, write stalls {}",
                gb(io.read.saturating_sub(self.io.read)),
                gb(io.write.saturating_sub(self.io.write)),
                stall_count(log).saturating_sub(self.stalls)
            );
            secs
        }
    }

    fn map_prefix(map: BlockMap) -> [u8; PREFIX_LEN] {
        let mut prefix = [0u8; PREFIX_LEN];
        prefix[..2].copy_from_slice(&N::ID.to_le_bytes());
        prefix[2..].copy_from_slice(&u16::from(MapID::Block(map)).to_le_bytes());
        prefix
    }

    fn authority_prefix() -> [u8; PREFIX_LEN] {
        map_prefix(BlockMap::Authority)
    }

    /// The last manual compaction RocksDB's LOG reports in the authority map: the LOG line's
    /// timestamp and the slice of `total` its start key falls in. The store splits the map at the
    /// first two key bytes, slice `i` starting at `i * 65536 / total`.
    fn last_logged_slice(log: &Path, total: usize) -> Option<(String, usize)> {
        const TAIL: u64 = 1 << 20;
        let mut file = std::fs::File::open(log).ok()?;
        let len = file.metadata().ok()?.len();
        file.seek(SeekFrom::Start(len.saturating_sub(TAIL))).ok()?;
        let mut tail = Vec::new();
        file.read_to_end(&mut tail).ok()?;
        let tail = String::from_utf8_lossy(&tail);
        let prefix: String = authority_prefix().iter().map(|b| format!("{b:02X}")).collect();
        tail.lines().rev().find_map(|line| {
            let range = line.split_once("Manual compaction from level-")?.1;
            let key = range.split('\'').nth(1)?.to_ascii_uppercase();
            let first = u16::from_str_radix(key.strip_prefix(prefix.as_str())?.get(..4)?, 16).ok()?;
            let slice = (0..total).rev().find(|i| i * 65536 / total <= usize::from(first))?;
            Some((line.split(' ').next().unwrap_or_default().to_string(), slice))
        })
    }

    // ---------------------------------------------------------------------------------------------
    // The store, opened as a node opens it.

    struct Node {
        store: Store,
        db: RocksDB,
        ledger_dir: PathBuf,
        /// When `open_with_authority_retention` returned.
        opened: Instant,
    }

    fn storage_mode(db_dir: &str) -> StorageMode {
        StorageMode::Custom(PathBuf::from(db_dir), None)
    }

    impl Node {
        /// Opens the database, then the block store with `retention`, timing the two.
        fn open(db_dir: &str, retention: Option<u32>) -> Result<Self> {
            let mode = storage_mode(db_dir);
            let ledger_dir = aleo_ledger_dir(N::ID, &mode);
            let timer = Instant::now();
            let db = RocksDB::open(N::ID, mode.clone())?;
            println!("{} opened the database at {db_dir} in {:.2} s", stamp(), timer.elapsed().as_secs_f64());
            print_props(&db, "at open", false);
            println!("ledger directory: {:.2} GB", gb(dir_size(&ledger_dir)));

            events().reset();
            let window = Window::start(&ledger_dir.join("LOG"));
            let store = Store::open_with_authority_retention(mode.clone(), retention)?;
            let opened = Instant::now();
            window.report("open (block tree, block cache, startup pruning)", &ledger_dir.join("LOG"));
            println!(
                "retention = {retention:?}, watermark = {:?}, ledger directory: {:.2} GB",
                store.authority_pruned_below()?,
                gb(dir_size(&ledger_dir))
            );
            Ok(Self { store, db, ledger_dir, opened })
        }

        fn log(&self) -> PathBuf {
            self.ledger_dir.join("LOG")
        }

        /// Waits for the compaction thread's plan. Returns `None` if the open started no thread.
        fn wait_started(&self) -> Result<Option<Compaction>> {
            if self.store.authority_pruned_below()?.is_none() {
                println!("no watermark, so the open started no compaction thread");
                return Ok(None);
            }
            let state = events().wait(Some(Duration::from_secs(300)), |c| c.started.is_some() || c.ended.is_some());
            ensure!(state.started.is_some() || state.ended.is_some(), "the compaction thread logged nothing in 300 s");
            Ok(Some(state))
        }

        fn cache_block_tree(&self) -> Result<()> {
            let timer = Instant::now();
            self.store.cache_block_tree()?;
            println!("{} wrote the block tree cache in {:.2} s", stamp(), timer.elapsed().as_secs_f64());
            Ok(())
        }
    }

    fn describe(ending: &Ending) -> String {
        match ending {
            Ending::Compacted { marked, total, skipped, secs } => {
                format!("compacted {marked} of {total} slices, skipped {skipped}, thread's own time {secs:.1} s")
            }
            Ending::NothingToReclaim { total } => format!("nothing to reclaim, 0 of {total} slices compacted"),
            Ending::Stopped { before, total } => format!("stopped before slice {before} of {total}"),
            Ending::Failed(message) => format!("FAILED: {message}"),
        }
    }

    /// `prune`, `compact-authorities` and `restart`: the open, then the compaction to its end.
    fn run(
        db_dir: &str,
        label: &str,
        retention: u32,
        stop_after: Option<f64>,
        settle: bool,
        tree_cache: bool,
    ) -> Result<()> {
        let node = Node::open(db_dir, Some(retention))?;
        let window = Window { timer: node.opened, ..Window::start(&node.log()) };
        let before = dir_size(&node.ledger_dir);
        if let Some(state) = node.wait_started()? {
            if let Some((_, marked, total)) = state.started {
                println!("{} the compaction thread planned {marked} of {total} slices", stamp());
            }
            let state = match stop_after {
                Some(secs) => {
                    events().wait(Some(Duration::from_secs_f64(secs)), |c| c.ended.is_some());
                    stop(&node);
                    events().compaction()
                }
                None => events().wait(None, |c| c.ended.is_some()),
            };
            let (_, ending) = state.ended.context("the compaction thread logged no ending")?;
            window.report(&format!("{label}: background authority compaction"), &node.log());
            println!("=== {label}: {}", describe(&ending));
            let after = dir_size(&node.ledger_dir);
            println!(
                "ledger directory: {:.2} GB -> {:.2} GB ({:+.2} GB)",
                gb(before),
                gb(after),
                gb(after) - gb(before)
            );
        }
        if settle {
            settle_db(&node.db)?;
            println!("ledger directory after settling: {:.2} GB", gb(dir_size(&node.ledger_dir)));
        }
        // What a node's shutdown does. The database stays open until the process exits.
        stop(&node);
        if tree_cache {
            node.cache_block_tree()?;
        }
        print_props(&node.db, "at exit", true);
        Ok(())
    }

    /// Calls `stop_background_work` and returns the seconds it took.
    fn stop(node: &Node) -> f64 {
        let timer = Instant::now();
        node.store.stop_background_work();
        let secs = timer.elapsed().as_secs_f64();
        println!("{} stop_background_work() returned after {secs:.3} s", stamp());
        secs
    }

    /// SplitMix64.
    struct SplitMix(u64);

    impl SplitMix {
        fn next(&mut self) -> u64 {
            self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
            let mut z = self.0;
            z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
            z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
            z ^ (z >> 31)
        }

        /// A uniform value in `[0, 1)`.
        fn unit(&mut self) -> f64 {
            (self.next() >> 11) as f64 / (1u64 << 53) as f64
        }
    }

    enum Mode {
        /// `process::exit(0)` with the compaction thread running.
        Abrupt,
        /// `stop_background_work()`, then `process::exit(0)`.
        StopThenExit,
        /// `stop_background_work()`, then a return from `main`.
        StopThenReturn,
    }

    /// `exit-mid-slice` and `stop-latency`: interrupts the production compaction thread at a random
    /// point after it starts.
    fn interrupt(
        db_dir: &str,
        retention: u32,
        exit: Mode,
        max_delay: f64,
        fixed_delay: Option<f64>,
        tree_cache: bool,
    ) -> Result<()> {
        let node = Node::open(db_dir, Some(retention))?;
        if tree_cache {
            node.cache_block_tree()?;
        }
        let Some(state) = node.wait_started()? else {
            println!("RESULT outcome=no-thread");
            std::process::exit(3);
        };
        let Some((started, marked, total)) = state.started.filter(|_| state.ended.is_none()) else {
            println!("RESULT outcome=nothing-to-compact");
            std::process::exit(3);
        };
        let seed = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_nanos() as u64;
        let delay = fixed_delay.unwrap_or_else(|| SplitMix(seed ^ u64::from(std::process::id())).unit() * max_delay);
        println!("{} thread planned {marked} of {total} slices; interrupting {delay:.3} s after its start", stamp());
        std::thread::sleep(Duration::from_secs_f64(delay).saturating_sub(started.elapsed()));

        let since_start = started.elapsed().as_secs_f64();
        let before = events().compaction();
        let running = property(&node.db, "rocksdb.num-running-compactions");
        let slice = last_logged_slice(&node.log(), total);
        let mut result = format!(
            "delay_s={delay:.3} since_thread_start_s={since_start:.3} thread={} running_compactions={running} \
             log_slice={} log_time={} slices_total={total} slices_marked={marked} progress_done={}",
            if before.ended.is_some() { "ended" } else { "running" },
            slice.as_ref().map_or("none".into(), |(_, slice)| slice.to_string()),
            slice.as_ref().map_or("none", |(time, _)| time.as_str()),
            before.progress_done,
        );
        let mode = match exit {
            Mode::Abrupt => "exit",
            Mode::StopThenExit => "stop-then-exit",
            Mode::StopThenReturn => "stop-then-return",
        };
        if !matches!(exit, Mode::Abrupt) {
            let latency = stop(&node);
            let after = events().compaction();
            let stopped_before = match after.ended {
                Some((_, Ending::Stopped { before, .. })) => before.to_string(),
                Some((_, ref ending)) => format!("({})", describe(ending).replace(' ', "_")),
                None => "none".into(),
            };
            let waited = after.waited.map_or("none".into(), |secs| format!("{secs:.1}"));
            write!(result, " stop_latency_s={latency:.3} stopped_before_slice={stopped_before} waited_log_s={waited}")?;
            write!(
                result,
                " running_compactions_after_stop={}",
                property(&node.db, "rocksdb.num-running-compactions")
            )?;
        }
        println!("RESULT outcome=interrupted mode={mode} {result} utc={}", utc());
        std::io::stdout().flush()?;
        match exit {
            // The store, the thread and the database are all alive here: `process::exit` runs no
            // Rust destructors, only the C library's exit handlers.
            Mode::Abrupt | Mode::StopThenExit => std::process::exit(0),
            Mode::StopThenReturn => Ok(()),
        }
    }

    /// `fault-watch`: probes writes and RocksDB's error state while the compaction thread runs.
    fn fault_watch(db_dir: &str, retention: u32, duration: f64, probe: Duration, flush_every: u64) -> Result<()> {
        let node = Node::open(db_dir, Some(retention))?;
        ensure!(node.wait_started()?.is_some(), "no compaction thread to watch");
        // A key outside every map: the network ID 0xffff has no maps.
        let key = [&[0xff, 0xff, 0xff, 0xfe][..], b"prune_bench_probe"].concat();
        let outcome = |result: std::result::Result<(), rocksdb::Error>| match result {
            Ok(()) => "ok".to_string(),
            Err(error) => format!("ERR({error})"),
        };
        let timer = Instant::now();
        let (mut last, mut flushed, mut tick) = (String::new(), "-".to_string(), 0u64);
        while timer.elapsed().as_secs_f64() < duration {
            tick += 1;
            let put = outcome(node.db.put(&key, tick.to_le_bytes()));
            if tick.is_multiple_of(flush_every) {
                flushed = outcome(node.db.flush());
            }
            let state = events().compaction();
            let thread = match &state.ended {
                Some((_, ending)) => describe(ending),
                None => format!("running, {} marked slices done at the last progress line", state.progress_done),
            };
            let line = format!(
                "put={put} last_flush={flushed} background_errors={} write_stopped={} thread=[{thread}]",
                property(&node.db, "rocksdb.background-errors"),
                property(&node.db, "rocksdb.is-write-stopped"),
            );
            // Every change, and a heartbeat.
            if line != last || tick.is_multiple_of(60) {
                let running = property(&node.db, "rocksdb.num-running-compactions");
                println!("{} PROBE tick={tick} {line} running_compactions={running}", stamp());
                last = line;
            }
            std::thread::sleep(probe);
        }
        let latency = stop(&node);
        let state = events().compaction();
        println!(
            "RESULT outcome=fault-watch stop_latency_s={latency:.3} thread=[{}] background_errors={} ledger_gb={:.2}",
            state.ended.as_ref().map_or("no ending logged".into(), |(_, ending)| describe(ending)),
            property(&node.db, "rocksdb.background-errors"),
            gb(dir_size(&node.ledger_dir)),
        );
        print_props(&node.db, "at exit", false);
        Ok(())
    }

    // ---------------------------------------------------------------------------------------------
    // The dataset.

    /// Raw access for the dataset commands; no block store, so nothing is pruned or compacted.
    struct Raw {
        storage: BlockDB<N>,
        db: RocksDB,
        ledger_dir: PathBuf,
    }

    impl Raw {
        fn open(db_dir: &str) -> Result<Self> {
            let mode = storage_mode(db_dir);
            let timer = Instant::now();
            let storage = BlockDB::<N>::open(mode.clone())?;
            let db = RocksDB::open(N::ID, mode.clone())?;
            println!("opened {db_dir} in {:.2} s", timer.elapsed().as_secs_f64());
            Ok(Self { storage, db, ledger_dir: aleo_ledger_dir(N::ID, &mode) })
        }

        /// The greatest height with a block hash, assuming heights are contiguous from zero.
        fn tip(&self) -> Result<Option<u32>> {
            let has = |height: u32| Ok::<_, anyhow::Error>(self.storage.id_map().get_confirmed(&height)?.is_some());
            if !has(0)? {
                return Ok(None);
            }
            // `low` has a hash, `high` has none.
            let (mut low, mut high) = (0u32, 1u32);
            while has(high)? {
                (low, high) = (high, high.saturating_mul(2));
                ensure!(high < u32::MAX, "no end of the chain found");
            }
            while high - low > 1 {
                let mid = low + (high - low) / 2;
                if has(mid)? { low = mid } else { high = mid }
            }
            Ok(Some(low))
        }

        /// The block tree cache describes the heights before a dataset change; a store would trust it.
        fn remove_tree_cache(&self) {
            let _ = std::fs::remove_file(self.ledger_dir.join("block_tree"));
        }
    }

    /// Waits for RocksDB's own compactions to finish, as on a node left running.
    fn settle_db(db: &RocksDB) -> Result<()> {
        db.flush()?;
        let timer = Instant::now();
        loop {
            let pending = db.property_int_value("rocksdb.compaction-pending")?.unwrap_or(0);
            let running = db.property_int_value("rocksdb.num-running-compactions")?.unwrap_or(0);
            if pending == 0 && running == 0 {
                break;
            }
            std::thread::sleep(Duration::from_secs(1));
        }
        println!("compaction settled after {:.0} s", timer.elapsed().as_secs_f64());
        print_props(db, "settled", false);
        Ok(())
    }

    /// Fills `key` with a random valid field element in little-endian bytes.
    fn random_key(rng: &mut SplitMix, key: &mut [u8]) {
        for chunk in key.chunks_exact_mut(8) {
            chunk.copy_from_slice(&rng.next().to_le_bytes());
        }
        // The BLS12-377 scalar modulus starts with 0x12, so a top byte below 0x10 is always in range.
        key[31] &= 0x0f;
    }

    fn raw_key<K: serde::Serialize>(map: BlockMap, key: &K) -> Result<Vec<u8>> {
        let mut raw = Vec::with_capacity(PREFIX_LEN + 32);
        raw.extend_from_slice(&N::ID.to_le_bytes());
        raw.extend_from_slice(&u16::from(MapID::Block(map)).to_le_bytes());
        bincode::serialize_into(&mut raw, key)?;
        Ok(raw)
    }

    /// Where a height's authority bytes and certificate count come from.
    enum Source {
        /// Authorities sampled from CDN bundles by `sample`.
        Samples(Vec<(Vec<u8>, u32)>),
        /// Random bytes: incompressible, and never decoded, as pruning and compaction read no values.
        Synthetic { bytes: usize, certs: u32 },
    }

    impl Source {
        fn parse(arg: &str) -> Result<Self> {
            let Some(spec) = arg.strip_prefix("synthetic:") else {
                let samples: Vec<(Vec<u8>, u32)> = bincode::deserialize(&std::fs::read(arg)?)?;
                ensure!(!samples.is_empty(), "empty sample file {arg}");
                return Ok(Self::Samples(samples));
            };
            let (bytes, certs) = spec.split_once(':').unwrap_or((spec, "4"));
            Ok(Self::Synthetic { bytes: bytes.parse()?, certs: certs.parse()? })
        }

        fn authority(&self, height: u32, rng: &mut SplitMix) -> (Vec<u8>, u32) {
            match self {
                Self::Samples(samples) => samples[height as usize % samples.len()].clone(),
                Self::Synthetic { bytes, certs } => {
                    let mut authority = vec![0u8; bytes.next_multiple_of(8)];
                    for chunk in authority.chunks_exact_mut(8) {
                        chunk.copy_from_slice(&rng.next().to_le_bytes());
                    }
                    authority.truncate(*bytes);
                    (authority, *certs)
                }
            }
        }
    }

    /// Adds the id, reverse-id, authority and certificate rows of `height` to `batch`. Returns the
    /// authority bytes and the number of certificate rows.
    fn put_height(
        batch: &mut rocksdb::WriteBatch,
        height: u32,
        source: &Source,
        rng: &mut SplitMix,
    ) -> Result<(u64, u64)> {
        let mut bytes = [0u8; 32];
        random_key(rng, &mut bytes);
        let hash: <N as Network>::BlockHash = Field::<N>::from_bytes_le(&bytes)?.into();
        let (authority, cert_count) = source.authority(height, rng);
        batch.put(raw_key(BlockMap::ID, &height)?, bincode::serialize(&hash)?);
        batch.put(raw_key(BlockMap::ReverseID, &hash)?, bincode::serialize(&height)?);
        let authority_bytes = authority.len() as u64;
        batch.put(raw_key(BlockMap::Authority, &hash)?, authority);
        let mut certs = 0;
        if height > 0 {
            for i in 0..cert_count {
                random_key(rng, &mut bytes);
                let id = Field::<N>::from_bytes_le(&bytes)?;
                let index = (height, u64::from(height) * 2 + u64::from(i % 2));
                batch.put(raw_key(BlockMap::Certificate, &id)?, bincode::serialize(&index)?);
                certs += 1;
            }
        }
        Ok((authority_bytes, certs))
    }

    /// Writes id, reverse-id, authority and certificate rows for `heights`; those below `split` take
    /// their authorities from `old`.
    fn write_heights(
        raw: &Raw,
        heights: std::ops::Range<u32>,
        recent: &Source,
        old: &Source,
        split: u32,
    ) -> Result<()> {
        let mut write_options = rocksdb::WriteOptions::default();
        write_options.disable_wal(true);
        // The seed of the original `build`, varied by the first height so `extend` repeats no key.
        let mut rng = SplitMix(7 ^ (u64::from(heights.start) << 32));
        let mut batch = rocksdb::WriteBatch::default();
        let (timer, mut authority_bytes, mut certs) = (Instant::now(), 0u64, 0u64);
        for height in heights.clone() {
            let source = if height < split { old } else { recent };
            let (bytes, count) = put_height(&mut batch, height, source, &mut rng)?;
            authority_bytes += bytes;
            certs += count;
            if batch.size_in_bytes() > 256 << 20 {
                raw.db.write_opt(std::mem::take(&mut batch), &write_options)?;
            }
            if height.is_multiple_of(100_000) {
                println!(
                    "height {height}: {:.1} GB authority, {:.0} s",
                    gb(authority_bytes),
                    timer.elapsed().as_secs_f64()
                );
            }
        }
        raw.db.write_opt(batch, &write_options)?;
        raw.db.flush()?;
        println!(
            "wrote heights {}..{}, {certs} certificate rows, {:.1} GB authority in {:.0} s",
            heights.start,
            heights.end,
            gb(authority_bytes),
            timer.elapsed().as_secs_f64()
        );
        raw.remove_tree_cache();
        settle_db(&raw.db)
    }

    fn build(raw: &Raw, recent: &Source, heights: u32, old: Option<&Source>, split: u32, seal_tip: bool) -> Result<()> {
        ensure!(raw.tip()?.is_none(), "the store already has blocks; use `extend`");
        write_heights(raw, 0..heights, recent, old.unwrap_or(recent), split)?;
        if seal_tip {
            seal(raw)?;
        }
        println!("next: prune <db_dir>");
        Ok(())
    }

    fn extend(raw: &Raw, source: &Source, count: u32) -> Result<()> {
        let tip = raw.tip()?.context("empty store; use `build`")?;
        write_heights(raw, tip + 1..tip + 1 + count, source, source, 0)?;
        seal(raw)
    }

    /// Stores complete blocks at the last heights the block cache reads at open, with the hashes
    /// and, where they decode, the authorities already there. The rows go through
    /// `BlockStorage::insert`, so their formats are production's.
    fn seal(raw: &Raw) -> Result<()> {
        // `BlockCache::BLOCK_CACHE_SIZE`.
        const CACHED_BLOCKS: u32 = 10;
        let tip = raw.tip()?.context("empty store")?;
        let genesis = Block::<N>::from_bytes_le(N::genesis_bytes())?;
        let one = Field::<N>::from_u64(1);
        let mut kept = 0;
        for height in tip.saturating_sub(CACHED_BLOCKS - 1).max(1)..=tip {
            let hash = *raw.storage.id_map().get_confirmed(&height)?.context("missing block hash")?;
            let previous_hash = *raw.storage.id_map().get_confirmed(&(height - 1))?.context("missing block hash")?;
            // Random bytes do not decode; a beacon authority is the smallest valid one.
            let authority = match raw.storage.get_block_authority(&hash) {
                Ok(Some(authority)) => {
                    kept += 1;
                    authority
                }
                _ => genesis.authority().clone(),
            };
            let metadata = Metadata::<N>::new(
                N::ID,
                u64::from(height) * 2,
                height,
                0,
                0,
                N::GENESIS_COINBASE_TARGET,
                N::GENESIS_PROOF_TARGET,
                N::GENESIS_COINBASE_TARGET,
                N::GENESIS_TIMESTAMP,
                N::GENESIS_TIMESTAMP + i64::from(height),
            )?;
            let header = Header::<N>::from(one.into(), one, one, one, one, one, metadata)?;
            let block = Block::<N>::from_unchecked(
                hash,
                previous_hash,
                header,
                authority,
                Ratifications::try_from(vec![])?,
                Solutions::from(None),
                vec![],
                Transactions::from_iter(std::iter::empty::<ConfirmedTransaction<N>>()),
                vec![],
            )?;
            raw.storage.insert(Field::<N>::from_u64(u64::from(height) + 2).into(), &block, None)?;
        }
        raw.db.flush()?;
        println!(
            "sealed the tip at height {tip}: {kept} stored authorities kept, the rest replaced by a beacon authority"
        );
        Ok(())
    }

    fn status(raw: &Raw) -> Result<()> {
        println!("tip = {:?}", raw.tip()?);
        println!("watermark = {:?}", raw.storage.confirmed_authority_pruned_below()?);
        // The plan flushes the memtable first, as the compaction thread's does.
        let plan = raw.storage.authority_compaction_plan()?;
        let marked: Vec<usize> = plan.iter().enumerate().filter_map(|(i, &marked)| marked.then_some(i)).collect();
        println!(
            "authority compaction plan: {} slices, {} marked; first marked {:?}",
            plan.len(),
            marked.len(),
            marked.first()
        );
        println!("ledger directory: {:.2} GB", gb(dir_size(&raw.ledger_dir)));
        print_props(&raw.db, "status", true);
        Ok(())
    }

    fn percentiles(mut values: Vec<u64>) -> String {
        if values.is_empty() {
            return "n=0".into();
        }
        values.sort_unstable();
        let at = |p: f64| values[((values.len() - 1) as f64 * p) as usize];
        let mean = values.iter().sum::<u64>() as f64 / values.len() as f64;
        format!(
            "n={} mean={mean:.0} p50={} p90={} p99={} max={}",
            values.len(),
            at(0.5),
            at(0.9),
            at(0.99),
            values[values.len() - 1]
        )
    }

    /// Decodes the CDN bundles in `dir`, prints size distributions, and saves the authority bytes and
    /// certificate counts of blocks at or above `min_height` to `out`.
    fn sample(dir: &str, out: &str, min_height: u32) -> Result<()> {
        let mut bundles: Vec<PathBuf> = std::fs::read_dir(dir)?
            .filter_map(|e| e.ok())
            .map(|e| e.path())
            .filter(|p| p.extension().is_some_and(|e| e == "blocks"))
            .collect();
        bundles.sort();
        let (mut recent_authority, mut recent_certs, mut recent_block) = (vec![], vec![], vec![]);
        let mut saved: Vec<(Vec<u8>, u32)> = vec![];
        for path in bundles {
            let blocks: Vec<Block<N>> = unchecked_deserialize(&std::fs::read(&path)?)?;
            let recent = blocks.first().is_some_and(|b| b.height() >= min_height);
            let (mut authority, mut certs, mut block) = (vec![], vec![], vec![]);
            for b in &blocks {
                let authority_bytes = bincode::serialize(b.authority())?;
                let cert_count = match b.authority() {
                    Authority::Beacon(_) => 0,
                    Authority::Quorum(subdag) => u32::try_from(subdag.certificate_ids().count())?,
                };
                authority.push(authority_bytes.len() as u64);
                certs.push(u64::from(cert_count));
                block.push(bincode::serialize(b)?.len() as u64);
                if recent {
                    saved.push((authority_bytes, cert_count));
                }
            }
            if recent {
                recent_authority.extend(authority);
                recent_certs.extend(certs);
                recent_block.extend(block);
            } else {
                println!("{}: height {}", path.display(), blocks.first().map_or(0, Block::height));
                println!("  authority bytes {}", percentiles(authority));
                println!("  certificates    {}", percentiles(certs));
                println!("  block bytes     {}", percentiles(block));
            }
        }
        println!("saved (>= {min_height}): {} blocks", saved.len());
        println!("  authority bytes {}", percentiles(recent_authority));
        println!("  certificates    {}", percentiles(recent_certs));
        println!("  block bytes     {}", percentiles(recent_block));
        std::fs::write(out, bincode::serialize(&saved)?)?;
        Ok(())
    }

    // ---------------------------------------------------------------------------------------------
    // The certificate pass on the raw database: the store's rewrite and the candidates.

    /// `RETAIN_SLICES`, `RETAIN_THREADS` and `RETAIN_READAHEAD` of the store's `retain_all`.
    const CERT_SLICES: usize = 256;
    const CERT_THREADS: usize = 4;
    const CERT_READAHEAD: usize = 4 << 20;

    /// The first key after every key of a map, as the store's `prefix_end`.
    fn prefix_end(prefix: [u8; PREFIX_LEN]) -> [u8; PREFIX_LEN] {
        (u32::from_be_bytes(prefix) + 1).to_be_bytes()
    }

    /// The raw key bounds `lower..upper` of the slices `i..i + count` of `slices`, as the store's
    /// `slice_bounds` and `key_range` give them.
    fn slice_range(prefix: [u8; PREFIX_LEN], i: usize, count: usize, slices: usize) -> (Vec<u8>, Vec<u8>) {
        let start = |i: usize| ((i * 65536 / slices) as u16).to_be_bytes();
        let lower = [&prefix[..], &start(i)[..]].concat();
        let upper = match i + count < slices {
            true => [&prefix[..], &start(i + count)[..]].concat(),
            false => prefix_end(prefix).to_vec(),
        };
        (lower, upper)
    }

    /// The first and the last possible key of slice `i` of `slices`, as the store's
    /// `slice_key_range` gives them to a sliced compaction.
    fn slice_key_range(prefix: [u8; PREFIX_LEN], i: usize, slices: usize) -> (Vec<u8>, Vec<u8>) {
        let start = |i: usize| (i * 65536 / slices) as u16;
        let end = match i + 1 < slices {
            true => [&prefix[..], &(start(i + 1) - 1).to_be_bytes(), &[0xff; 30][..]].concat(),
            false => [&prefix[..], &[0xff; 32][..]].concat(),
        };
        ([&prefix[..], &start(i).to_be_bytes()[..]].concat(), end)
    }

    /// The peak and the current resident memory in MB; zero where `/proc` is absent.
    fn memory_mb() -> (f64, f64) {
        let status = std::fs::read_to_string("/proc/self/status").unwrap_or_default();
        let field = |name: &str| {
            let line = status.lines().find(|line| line.starts_with(name));
            line.and_then(|line| numbers(line).first().copied()).unwrap_or(0.0) / 1024.0
        };
        (field("VmHWM:"), field("VmRSS:"))
    }

    /// Restarts the peak resident memory at the current value (Linux; a no-op elsewhere).
    fn reset_peak_memory() {
        let _ = std::fs::write("/proc/self/clear_refs", "5");
    }

    /// Samples the size of a directory once a second and keeps the largest.
    struct PeakDirSize {
        stop: Arc<AtomicBool>,
        peak: Arc<AtomicU64>,
        handle: std::thread::JoinHandle<()>,
    }

    impl PeakDirSize {
        fn start(dir: PathBuf) -> Self {
            let (stop, peak) = (Arc::new(AtomicBool::new(false)), Arc::new(AtomicU64::new(dir_size(&dir))));
            let handle = std::thread::spawn({
                let (stop, peak) = (stop.clone(), peak.clone());
                move || {
                    while !stop.load(Ordering::Relaxed) {
                        peak.fetch_max(dir_size(&dir), Ordering::Relaxed);
                        std::thread::sleep(Duration::from_secs(1));
                    }
                    peak.fetch_max(dir_size(&dir), Ordering::Relaxed);
                }
            });
            Self { stop, peak, handle }
        }

        fn finish(self) -> u64 {
            self.stop.store(true, Ordering::Relaxed);
            let _ = self.handle.join();
            self.peak.load(Ordering::Relaxed)
        }
    }

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    enum PassMode {
        /// No pass.
        None,
        /// Counts the rows.
        Scan,
        /// One delete per removed row.
        Point,
        /// The store's write: a range delete of the slice, then puts of the kept rows.
        Rewrite,
        /// Deletes if the slice loses at most half its rows and no more than the cap; otherwise a
        /// second scan that rewrites.
        Design,
        /// As `Design`, but the first scan ends as soon as it has seen more removed rows than the cap.
        DesignEarly,
    }

    impl PassMode {
        fn parse(name: &str) -> Result<Self> {
            Ok(match name {
                "none" => Self::None,
                "scan" => Self::Scan,
                "point" => Self::Point,
                "rewrite" => Self::Rewrite,
                "design" => Self::Design,
                "design-early" => Self::DesignEarly,
                other => bail!("unknown mode {other}"),
            })
        }
    }

    #[derive(Clone, Debug, Default)]
    struct SliceStats {
        kept: u64,
        removed: u64,
        /// The key and value bytes of the rows read.
        row_bytes: u64,
        scan_secs: f64,
        /// The second scan of a slice that `design` rewrites.
        rescan_secs: f64,
        write_secs: f64,
        /// The size of the batch written.
        batch_bytes: usize,
        /// The size of a delete batch that `design` built and dropped.
        dropped_bytes: usize,
        wrote_deletes: bool,
        wrote_rewrite: bool,
        /// The deletion entries the scan stepped over, and every entry it stepped over, rows included.
        tombstones: u64,
        entries: u64,
    }

    /// Visits the rows in `lower..upper` with the read options of the store's `retain_range`, until
    /// `visit` returns `false`.
    fn scan_range(db: &RocksDB, lower: &[u8], upper: &[u8], mut visit: impl FnMut(&[u8], &[u8]) -> bool) -> Result<()> {
        let mut options = rocksdb::ReadOptions::default();
        options.set_total_order_seek(true);
        options.set_iterate_lower_bound(lower.to_vec());
        options.set_iterate_upper_bound(upper.to_vec());
        options.set_readahead_size(CERT_READAHEAD);
        options.fill_cache(false);
        let mut iter = db.raw_iterator_opt(options);
        iter.seek(lower);
        while let Some((key, value)) = iter.item() {
            if !visit(key, value) {
                break;
            }
            iter.next();
        }
        iter.status()?;
        Ok(())
    }

    /// Whether a certificate row's value, `(height, round)` in bincode, is of a height in `1..below`.
    fn is_removable(value: &[u8], below: u32) -> bool {
        value.first_chunk::<4>().is_some_and(|height| (1..below).contains(&u32::from_le_bytes(*height)))
    }

    /// Runs one mode of the certificate pass on the rows in `lower..upper`, in one write.
    fn pass_range(
        db: &RocksDB,
        lower: &[u8],
        upper: &[u8],
        below: u32,
        mode: PassMode,
        cap: usize,
    ) -> Result<SliceStats> {
        use rocksdb::perf::{PerfContext, PerfMetric};

        let mut stats = SliceStats::default();
        let mut perf = PerfContext::default();
        perf.reset();
        let timer = Instant::now();
        let mut batch = rocksdb::WriteBatch::default();
        let design = matches!(mode, PassMode::Design | PassMode::DesignEarly);
        if mode == PassMode::Rewrite {
            // The range delete applies before the puts that follow it.
            batch.delete_range(lower, upper);
        }
        scan_range(db, lower, upper, |key, value| {
            stats.row_bytes += (key.len() + value.len()) as u64;
            if is_removable(value, below) {
                stats.removed += 1;
                if mode == PassMode::Point || (design && batch.len() < cap) {
                    batch.delete(key);
                }
            } else {
                stats.kept += 1;
                if mode == PassMode::Rewrite {
                    batch.put(key, value);
                }
            }
            mode != PassMode::DesignEarly || stats.removed <= cap as u64
        })?;
        stats.scan_secs = timer.elapsed().as_secs_f64();
        stats.tombstones = perf.metric(PerfMetric::InternalDeleteSkippedCount);
        stats.entries = perf.metric(PerfMetric::InternalKeySkippedCount);

        let deletes_fit = stats.removed <= stats.kept && stats.removed <= cap as u64;
        match mode {
            PassMode::None | PassMode::Scan => {}
            _ if stats.removed == 0 => {}
            _ if design && !deletes_fit => {
                stats.dropped_bytes = batch.size_in_bytes();
                drop(batch);
                let rewrite = pass_range(db, lower, upper, below, PassMode::Rewrite, cap)?;
                // The first scan may have ended early.
                (stats.kept, stats.removed, stats.row_bytes) = (rewrite.kept, rewrite.removed, rewrite.row_bytes);
                stats.rescan_secs = rewrite.scan_secs;
                stats.write_secs = rewrite.write_secs;
                stats.batch_bytes = rewrite.batch_bytes;
                stats.wrote_rewrite = true;
            }
            _ => {
                stats.batch_bytes = batch.size_in_bytes();
                let timer = Instant::now();
                db.write(batch)?;
                stats.write_secs = timer.elapsed().as_secs_f64();
                stats.wrote_rewrite = mode == PassMode::Rewrite;
                stats.wrote_deletes = mode != PassMode::Rewrite;
            }
        }
        Ok(stats)
    }

    /// Runs one mode of the certificate pass over the map, in 256 slices on `threads` threads.
    fn cert_pass(db: &RocksDB, below: u32, mode: PassMode, cap: usize, threads: usize) -> Result<Vec<SliceStats>> {
        use rayon::iter::{IntoParallelIterator, ParallelIterator};

        let prefix = map_prefix(BlockMap::Certificate);
        let pool = rayon::ThreadPoolBuilder::new().num_threads(threads).build()?;
        pool.install(|| {
            (0..CERT_SLICES)
                .into_par_iter()
                .map(|i| {
                    // The counters are per thread.
                    rocksdb::perf::set_perf_stats(rocksdb::perf::PerfStatsLevel::EnableCount);
                    let (lower, upper) = slice_range(prefix, i, 1, CERT_SLICES);
                    pass_range(db, &lower, &upper, below, mode, cap)
                })
                .collect()
        })
    }

    /// Runs a pass with its measurements around it and prints them.
    fn measured_pass(
        db: &RocksDB,
        log: &Path,
        label: &str,
        below: u32,
        mode: PassMode,
        cap: usize,
        threads: usize,
    ) -> Result<Vec<SliceStats>> {
        reset_peak_memory();
        let (_, rss_before) = memory_mb();
        let (timer, io, stalls) = (Instant::now(), disk_io(), stall_count(log));
        let slices = cert_pass(db, below, mode, cap, threads)?;
        let (secs, io_after, (peak, _)) = (timer.elapsed().as_secs_f64(), disk_io(), memory_mb());

        let sum = |f: &dyn Fn(&SliceStats) -> f64| slices.iter().map(f).sum::<f64>();
        let count = |f: &dyn Fn(&SliceStats) -> bool| slices.iter().filter(|s| f(s)).count();
        let largest = |f: &dyn Fn(&SliceStats) -> usize| slices.iter().map(f).max().unwrap_or(0);
        let (kept, removed) = (sum(&|s| s.kept as f64), sum(&|s| s.removed as f64));
        let mut walls: Vec<f64> = slices.iter().map(|s| s.scan_secs + s.rescan_secs + s.write_secs).collect();
        walls.sort_by(f64::total_cmp);
        println!(
            "RESULT cert-pass label={label} mode={mode:?} below={below} cap={cap} threads={threads} secs={secs:.2} \
             rows={:.0} kept={kept:.0} removed={removed:.0} removed_fraction={:.4} row_bytes={:.0} \
             slices_deleted={} slices_rewritten={} slices_untouched={} \
             scan_thread_s={:.2} rescan_thread_s={:.2} write_thread_s={:.2} slice_s_median={:.3} slice_s_max={:.3} \
             batch_bytes_total={:.0} batch_bytes_max={} dropped_bytes_total={:.0} dropped_bytes_max={} \
             tombstones_skipped={:.0} entries_stepped={:.0} disk_read_gb={:.3} disk_write_gb={:.3} stalls={} \
             rss_before_mb={rss_before:.0} rss_peak_mb={peak:.0}",
            kept + removed,
            removed / (kept + removed).max(1.0),
            sum(&|s| s.row_bytes as f64),
            count(&|s| s.wrote_deletes),
            count(&|s| s.wrote_rewrite),
            count(&|s| !s.wrote_deletes && !s.wrote_rewrite),
            sum(&|s| s.scan_secs),
            sum(&|s| s.rescan_secs),
            sum(&|s| s.write_secs),
            walls[walls.len() / 2],
            walls[walls.len() - 1],
            sum(&|s| s.batch_bytes as f64),
            largest(&|s| s.batch_bytes),
            sum(&|s| s.dropped_bytes as f64),
            largest(&|s| s.dropped_bytes),
            sum(&|s| s.tombstones as f64),
            sum(&|s| s.entries as f64),
            gb(io_after.read.saturating_sub(io.read)),
            gb(io_after.write.saturating_sub(io.write)),
            stall_count(log).saturating_sub(stalls),
        );
        Ok(slices)
    }

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    enum CompactKind {
        /// The store's `compact_prefix`: a plain `compact_range`.
        Plain,
        /// The store's `compact_key_range`: bottom-level files are rewritten too.
        Force,
    }

    impl CompactKind {
        fn parse(name: &str) -> Result<Self> {
            Ok(match name {
                "plain" => Self::Plain,
                "force" => Self::Force,
                other => bail!("unknown compaction {other}"),
            })
        }
    }

    /// Compacts slice `i` of `slices` of a map; slice 0 of 1 is the map.
    fn compact_map(db: &RocksDB, map: BlockMap, kind: CompactKind, i: usize, slices: usize) {
        let prefix = map_prefix(map);
        match kind {
            CompactKind::Plain => {
                let (lower, upper) = slice_range(prefix, i, 1, slices);
                db.compact_range(Some(&lower), Some(&upper));
            }
            CompactKind::Force => {
                let (lower, end) = slice_key_range(prefix, i, slices);
                let mut options = rocksdb::CompactOptions::default();
                options.set_bottommost_level_compaction(rocksdb::BottommostLevelCompaction::ForceOptimized);
                options.set_exclusive_manual_compaction(false);
                db.compact_range_opt(Some(&lower), Some(&end), &options);
            }
        }
    }

    /// Compacts the certificate map and prints the time, the disk bytes and the error count.
    fn measured_compaction(db: &RocksDB, log: &Path, label: &str, kind: CompactKind) -> f64 {
        let (timer, io, stalls) = (Instant::now(), disk_io(), stall_count(log));
        let errors = property(db, "rocksdb.background-errors");
        compact_map(db, BlockMap::Certificate, kind, 0, 1);
        let (secs, io_after) = (timer.elapsed().as_secs_f64(), disk_io());
        println!(
            "RESULT cert-compact label={label} kind={kind:?} secs={secs:.2} disk_read_gb={:.3} disk_write_gb={:.3} \
             stalls={} background_errors={errors}->{}",
            gb(io_after.read.saturating_sub(io.read)),
            gb(io_after.write.saturating_sub(io.write)),
            stall_count(log).saturating_sub(stalls),
            property(db, "rocksdb.background-errors"),
        );
        secs
    }

    /// Prints the live files that overlap the certificate prefix, by level, and RocksDB's size
    /// estimate for the prefix. A file's entries and deletions are those RocksDB has loaded: after a
    /// restart, at most about 20 files.
    fn cert_state(db: &RocksDB, ledger_dir: &Path, label: &str) -> Result<()> {
        let prefix = map_prefix(BlockMap::Certificate);
        let end = prefix_end(prefix);
        let mut levels = std::collections::BTreeMap::<i32, (usize, usize, u64, u64)>::new();
        for file in db.live_files()? {
            let after = file.start_key.as_deref().is_some_and(|start| start >= &end[..]);
            let before = file.end_key.as_deref().is_some_and(|last| last < &prefix[..]);
            if !after && !before {
                let level = levels.entry(file.level).or_default();
                *level = (level.0 + 1, level.1 + file.size, level.2 + file.num_entries, level.3 + file.num_deletions);
            }
        }
        let total = levels.values().fold((0, 0, 0, 0), |a, l| (a.0 + l.0, a.1 + l.1, a.2 + l.2, a.3 + l.3));
        let by_level: Vec<String> =
            levels.iter().map(|(level, l)| format!("L{level}:{}f/{}B/{}e/{}d", l.0, l.1, l.2, l.3)).collect();
        println!(
            "RESULT cert-state label={label} approximate_bytes={} files={} file_bytes={} file_entries={} \
             file_deletions={} levels=[{}] total_sst_bytes={} ledger_dir_bytes={} memtable_bytes={}",
            db.get_approximate_sizes(&[rocksdb::Range::new(&prefix, &end)])[0],
            total.0,
            total.1,
            total.2,
            total.3,
            by_level.join(","),
            property(db, "rocksdb.total-sst-files-size"),
            dir_size(ledger_dir),
            property(db, "rocksdb.cur-size-all-mem-tables"),
        );
        Ok(())
    }

    #[derive(Clone, Copy, Debug, PartialEq)]
    enum Load {
        None,
        /// Repeats the certificate scan.
        Scan,
        /// Stores this many heights per second after the tip, one batch each; zero is unthrottled.
        Write(f64),
    }

    impl Load {
        fn parse(name: &str) -> Result<Self> {
            Ok(match name {
                "none" => Self::None,
                "scan" => Self::Scan,
                other => Self::Write(other.strip_prefix("write:").context("unknown load")?.parse()?),
            })
        }
    }

    /// Compacts the certificate map on a thread while `load` runs on this one, and prints the
    /// compaction's time and the load's latencies.
    fn compact_under_load(
        db_dir: &str,
        db: &RocksDB,
        log: &Path,
        kind: CompactKind,
        load: Load,
        source: Option<&str>,
        below: u32,
    ) -> Result<()> {
        // Opened before the compaction starts, so the load starts with it.
        let writer = match load {
            Load::Write(_) => {
                let raw = Raw::open(db_dir)?;
                let tip = raw.tip()?.context("empty store")?;
                Some((raw, tip, Source::parse(source.context("--load write needs --source <sample>")?)?))
            }
            _ => None,
        };
        let done = AtomicBool::new(false);
        let (io, stalls) = (disk_io(), stall_count(log));
        let errors = property(db, "rocksdb.background-errors");
        let (secs, mut latencies, load_secs) = std::thread::scope(|scope| -> Result<_> {
            let compaction = scope.spawn(|| {
                let timer = Instant::now();
                compact_map(db, BlockMap::Certificate, kind, 0, 1);
                done.store(true, Ordering::SeqCst);
                timer.elapsed().as_secs_f64()
            });
            let (timer, mut latencies) = (Instant::now(), Vec::<f64>::new());
            match load {
                Load::None => {}
                Load::Scan => {
                    while !done.load(Ordering::SeqCst) {
                        let timer = Instant::now();
                        cert_pass(db, below, PassMode::Scan, 0, CERT_THREADS)?;
                        latencies.push(timer.elapsed().as_secs_f64());
                    }
                }
                Load::Write(per_sec) => {
                    let (_, tip, source) = writer.as_ref().context("no writer")?;
                    let mut rng = SplitMix(11 ^ (u64::from(*tip) << 32));
                    let mut height = *tip;
                    while !done.load(Ordering::SeqCst) {
                        height += 1;
                        let mut batch = rocksdb::WriteBatch::default();
                        put_height(&mut batch, height, source, &mut rng)?;
                        let write = Instant::now();
                        db.write(batch)?;
                        latencies.push(write.elapsed().as_secs_f64());
                        if per_sec > 0.0 {
                            let due = Duration::from_secs_f64(latencies.len() as f64 / per_sec);
                            std::thread::sleep(due.saturating_sub(timer.elapsed()));
                        }
                    }
                }
            }
            let load_secs = timer.elapsed().as_secs_f64();
            let secs = compaction.join().map_err(|_| anyhow::anyhow!("the compaction thread panicked"))?;
            Ok((secs, latencies, load_secs))
        })?;
        latencies.sort_by(f64::total_cmp);
        let at = |p: f64| latencies.get(((latencies.len().max(1) - 1) as f64 * p) as usize).copied().unwrap_or(0.0);
        let io_after = disk_io();
        println!(
            "RESULT bg-compact kind={kind:?} load={load:?} compaction_s={secs:.2} load_s={load_secs:.2} load_ops={} \
             op_ms_p50={:.3} op_ms_p99={:.3} op_ms_max={:.3} disk_read_gb={:.3} disk_write_gb={:.3} stalls={} \
             background_errors={errors}->{}",
            latencies.len(),
            at(0.5) * 1e3,
            at(0.99) * 1e3,
            at(1.0) * 1e3,
            gb(io_after.read.saturating_sub(io.read)),
            gb(io_after.write.saturating_sub(io.write)),
            stall_count(log).saturating_sub(stalls),
            property(db, "rocksdb.background-errors"),
        );
        Ok(())
    }

    struct PassArgs {
        below: u32,
        mode: PassMode,
        cap: usize,
        threads: usize,
        flush: bool,
        compact: Option<CompactKind>,
        then_open: bool,
        bg_compact: Option<CompactKind>,
        load: Load,
        source: Option<String>,
        retention: u32,
    }

    /// `cert-pass`: a pass, then optionally a flush, a compaction, the store's own open, and a
    /// compaction under load.
    fn cert_pass_command(db_dir: &str, args: &PassArgs) -> Result<()> {
        let mode = storage_mode(db_dir);
        let ledger_dir = aleo_ledger_dir(N::ID, &mode);
        let log = ledger_dir.join("LOG");
        let timer = Instant::now();
        let db = RocksDB::open(N::ID, mode.clone())?;
        println!("{} opened the database at {db_dir} in {:.2} s", stamp(), timer.elapsed().as_secs_f64());
        let peak = PeakDirSize::start(ledger_dir.clone());
        // A run that times the open reads nothing it does not need before it.
        if !args.then_open {
            cert_state(&db, &ledger_dir, "before")?;
        }
        if args.mode != PassMode::None {
            measured_pass(&db, &log, "pass", args.below, args.mode, args.cap, args.threads)?;
        }
        if args.flush {
            let (timer, io) = (Instant::now(), disk_io());
            db.flush()?;
            println!(
                "RESULT cert-flush secs={:.2} disk_write_gb={:.3}",
                timer.elapsed().as_secs_f64(),
                gb(disk_io().write.saturating_sub(io.write))
            );
        }
        if let Some(kind) = args.compact {
            measured_compaction(&db, &log, "after-pass", kind);
        }
        if !args.then_open && (args.mode != PassMode::None || args.compact.is_some()) {
            cert_state(&db, &ledger_dir, "after")?;
        }
        if args.then_open {
            let before_open = events().start.elapsed().as_secs_f64();
            let window = Window::start(&log);
            let store = Store::open_with_authority_retention(mode.clone(), Some(args.retention))?;
            let total = events().start.elapsed().as_secs_f64();
            let open = window.report("store open (block tree, block cache, startup pruning)", &log);
            let logged = |prefix: &str| events().logged_number(prefix).map_or("none".into(), |n| format!("{n}"));
            println!(
                "RESULT open mode={:?} compact={:?} process_start_to_open_s={total:.2} before_store_open_s={before_open:.2} \
                 store_open_s={open:.2} store_walk_s={} store_cert_scan_nothing_removed_s={} store_cert_rewrite_s={} \
                 store_cert_compaction_s={} watermark={:?}",
                args.mode,
                args.compact,
                logged("Pruned the authority data below block"),
                logged("No certificate indexes of pruned blocks to remove"),
                logged("Removed "),
                logged("Compacted the certificate map"),
                store.authority_pruned_below()?,
            );
            std::io::stdout().flush()?;
            let timer = Instant::now();
            store.stop_background_work();
            println!("{} stop_background_work() returned after {:.3} s", stamp(), timer.elapsed().as_secs_f64());
            cert_state(&db, &ledger_dir, "after-open")?;
        }
        if let Some(kind) = args.bg_compact {
            compact_under_load(db_dir, &db, &log, kind, args.load, args.source.as_deref(), args.below)?;
            cert_state(&db, &ledger_dir, "after-bg-compact")?;
        }
        let (peak_mb, rss_mb) = memory_mb();
        println!(
            "RESULT process secs={:.2} rss_peak_mb={peak_mb:.0} rss_mb={rss_mb:.0} peak_ledger_dir_bytes={} \
             ledger_dir_bytes={} background_errors={}",
            events().start.elapsed().as_secs_f64(),
            peak.finish(),
            dir_size(&ledger_dir),
            property(&db, "rocksdb.background-errors"),
        );
        Ok(())
    }

    /// `slice-bench`: the cost of one slice by removal fraction, from a warm page cache, and of one
    /// large batch.
    fn slice_bench(
        db_dir: &str,
        belows: &[u32],
        reps: usize,
        big_keys: usize,
        big_slices: usize,
        big_below: u32,
    ) -> Result<()> {
        let db = RocksDB::open(N::ID, storage_mode(db_dir))?;
        rocksdb::perf::set_perf_stats(rocksdb::perf::PerfStatsLevel::EnableCount);
        let prefix = map_prefix(BlockMap::Certificate);
        let mut next = 0;
        let ms = |secs: f64| secs * 1e3;
        for &below in belows {
            for mode in [PassMode::Point, PassMode::Rewrite] {
                for _ in 0..reps {
                    ensure!(next < CERT_SLICES, "more runs than slices");
                    let (lower, upper) = slice_range(prefix, next, 1, CERT_SLICES);
                    // The first scan loads the page cache.
                    let first = pass_range(&db, &lower, &upper, below, PassMode::Scan, 0)?;
                    let scan = pass_range(&db, &lower, &upper, below, PassMode::Scan, 0)?;
                    let run = pass_range(&db, &lower, &upper, below, mode, usize::MAX)?;
                    // The next start's scan of this slice, with the write still in the memtable.
                    let after = pass_range(&db, &lower, &upper, below, PassMode::Scan, 0)?;
                    println!(
                        "RESULT slice-bench below={below} mode={mode:?} slice={next} kept={} removed={} \
                         removed_fraction={:.4} first_scan_ms={:.2} warm_scan_ms={:.2} scan_and_build_ms={:.2} \
                         write_ms={:.2} batch_bytes={} row_bytes={} scan_after_ms={:.2} scan_after_tombstones={} \
                         scan_after_entries={} scan_after_rows={}",
                        run.kept,
                        run.removed,
                        run.removed as f64 / (run.kept + run.removed).max(1) as f64,
                        ms(first.scan_secs),
                        ms(scan.scan_secs),
                        ms(run.scan_secs),
                        ms(run.write_secs),
                        run.batch_bytes,
                        run.row_bytes,
                        ms(after.scan_secs),
                        after.tombstones,
                        after.entries,
                        after.kept + after.removed,
                    );
                    next += 1;
                }
            }
        }
        if big_keys > 0 {
            ensure!(next + big_slices <= CERT_SLICES, "the large batch needs {big_slices} untouched slices");
            let (lower, upper) = slice_range(prefix, next, big_slices, CERT_SLICES);
            let (mut removed, mut kept) = (Vec::<Vec<u8>>::new(), Vec::<(Vec<u8>, Vec<u8>)>::new());
            let timer = Instant::now();
            scan_range(&db, &lower, &upper, |key, value| {
                if is_removable(value, big_below) {
                    if removed.len() < big_keys {
                        removed.push(key.to_vec());
                    }
                } else if kept.len() < big_keys {
                    kept.push((key.to_vec(), value.to_vec()));
                }
                true
            })?;
            let scan_secs = timer.elapsed().as_secs_f64();
            let timer = Instant::now();
            let mut deletes = rocksdb::WriteBatch::default();
            removed.iter().for_each(|key| deletes.delete(key));
            let (build_deletes, delete_bytes) = (timer.elapsed().as_secs_f64(), deletes.size_in_bytes());
            let timer = Instant::now();
            db.write(deletes)?;
            let write_deletes = timer.elapsed().as_secs_f64();
            let timer = Instant::now();
            let mut puts = rocksdb::WriteBatch::default();
            kept.iter().for_each(|(key, value)| puts.put(key, value));
            let (build_puts, put_bytes) = (timer.elapsed().as_secs_f64(), puts.size_in_bytes());
            let timer = Instant::now();
            db.write(puts)?;
            let write_puts = timer.elapsed().as_secs_f64();
            println!(
                "RESULT big-batch below={big_below} slices={big_slices} scan_ms={:.1} deletes={} delete_batch_bytes={delete_bytes} \
                 build_deletes_ms={:.2} write_deletes_ms={:.2} puts={} put_batch_bytes={put_bytes} build_puts_ms={:.2} \
                 write_puts_ms={:.2}",
                ms(scan_secs),
                removed.len(),
                ms(build_deletes),
                ms(write_deletes),
                kept.len(),
                ms(build_puts),
                ms(write_puts),
            );
        }
        Ok(())
    }

    struct FaultArgs {
        below: u32,
        kind: String,
        fault_on: Option<String>,
        fault_off: Option<String>,
        stop_by_flush: bool,
        /// Skips the compactions that rewrite the bottom level, which take minutes on a healthy store.
        skip_force: bool,
    }

    /// `fault-cert`: what manual compactions do on a broken disk and on a store RocksDB has stopped.
    fn fault_cert(db_dir: &str, args: &FaultArgs) -> Result<()> {
        use std::os::unix::fs::PermissionsExt;

        let mode = storage_mode(db_dir);
        let ledger_dir = aleo_ledger_dir(N::ID, &mode);
        let log = ledger_dir.join("LOG");
        let db = RocksDB::open(N::ID, mode)?;
        // Work for the compactions, flushed so that none of them starts with a flush.
        measured_pass(&db, &log, "setup", args.below, PassMode::Point, usize::MAX, CERT_THREADS)?;
        db.flush()?;
        // RocksDB's own compactions end first, so the first failure is the manual compaction's.
        let timer = Instant::now();
        while property(&db, "rocksdb.num-running-compactions") > 0 && timer.elapsed() < Duration::from_secs(300) {
            std::thread::sleep(Duration::from_millis(200));
        }
        println!("{} RocksDB's own compactions ended after {:.1} s", stamp(), timer.elapsed().as_secs_f64());
        cert_state(&db, &ledger_dir, "before")?;

        let errors = || property(&db, "rocksdb.background-errors");
        let outcome = |result: std::result::Result<(), rocksdb::Error>| match result {
            Ok(()) => "ok".to_string(),
            Err(error) => format!("ERR({error})"),
        };
        // A key outside every map: the network ID 0xffff has no maps.
        let key = [&[0xff, 0xff, 0xff, 0xfe][..], b"prune_bench_probe"].concat();
        let probe = |label: &str| {
            let timer = Instant::now();
            let put = outcome(db.put(&key, utc().as_bytes()));
            println!(
                "{} PROBE at={label} put={put} put_s={:.3} background_errors={} running_compactions={} write_stopped={}",
                stamp(),
                timer.elapsed().as_secs_f64(),
                errors(),
                property(&db, "rocksdb.num-running-compactions"),
                property(&db, "rocksdb.is-write-stopped"),
            );
        };
        let step = |label: &str, work: &dyn Fn() -> String| {
            let (before, io, timer) = (errors(), disk_io(), Instant::now());
            let result = work();
            println!(
                "{} STEP {label}: returned after {:.3} s, result={result}, background_errors {before} -> {}, disk_write_gb={:.3}",
                stamp(),
                timer.elapsed().as_secs_f64(),
                errors(),
                gb(disk_io().write.saturating_sub(io.write)),
            );
            probe(&format!("after-{}", label.split(' ').next().unwrap_or_default()));
        };
        let shell = |command: &Option<String>| -> Result<()> {
            if let Some(command) = command {
                let status = std::process::Command::new("sh").arg("-c").arg(command).status()?;
                println!("{} ran `{command}`: {status}", stamp());
            }
            Ok(())
        };
        let compact = |map: BlockMap, kind: CompactKind, i: usize, slices: usize| {
            compact_map(&db, map, kind, i, slices);
            "returned (the call reports no status)".to_string()
        };

        probe("healthy");
        match args.kind.as_str() {
            "none" => {}
            "chmod" => std::fs::set_permissions(&ledger_dir, std::fs::Permissions::from_mode(0o555))?,
            "cmd" => shell(&args.fault_on)?,
            other => bail!("unknown fault {other}"),
        }
        println!("{} FAULT {} on", stamp(), args.kind);
        probe("fault-on");
        if args.stop_by_flush {
            step("F1 flush", &|| outcome(db.flush()));
        }
        step("C1 plain compact_range of the certificate prefix", &|| {
            compact(BlockMap::Certificate, CompactKind::Plain, 0, 1)
        });
        step("C2 plain compact_range of the certificate prefix again", &|| {
            compact(BlockMap::Certificate, CompactKind::Plain, 0, 1)
        });
        if !args.skip_force {
            step("C3 ForceOptimized, authority slice 0 of 24", &|| {
                compact(BlockMap::Authority, CompactKind::Force, 0, 24)
            });
            step("C4 ForceOptimized, certificate prefix", &|| compact(BlockMap::Certificate, CompactKind::Force, 0, 1));
        }
        step("W1 wait_for_compact, 10 s timeout", &|| {
            let mut options = rocksdb::WaitForCompactOptions::default();
            options.set_timeout(10_000_000);
            outcome(db.wait_for_compact(&options))
        });
        match args.kind.as_str() {
            "chmod" => std::fs::set_permissions(&ledger_dir, std::fs::Permissions::from_mode(0o755))?,
            "cmd" => shell(&args.fault_off)?,
            _ => {}
        }
        println!("{} FAULT {} off", stamp(), args.kind);
        probe("fault-off");
        step("C5 plain compact_range of the certificate prefix, fault removed", &|| {
            compact(BlockMap::Certificate, CompactKind::Plain, 0, 1)
        });
        step("F2 flush", &|| outcome(db.flush()));
        cert_state(&db, &ledger_dir, "after")?;
        println!(
            "RESULT fault-cert kind={} stop_by_flush={} background_errors={}",
            args.kind,
            args.stop_by_flush,
            errors()
        );
        Ok(())
    }

    // ---------------------------------------------------------------------------------------------

    fn flag(args: &[String], name: &str) -> bool {
        args.iter().any(|a| a == name)
    }

    fn flag_value<T: std::str::FromStr>(args: &[String], name: &str) -> Result<Option<T>>
    where
        T::Err: std::error::Error + Send + Sync + 'static,
    {
        match args.iter().position(|a| a == name) {
            Some(i) => Ok(Some(args.get(i + 1).with_context(|| format!("{name} needs a value"))?.parse()?)),
            None => Ok(None),
        }
    }

    pub fn main() -> Result<()> {
        events();
        tracing::subscriber::set_global_default(Logger).context("a tracing subscriber is already set")?;
        let args: Vec<String> = std::env::args().skip(1).collect();
        let Some(command) = args.first() else { bail!("{HELP}") };
        let arg = |i: usize| args.get(i).with_context(|| format!("missing argument {i}; see --help"));
        if command == "--help" || command == "-h" || command == "help" {
            print!("{HELP}");
            return Ok(());
        }
        if command == "sample" {
            return sample(arg(1)?, arg(2)?, args.get(3).map_or(Ok(22_000_000), |a| a.parse())?);
        }
        let db_dir = arg(1)?;
        let retention = flag_value(&args, "--retention")?.unwrap_or(AUTHORITY_RETENTION_BLOCKS);
        let max_delay = || flag_value::<f64>(&args, "--max-delay")?.context("--max-delay <seconds> is required");
        let interrupt = |exit| {
            interrupt(db_dir, retention, exit, max_delay()?, flag_value(&args, "--delay")?, flag(&args, "--tree-cache"))
        };
        match command.as_str() {
            "prune" | "compact-authorities" | "restart" => {
                let stop_after = flag_value(&args, "--stop-after-secs")?;
                run(db_dir, command, retention, stop_after, flag(&args, "--settle"), flag(&args, "--tree-cache"))
            }
            "exit-mid-slice" if flag(&args, "--stop-first") => interrupt(Mode::StopThenExit),
            "exit-mid-slice" => interrupt(Mode::Abrupt),
            "stop-latency" => interrupt(Mode::StopThenReturn),
            "fault-watch" => fault_watch(
                db_dir,
                retention,
                flag_value(&args, "--duration")?.context("--duration <seconds> is required")?,
                Duration::from_millis(flag_value(&args, "--probe-ms")?.unwrap_or(1000)),
                flag_value(&args, "--flush-every")?.unwrap_or(10),
            ),
            "build" => {
                let positional: Vec<&String> = args.iter().filter(|a| !a.starts_with("--")).collect();
                let old = positional.get(4).map(|a| Source::parse(a)).transpose()?;
                let split = positional.get(5).map_or(Ok(0), |a| a.parse())?;
                let (source, heights) = (Source::parse(arg(2)?)?, arg(3)?.parse()?);
                build(&Raw::open(db_dir)?, &source, heights, old.as_ref(), split, !flag(&args, "--no-seal"))
            }
            "extend" => extend(&Raw::open(db_dir)?, &Source::parse(arg(2)?)?, arg(3)?.parse()?),
            "seal" => {
                let raw = Raw::open(db_dir)?;
                raw.remove_tree_cache();
                seal(&raw)
            }
            "settle" => settle_db(&Raw::open(db_dir)?.db),
            "cert-pass" => {
                let kind =
                    |name: &str| flag_value::<String>(&args, name)?.map(|kind| CompactKind::parse(&kind)).transpose();
                let pass = PassArgs {
                    below: flag_value(&args, "--below")?.context("--below <height> is required")?,
                    mode: PassMode::parse(&flag_value::<String>(&args, "--mode")?.context("--mode is required")?)?,
                    cap: flag_value(&args, "--cap")?.unwrap_or(262_144),
                    threads: flag_value(&args, "--threads")?.unwrap_or(CERT_THREADS),
                    flush: flag(&args, "--flush"),
                    compact: kind("--compact")?,
                    then_open: flag(&args, "--then-open"),
                    bg_compact: kind("--bg-compact")?,
                    load: Load::parse(&flag_value::<String>(&args, "--load")?.unwrap_or("none".into()))?,
                    source: flag_value(&args, "--source")?,
                    retention,
                };
                cert_pass_command(db_dir, &pass)
            }
            "cert-state" => {
                let mode = storage_mode(db_dir);
                cert_state(&RocksDB::open(N::ID, mode.clone())?, &aleo_ledger_dir(N::ID, &mode), "now")
            }
            "slice-bench" => {
                let belows = flag_value::<String>(&args, "--belows")?.unwrap_or_default();
                let belows =
                    belows.split(',').filter(|b| !b.is_empty()).map(str::parse).collect::<Result<Vec<u32>, _>>()?;
                slice_bench(
                    db_dir,
                    &belows,
                    flag_value(&args, "--reps")?.unwrap_or(3),
                    flag_value(&args, "--big-keys")?.unwrap_or(0),
                    flag_value(&args, "--big-slices")?.unwrap_or(8),
                    flag_value(&args, "--big-below")?.unwrap_or(0),
                )
            }
            "fault-cert" => fault_cert(db_dir, &FaultArgs {
                below: flag_value(&args, "--below")?.context("--below <height> is required")?,
                kind: flag_value(&args, "--kind")?.context("--kind is required")?,
                fault_on: flag_value(&args, "--fault-on")?,
                fault_off: flag_value(&args, "--fault-off")?,
                stop_by_flush: flag(&args, "--stop-by-flush"),
                skip_force: flag(&args, "--skip-force"),
            }),
            "status" => status(&Raw::open(db_dir)?),
            other => bail!("unknown command {other}; see --help"),
        }
    }
}
