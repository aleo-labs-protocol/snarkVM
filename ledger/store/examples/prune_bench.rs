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
        sync::{Condvar, Mutex, OnceLock},
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
    }

    static EVENTS: OnceLock<Events> = OnceLock::new();

    fn events() -> &'static Events {
        EVENTS.get_or_init(|| Events { start: Instant::now(), compaction: Default::default(), changed: Condvar::new() })
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

        fn update(&self, message: &str) {
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

    fn authority_prefix() -> [u8; PREFIX_LEN] {
        let mut prefix = [0u8; PREFIX_LEN];
        prefix[..2].copy_from_slice(&N::ID.to_le_bytes());
        prefix[2..].copy_from_slice(&u16::from(MapID::Block(BlockMap::Authority)).to_le_bytes());
        prefix
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
        let mut bytes = [0u8; 32];
        let mut batch = rocksdb::WriteBatch::default();
        let (timer, mut authority_bytes, mut certs) = (Instant::now(), 0u64, 0u64);
        for height in heights.clone() {
            random_key(&mut rng, &mut bytes);
            let hash: <N as Network>::BlockHash = Field::<N>::from_bytes_le(&bytes)?.into();
            let (authority, cert_count) = if height < split { old } else { recent }.authority(height, &mut rng);
            batch.put(raw_key(BlockMap::ID, &height)?, bincode::serialize(&hash)?);
            batch.put(raw_key(BlockMap::ReverseID, &hash)?, bincode::serialize(&height)?);
            authority_bytes += authority.len() as u64;
            batch.put(raw_key(BlockMap::Authority, &hash)?, authority);
            if height > 0 {
                for i in 0..cert_count {
                    random_key(&mut rng, &mut bytes);
                    let id = Field::<N>::from_bytes_le(&bytes)?;
                    let index = (height, u64::from(height) * 2 + u64::from(i % 2));
                    batch.put(raw_key(BlockMap::Certificate, &id)?, bincode::serialize(&index)?);
                    certs += 1;
                }
            }
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
            "status" => status(&Raw::open(db_dir)?),
            other => bail!("unknown command {other}; see --help"),
        }
    }
}
