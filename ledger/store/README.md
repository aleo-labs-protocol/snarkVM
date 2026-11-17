# snarkvm-ledger-store

[![Crates.io](https://img.shields.io/crates/v/snarkvm-ledger-store.svg?color=neon)](https://crates.io/crates/snarkvm-ledger-store)
[![Authors](https://img.shields.io/badge/authors-Aleo-orange.svg)](https://aleo.org)
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](./LICENSE.md)

The `snarkvm-ledger-store` crate provides the data store for the ledger.

There are currently 2 implementations: a persistent one based on RocksDB, and an in-memory one. The
in-memory one is the default, while the `"rocks"` feature utilizes RocksDB instead.

### General assumptions

The following is a list of assumptions related to the way the Aleo storage is typically used,
which influenced the database choice and configuration, some of the APIs, and overall design
decisions:
- The storage needs to be usable both in a persistent and ephemeral (in-memory) way, the latter of
which may not assume the existence of a filesystem (excluding a “persistent” storage residing in
`/tmp`)
- The high-level API needs to be consistent across the storage implementations
- Many concurrent reads are expected at any point in time, with only few composite writes related
to block insertions

### Storage properties

Due to RocksDB being the primary implementation of persistent storage used by snarkOS, some of its
design specifics have impacted the overall design of the storage APIs and objects. These include:
- The data is stored as key-value pairs
- The entries are ordered lexicographically (automatic in RocksDB); this is sometimes taken
advantage of when iterating over multiple records
- Operations may be performed individually, or as part of atomic batches
- In order for multiple entries to be inserted atomically, the high-level operations are organized
into batches

### Main features shared between implementations

The primary means of accessing the storage are the `Map` and `NestedMap` traits, plus their
`(Nested)MapRead` counterparts, which provide read-only functionalities.

The basic concept behind the `Map` is that it relates to key-value pairs, like in a hash map.
The RocksDB-applicable object is the `(Nested)DataMap`, and the in-memory one is the
`(Nested)MemoryMap`.

The nested maps work like a double map - keys and values inserted into storage not just
individually, but also within the context of some grouping key `M`; removing it (via
`NestedMap::remove_map`) removes all the grouped entries.

Each `*Map` object contains the following members which work basically the same:
- `batch_in_progress` - an indicator of whether the map is currently involved in an atomic batch
operation
- `atomic_batch` - the contents of the current atomic batch operation (useful in case any of them
need to be looked up during that operation; a `None` value indicates a deletion, while `Some` - an
insertion
- `checkpoints` - a list of indices demarcating potential meaningful subsets of the atomic batch
operation, allowing the rolling back of a partial pending operation

The storage is divided into several logical units (e.g. `BlockStorage`) which may contain several
`*Map` members.

### Main differences between implementations

All RocksDB-backed objects (`(Nested)DataMap`s) share a single underlying instance of RocksDB
containing all the data, while the data in the in-memory storage is chunked across all the
`(Nested)MemoryMap`s, each containing only its relevant entries.

The persistent storage, which needs stricter atomicity guarantees than the in-memory one, has a
feature which allows the atomic writes to be paused (`pause_atomic_writes`). When called, it
causes the storage write operations to not automatically result in physical writes, instead
accumulating any further writes and extending any ongoing write batch with them. This ends upon a
call to `unpause_atomic_writes`, which executes all the accumulated writes as a single atomic
operation.

Every `(Nested)DataMap` is associated with a `DataID` enum, which constitutes a part of a binary
prefix that gets prepended to the keys when they are written to the database. This allows us to
have the same key used for different storage entries without resulting in duplicates (e.g. having
a single block hash corresponding to both a height, and list of transaction IDs).

The `Network` identifier (`Network::ID`) paired with the `DataID` comprises the context member of
each `(Nested)DataMap`, which is also the aforementioned binary prefix of RocksDB keys.

The `StorageMode` is of little interest to the in-memory storage, as its primary use is to decide
where to store storage-related files (or where to load them from).

There is a `static DATABASES` which is used with RocksDB, but it is only meaningful in tests
involving persistent storage - it ensures that all instances are completely unrelated during
concurrent tests.

### Macros

`atomic_batch_scope`: this macro serves as a wrapper for multiple low-level storage operations,
which causes them to be executed as a single atomic batch. Note that each consecutive time it is
called, a new atomic checkpoint is created, but `start_atomic` is called only once. It is
restricted to a single logical unit of storage (e.g. `BlockStorage`), which separates it from the
later workaround that is `(un)pause_atomic_writes` (which was introduced specifically so that a
single atomic operation could be performed both on `BlockStorage` and `FinalizeStorage`).

`atomic_finalize`: this was added in order to facilitate different modes of finalization,
specifically to not perform any actual writes in the `DryRun` mode. Other than that, it behaves
like `atomic_batch_scope`, with the exception that it may not be nested.

### Basic atomic batch happy path for RocksDB

**Phase 1 (setup)**:
1. `start_atomic` is called, typically from `atomic_batch_scope` or a top-level operation on one
of the logical storage units (`*Storage` trait implementors).
2. `batch_in_progress` is set to true in all the maps involved.
3. Each map triggering `start_atomic causes` the `atomic_depth` counter to be incremented; it is
the most foolproof way to check whether there is any active atomic batch started in any logical
storage unit, which is why `pause_atomic_writes` uses it internally.
4. The contents of the per-map `atomic_batch` are checked - they must be empty at this stage
(logic check).
5. The contents of the database-wide `atomic_batch` are checked - they too must be empty, unless
we’ve paused atomic writes (which will cause the per-map collections to be moved to the
per-database one, but ultimately not remove the latter).

**Phase 2 (batching)**:
1. A number of read and write operations are performed in the associated maps. Any writes are
collected in the per-map `atomic_batch` collections.
2. If any nested operations are performed via the `atomic_batch_scope` macro, `atomic_checkpoint`
will be called instead of `start_atomic`, demarcating the end of a meaningful subset of the entire
batch operation.
3. After each nested operation is executed (queued for writing) successfully,
`clear_latest_checkpoint` is called, as there is no more potential need to roll it back.

**Phase 3 (execution)**:
1. `finish_atomic` is called either directly, or once `atomic_batch_scope` detects that it’s the
end of its scope (i.e. all the lower-level operations have already been called `finish_atomic`
internally, leaving only the final `atomic_depth` value of `1` coming from the macro).
2. All the pending per-map operations are serialized, and moved to the database-wide (under the
`RocksDB` object) `atomic_batch` collection.
3. The (per-map) `checkpoints` are cleared, as they are no longer useful.
4. The (per-map) `batch_in_progress` flag is set to `false`.
5. The (database-wide) `atomic_depth` decreases by `1` for each map involved in the batch
operation.
6. The previous `atomic_depth` is checked - it may not be `0`, as it would indicate that a
`start_atomic` call was not paired with one to `finish_atomic`.
7. If `pause_atomic_writes` is not in force, and it’s the final (outermost) call to
`finish_atomic`, the database-wide `atomic_batch` is cleared from entries, which are executed by
RocksDB atomically.

### The sequential processing thread

While the atomicity of storage write operations is enforced by the storage itself, some of the
operations (currently `VM::{atomic_speculate, add_next_block}`) that involve them may not be
invoked concurrently. In order to avoid this, the `VM` object spawns a persistent background thread
(introduced in [#2975](https://github.com/ProvableHQ/snarkVM/pull/2975)) dedicated to collecting
(via an `mpsc` channel) and sequentially processing them.

### Storage modes

One of the fundamental parameters associated with the storage is the `StorageMode`, defined in
`snarkvm-utilities` and re-exported by this crate. It is primarily used to determine where the
persistent storage is stored on the disk (via `aleo_ledger_dir`).

The `StorageMode::Test`, dedicated to testing, should be created via `StorageMode::new_test`,
unless only a single `DataMap` is used, in which case it can also be constructed manually.
