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

use snarkvm_console::prelude::*;
use snarkvm_ledger::{
    Block,
    store::{
        BlockStorage,
        helpers::{memory::BlockMemory, rocksdb::BlockDB},
    },
};
use snarkvm_utilities::PrettyUnwrap;

use criterion::{BenchmarkGroup, Criterion, criterion_group, criterion_main, measurement::WallTime};
use rand::seq::IndexedRandom;
use std::time::Instant;

mod common;
use common::{CurrentNetwork, create_storage, initialize_logging, load_blocks};

/// Runs the benchmark for the given implementation of `BlockStorage`.
fn bench_block_store<S: BlockStorage<CurrentNetwork>>(
    name: &str,
    group: &mut BenchmarkGroup<WallTime>,
    genesis_block: &Block<CurrentNetwork>,
    blocks: &[Block<CurrentNetwork>],
) {
    let rng = &mut TestRng::default();

    group.bench_function(format!("{name}::insert"), |b| {
        b.iter_custom(|num_inserts| {
            let num_inserts = num_inserts as usize;
            let store = create_storage::<S>(genesis_block);

            assert!(num_inserts < blocks.len());

            let start = Instant::now();
            for block in &blocks[..num_inserts] {
                store
                    .insert(block)
                    .map_err(|err| err.context(format!("Failed to insert block at height {}", block.height())))
                    .pretty_unwrap();
            }

            start.elapsed()
        })
    });

    group.bench_function(format!("{name}::get_block"), |b| {
        let hashes: Vec<_> = blocks.iter().map(|b| b.hash()).collect();

        b.iter_custom(|num_gets| {
            let store = create_storage::<S>(genesis_block);

            for block in blocks {
                store
                    .insert(block)
                    .map_err(|err| err.context(format!("Failed to insert block at height {}", block.height())))
                    .pretty_unwrap();
            }

            let start = Instant::now();
            for _ in 0..num_gets {
                let hash = hashes.choose(rng).unwrap();
                let _ = store.get_block(hash).unwrap();
            }

            start.elapsed()
        })
    });

    group.bench_function(format!("{name}::get_block_height"), |b| {
        let hashes: Vec<_> = blocks.iter().map(|b| b.hash()).collect();

        b.iter_custom(|num_gets| {
            let store = create_storage::<S>(genesis_block);

            for block in blocks {
                if let Err(err) = store.insert(block) {
                    panic!("Failed to insert block at height {}: {err}", block.height());
                }
            }

            let start = Instant::now();
            for _ in 0..num_gets {
                let hash = hashes.choose(rng).unwrap();
                let _ = store.get_block_height(hash).unwrap();
            }

            start.elapsed()
        })
    });
}

fn block_store(c: &mut Criterion) {
    initialize_logging();

    let (genesis_block, blocks) = load_blocks("test-ledger").pretty_expect("Failed to load blocks from disk");

    let mut group = c.benchmark_group("block_store");
    group.sample_size(10);

    bench_block_store::<BlockMemory<CurrentNetwork>>("BlockMemory", &mut group, &genesis_block, &blocks);
    bench_block_store::<BlockDB<CurrentNetwork>>("BlockDB", &mut group, &genesis_block, &blocks);

    group.finish();
}

criterion_group!(benches, block_store);
criterion_main!(benches);
