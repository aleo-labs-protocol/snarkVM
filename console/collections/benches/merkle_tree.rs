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

#[macro_use]
extern crate criterion;

use snarkvm_console_algorithms::{BHP512, BHP1024};
use snarkvm_console_collections::merkle_tree::{MerkleTree, MerkleTreeState, PathHash};
use snarkvm_console_network::{
    BHP_512,
    BHP_1024,
    BHPMerkleTree,
    MainnetV0,
    Network,
    prelude::{Rng, TestRng, ToBits, Uniform, Zero},
};
use snarkvm_console_types::Field;

use criterion::{BatchSize, BenchmarkId, Criterion};
use std::{collections::BTreeMap, time::Duration};

const DEPTH: u8 = 32;
const MAX_INSTANTIATED_DEPTH: u8 = 8;

const NUM_LEAVES: &[usize] = &[1, 100];
const APPEND_SIZES: &[usize] = &[1, 100];
const UPDATE_SIZES: &[usize] = &[1, 100];

/// The tree sizes used by the `MerkleTreeState` benchmarks; these reach further
/// than `NUM_LEAVES`, as caching a tree is most interesting for large trees.
const STATE_NUM_LEAVES: &[usize] = &[1, 100, 10_000, 1_000_000];

/// Generates the specified number of random Merkle tree leaves.
macro_rules! generate_leaves {
    ($num_leaves:expr, $rng:expr) => {{ (0..$num_leaves).map(|_| Field::<MainnetV0>::rand($rng).to_bits_le()).collect::<Vec<_>>() }};
}

fn new(c: &mut Criterion) {
    let mut rng = TestRng::default();
    // Accumulate leaves in a vector to avoid recomputing across iterations.
    let leaves = generate_leaves!(*NUM_LEAVES.last().unwrap(), &mut rng);
    for num_leaves in NUM_LEAVES {
        // Benchmark the creation of a Merkle tree with the specified number of leaves.
        c.bench_function(&format!("MerkleTree/new/{num_leaves}"), |b| {
            b.iter(|| {
                let _tree = MainnetV0::merkle_tree_bhp::<DEPTH>(&leaves[0..*num_leaves]).unwrap();
            })
        });
    }
}

/// Constructing the shallow trees a block is made of: the header tree (`HEADER_DEPTH`,
/// 3), a transaction's and a transition's (`TRANSACTION_DEPTH` and `TRANSITION_DEPTH`,
/// both 5), and the transactions tree (`TRANSACTIONS_DEPTH`, 20).
///
/// [`new`] above is at `BLOCKS_DEPTH`, where a 32-hash padding chain dominates and hides
/// everything else. These are the shapes a node builds per block, and the shapes in which
/// the one `PathHash::hash_empty` every tree needs is worth measuring.
fn new_block_tree_shapes(c: &mut Criterion) {
    let mut rng = TestRng::default();
    let leaves = generate_leaves!(16, &mut rng);
    macro_rules! shape {
        ($depth:expr, $num_leaves:expr) => {
            c.bench_function(&format!("MerkleTree/new/depth{}/{}", $depth, $num_leaves), |b| {
                b.iter(|| {
                    MerkleTree::<MainnetV0, _, _, $depth>::new(&*BHP_1024, &*BHP_512, &leaves[..$num_leaves]).unwrap()
                })
            });
        };
    }
    shape!(3, 8);
    shape!(5, 2);
    shape!(5, 4);
    shape!(5, 16);
    shape!(20, 1);
    shape!(20, 8);
}

/// The empty hash, which every tree construction needs: `hash_empty` is the read of the
/// value the path hasher remembers, `hash_children` the work that read skips.
fn empty_hash(c: &mut Criterion) {
    c.bench_function("MerkleTree/hash_empty", |b| b.iter(|| PathHash::hash_empty(&*BHP_512).unwrap()));

    let zero = Field::<MainnetV0>::zero();
    c.bench_function("MerkleTree/hash_children/zeros", |b| {
        b.iter(|| PathHash::hash_children(&*BHP_512, &zero, &zero).unwrap())
    });
}

fn append(c: &mut Criterion) {
    let mut rng = TestRng::default();
    // Accumulate all leaves in a vector to avoid recomputing across iterations.
    let leaves = generate_leaves!(*NUM_LEAVES.last().unwrap(), &mut rng);
    // Generate all of the leaves that will be appended to the tree.
    let new_leaves = generate_leaves!(*APPEND_SIZES.last().unwrap(), &mut rng);
    // For each number of leaves to append, benchmark the append operation.
    for num_leaves in NUM_LEAVES {
        for num_new_leaves in APPEND_SIZES {
            // Construct a Merkle tree with the specified number of leaves.
            let merkle_tree = MainnetV0::merkle_tree_bhp::<DEPTH>(&leaves[..*num_leaves]).unwrap();
            c.bench_function(&format!("MerkleTree/append/{num_leaves}/{num_new_leaves}"), |b| {
                b.iter_batched(
                    || merkle_tree.clone(),
                    |mut merkle_tree| {
                        merkle_tree.append(&new_leaves[..*num_new_leaves]).unwrap();
                    },
                    BatchSize::SmallInput,
                )
            });
        }
    }
}

fn update(c: &mut Criterion) {
    let mut rng = TestRng::default();
    // Accumulate leaves in a vector to avoid recomputing across iterations.
    let leaves = generate_leaves!(*NUM_LEAVES.last().unwrap(), &mut rng);
    // For each number of leaves to update, benchmark the update operation.
    for num_leaves in NUM_LEAVES {
        // Construct a vector of (index, new_leaf) pairs to update the tree with.
        // Note that we need to bound the number of updates since a large number of sequential singular updates to exceedingly long.
        let updates = generate_leaves!(std::cmp::min(*UPDATE_SIZES.last().unwrap(), 10_000), &mut rng)
            .into_iter()
            .map(|leaf| {
                let index = rng.random_range(0..*num_leaves);
                (index, leaf)
            })
            .collect::<Vec<_>>();

        for num_new_leaves in UPDATE_SIZES {
            // Construct a Merkle tree with the specified number of leaves.
            let merkle_tree = MainnetV0::merkle_tree_bhp::<DEPTH>(&leaves[..*num_leaves]).unwrap();

            c.bench_function(&format!("MerkleTree/update/{num_leaves}/{num_new_leaves}"), |b| {
                b.iter_batched(
                    || merkle_tree.clone(),
                    |mut merkle_tree| {
                        for (index, new_leaf) in updates.iter().take(*num_new_leaves) {
                            merkle_tree.update(*index, new_leaf).unwrap();
                        }
                    },
                    BatchSize::SmallInput,
                )
            });
        }
    }
}

fn update_many(c: &mut Criterion) {
    let mut rng = TestRng::default();
    // Accumulate leaves in a vector to avoid recomputing across iterations.
    let leaves = generate_leaves!(*NUM_LEAVES.last().unwrap(), &mut rng);
    // For each number of leaves to update, benchmark the update operation.
    for num_leaves in NUM_LEAVES {
        // Generate all of the updates that will be applied to the tree.
        // Note that we generate 2 * MAX_UPDATE_SIZE leaves to increase the number of unique of updates.
        let mut updates = generate_leaves!(2 * *UPDATE_SIZES.last().unwrap(), &mut rng)
            .into_iter()
            .map(|leaf| {
                let index = rng.random_range(0..*num_leaves);
                (index, leaf)
            })
            .collect::<Vec<_>>();
        updates.sort_by_key(|(a, _)| *a);
        updates.reverse();
        updates.dedup_by_key(|(a, _)| *a);

        for num_new_leaves in UPDATE_SIZES {
            // Construct a Merkle tree with the specified number of leaves.
            let merkle_tree = MainnetV0::merkle_tree_bhp::<DEPTH>(&leaves[..*num_leaves]).unwrap();
            let num_new_leaves = std::cmp::min(*num_new_leaves, updates.len());
            let updates = BTreeMap::from_iter(updates[..num_new_leaves].iter().cloned());
            c.bench_function(&format!("MerkleTree/update_many/{num_leaves}/{num_new_leaves}",), |b| {
                b.iter_batched(
                    || merkle_tree.clone(),
                    |mut merkle_tree| {
                        merkle_tree.update_many(&updates).unwrap();
                    },
                    BatchSize::SmallInput,
                )
            });
        }
    }
}

fn update_vs_update_many(c: &mut Criterion) {
    let mut group = c.benchmark_group("UpdateVSUpdateMany");
    let mut rng = TestRng::default();
    // Accumulate leaves in a vector to avoid recomputing across iterations.
    let max_leaves = 2usize.saturating_pow(MAX_INSTANTIATED_DEPTH as u32);
    let leaves = generate_leaves!(max_leaves, &mut rng);
    for depth in 1..=MAX_INSTANTIATED_DEPTH {
        // Compute the number of leaves at this depth.
        let num_leaves = 2usize.saturating_pow(depth as u32);
        // Construct a Merkle tree with the specified number of leaves.
        let tree = MainnetV0::merkle_tree_bhp::<DEPTH>(&leaves[..num_leaves]).unwrap();
        // Generate a new leaf and select a random index to update.
        let index = rng.random_range(0..num_leaves);
        let new_leaf = generate_leaves!(1, &mut rng).pop().unwrap();
        // Benchmark the standard update operation.
        group.bench_with_input(BenchmarkId::new("Single", format!("{depth}")), &new_leaf, |b, new_leaf| {
            b.iter_batched(|| tree.clone(), |mut tree| tree.update(index, new_leaf), BatchSize::SmallInput)
        });
        // Benchmark the `update_many` operation.
        group.bench_with_input(
            BenchmarkId::new("Batch", format!("{depth}")),
            &BTreeMap::from([(index, new_leaf)]),
            |b, updates| b.iter_batched(|| tree.clone(), |mut tree| tree.update_many(updates), BatchSize::SmallInput),
        );
    }
}

/// A Merkle tree as it was cached before [`MerkleTreeState`] was introduced, i.e. the
/// whole tree, hashers included.
///
/// Note: `bincode` encodes a tuple and a struct identically - as the concatenation of
/// their fields - so this decodes the legacy payload byte for byte.
type LegacyCachedTree<'a> = (BHP1024<MainnetV0>, BHP512<MainnetV0>, MerkleTreeState<'a, MainnetV0>);

/// Produces the payload that caching the given tree used to write, for comparison.
fn legacy_payload(merkle_tree: &BHPMerkleTree<MainnetV0, DEPTH>) -> Vec<u8> {
    bincode::serialize(&(&*BHP_1024, &*BHP_512, merkle_tree.to_state())).unwrap()
}

/// Compares recreating a Merkle tree from a cached [`MerkleTreeState`] against
/// constructing the same tree from scratch, across a range of tree sizes.
///
/// Run with `cargo bench --bench merkle_tree -- MerkleTreeState`.
fn state(c: &mut Criterion) {
    let mut group = c.benchmark_group("MerkleTreeState");
    let mut rng = TestRng::default();
    // Accumulate leaves in a vector to avoid recomputing across iterations.
    let leaves = generate_leaves!(*STATE_NUM_LEAVES.last().unwrap(), &mut rng);

    for num_leaves in STATE_NUM_LEAVES {
        // Construct a Merkle tree with the specified number of leaves, and cache its state.
        let merkle_tree = MainnetV0::merkle_tree_bhp::<DEPTH>(&leaves[..*num_leaves]).unwrap();
        let cached = bincode::serialize(&merkle_tree.to_state()).unwrap();
        // Report the size of the cached payload against that of the legacy one; the former
        // should be proportional to the tree, i.e. it must not contain the hashers.
        println!(
            "MerkleTreeState/{num_leaves} leaves: {} bytes cached ({} bytes in the legacy format)",
            cached.len(),
            legacy_payload(&merkle_tree).len()
        );

        // For reference: constructing the tree from scratch, i.e. not using a cache at all.
        group.bench_with_input(BenchmarkId::new("from_scratch", num_leaves), num_leaves, |b, num_leaves| {
            b.iter(|| MainnetV0::merkle_tree_bhp::<DEPTH>(&leaves[..*num_leaves]).unwrap())
        });
        // Serializing the state of the tree, i.e. the cost of writing the cache.
        group.bench_with_input(BenchmarkId::new("serialize", num_leaves), &merkle_tree, |b, merkle_tree| {
            b.iter(|| bincode::serialize(&merkle_tree.to_state()).unwrap())
        });
        // Deserializing the state, i.e. the decoding half of the cost of reading the cache.
        group.bench_with_input(BenchmarkId::new("deserialize", num_leaves), &cached, |b, cached| {
            b.iter(|| bincode::deserialize::<MerkleTreeState<'_, MainnetV0>>(cached).unwrap())
        });
        // Recreating the tree from a deserialized state, i.e. the validating half.
        group.bench_with_input(BenchmarkId::new("from_state", num_leaves), &cached, |b, cached| {
            b.iter_batched(
                || bincode::deserialize::<MerkleTreeState<'_, MainnetV0>>(cached).unwrap(),
                |state| MainnetV0::merkle_tree_bhp_from_state::<DEPTH>(state).unwrap(),
                BatchSize::LargeInput,
            )
        });
        // Both halves together, i.e. what a node pays to load a cached tree.
        group.bench_with_input(BenchmarkId::new("deserialize_and_recreate", num_leaves), &cached, |b, cached| {
            b.iter(|| {
                let state = bincode::deserialize::<MerkleTreeState<'_, MainnetV0>>(cached).unwrap();
                MainnetV0::merkle_tree_bhp_from_state::<DEPTH>(state).unwrap()
            })
        });
    }

    group.finish();
}

/// Measures loading a tree from a legacy cache payload, i.e. one that carries the hashers.
///
/// This is kept apart from [`state`] because a single iteration takes tens of seconds: the
/// hashers hold hundreds of thousands of group elements, and deserializing each one costs a
/// subgroup check, i.e. a full scalar multiplication. That cost is also invariant in the
/// size of the tree, which is why this is measured for a single tree size only.
///
/// Run with `cargo bench --bench merkle_tree -- LegacyMerkleTreeCache` (slow).
fn legacy_state(c: &mut Criterion) {
    let mut group = c.benchmark_group("LegacyMerkleTreeCache");
    let mut rng = TestRng::default();

    let num_leaves = STATE_NUM_LEAVES[0];
    let leaves = generate_leaves!(num_leaves, &mut rng);
    let merkle_tree = MainnetV0::merkle_tree_bhp::<DEPTH>(&leaves).unwrap();
    let legacy = legacy_payload(&merkle_tree);
    println!("LegacyMerkleTreeCache/{num_leaves} leaves: {} bytes cached", legacy.len());

    group.bench_with_input(BenchmarkId::new("deserialize", num_leaves), &legacy, |b, legacy| {
        b.iter(|| bincode::deserialize::<LegacyCachedTree<'_>>(legacy).unwrap())
    });

    group.finish();
}

criterion_group! {
    name = merkle_tree;
    config = Criterion::default().sample_size(10);
    targets = new, new_block_tree_shapes, empty_hash, append, update, update_many, update_vs_update_many
}
criterion_group! {
    name = merkle_tree_state;
    config = Criterion::default().sample_size(10).warm_up_time(Duration::from_secs(1));
    targets = state
}
criterion_group! {
    name = legacy_merkle_tree_cache;
    config = Criterion::default().sample_size(10).warm_up_time(Duration::from_secs(1));
    targets = legacy_state
}
// MerkleTreeState and LegacyMerkleTreeCache are opt-in: they include multi-million-leaf
// trees and legacy hasher deserialization that each take minutes per sample.
// Run with: cargo bench --bench merkle_tree -- MerkleTreeState
// Run with: cargo bench --bench merkle_tree -- LegacyMerkleTreeCache
criterion_main!(merkle_tree);
