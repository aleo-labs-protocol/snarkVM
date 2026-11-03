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

use snarkvm_console_algorithms::{BHP512, BHP1024};
use snarkvm_console_types::prelude::*;

use crate::merkle_tree::{MerkleTree, print_merkle_tree};

type CurrentEnvironment = Console;
type LH = BHP1024<CurrentEnvironment>;
type PH = BHP512<CurrentEnvironment>;

#[test]
fn test_print_merkle_tree() {
    let mut rng = TestRng::default();

    let leaf_hasher = LH::setup("PrintTestLH").unwrap();
    let path_hasher = PH::setup("PrintTestPH").unwrap();

    // Case 1: DEPTH 1, 1 leaf
    let num_leaves = 1;

    let leaves = (0..num_leaves).map(|_| Field::<CurrentEnvironment>::rand(&mut rng).to_bits_le()).collect::<Vec<_>>();
    let merkle_tree = MerkleTree::<CurrentEnvironment, LH, PH, 1>::new(&leaf_hasher, &path_hasher, &leaves).unwrap();

    println!("\nCase 1: DEPTH 1, 1 leaf (root: {:?})\n", merkle_tree.root());
    print_merkle_tree(&merkle_tree, &path_hasher, 4).unwrap();

    // Case 2: Depth 8, all possible leaf numbers between 0 and 8

    println!("\nCase 2: DEPTH 3");

    for num_leaves in 1..=8 {
        let leaves =
            (0..num_leaves).map(|_| Field::<CurrentEnvironment>::rand(&mut rng).to_bits_le()).collect::<Vec<_>>();
        let merkle_tree =
            MerkleTree::<CurrentEnvironment, LH, PH, 3>::new(&leaf_hasher, &path_hasher, &leaves).unwrap();

        println!(
            "\n----Case 2.{}: {} {} (root: {:?})\n",
            num_leaves,
            num_leaves,
            if num_leaves != 1 { "leaves" } else { "leaf" },
            merkle_tree.root()
        );

        print_merkle_tree(&merkle_tree, &path_hasher, 5).unwrap();
    }

    // Case 3: Depth 4, 8 leaves
    let num_leaves = 8;

    let leaves = (0..num_leaves).map(|_| Field::<CurrentEnvironment>::rand(&mut rng).to_bits_le()).collect::<Vec<_>>();
    let merkle_tree = MerkleTree::<CurrentEnvironment, LH, PH, 4>::new(&leaf_hasher, &path_hasher, &leaves).unwrap();

    println!("\nCase 3: DEPTH 4, 8 leaves (root: {:?})\n", merkle_tree.root());
    print_merkle_tree(&merkle_tree, &path_hasher, 3).unwrap();

    // Case 4: Depth 4, 9 leaves.
    let num_leaves = 9;

    let leaves = (0..num_leaves).map(|_| Field::<CurrentEnvironment>::rand(&mut rng).to_bits_le()).collect::<Vec<_>>();
    let merkle_tree = MerkleTree::<CurrentEnvironment, LH, PH, 4>::new(&leaf_hasher, &path_hasher, &leaves).unwrap();

    println!("\nCase 4: DEPTH 4, 9 leaves (root: {:?})\n", merkle_tree.root());
    print_merkle_tree(&merkle_tree, &path_hasher, 3).unwrap();

    // Case 5: Depth 10, 17 leaves.
    let num_leaves = 17;

    let leaves = (0..num_leaves).map(|_| Field::<CurrentEnvironment>::rand(&mut rng).to_bits_le()).collect::<Vec<_>>();
    let merkle_tree = MerkleTree::<CurrentEnvironment, LH, PH, 10>::new(&leaf_hasher, &path_hasher, &leaves).unwrap();

    println!("\nCase 5: DEPTH 10, 17 leaves (root: {:?})\n", merkle_tree.root());
    print_merkle_tree(&merkle_tree, &path_hasher, 1).unwrap();

    println!();
}
