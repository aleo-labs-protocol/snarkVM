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

use snarkvm_console_algorithms::Environment;
use snarkvm_console_types::Field;

use crate::merkle_tree::{LeafHash, MerkleTree, PathHash};

use snarkvm_console_types::prelude::*;

/// Prints the Merkle tree level by level. Each left child is displayed
/// immediately below its parent, followed by a number of spaces and its
/// sibling. This function is intended for testing/debugging purposes.
///
/// Each node (including leaves) is truncated to a number of its
/// least-significant digits controlled by the `node_width` argument.
///
/// Nodes whose value is the empty hash are displayed as `e`. Nodes whose value
/// is `hash(empty hash, empty hash)` are displayed as `E`. Virtual leaves used
/// to pad the lowest level, which are not stored in the tree but considered to
/// have the value of the empty hash, are displayed as a sequence of `*`
/// characters.
///
/// Fully padded subtrees (that is, right subtrees replaced by the empty hash)
/// are represented by the string ` \ e` next to their parent.
///
/// Arguments:
/// - `merkle_tree`: The Merkle tree to print.
/// - `path_hasher`: The path hasher, used to compute the value of the empty
///   hash and the hash of two empty hashes.
/// - `node_width`: The number of characters used to display each node. It must
///   be at least 1.
pub fn print_merkle_tree<
    N: Environment,
    LH: LeafHash<Hash = PH::Hash>,
    PH: PathHash<Hash = Field<N>>,
    const DEPTH: u8,
>(
    merkle_tree: &MerkleTree<N, LH, PH, DEPTH>,
    path_hasher: &PH,
    node_width: usize,
) -> Result<()> {
    let empty_hash = path_hasher.hash_empty()?;
    let empty_hash_hash = path_hasher.hash_children(&empty_hash, &empty_hash)?;
    let empty_hash_str = format!("| {:<node_width$}", "e");
    let empty_hash_hash_str = format!("| {:<node_width$}", "E");
    let padding_leaf_str = format!("| {:<node_width$}", "*".repeat(node_width));

    // For depth > 9, three characters are allotted for the level number to
    // accommodate two-digit depth labels; otherwise two characters suffice.
    let level_width = if DEPTH > 9 { 3 } else { 2 };

    ensure!(node_width >= 1, "node_width must be at least 1");

    // Anonymous auxiliary function to format a node.
    let node_string = |element: Field<N>| {
        if element == empty_hash {
            empty_hash_str.clone()
        } else if element == empty_hash_hash {
            empty_hash_hash_str.clone()
        } else {
            let element_str = &element.to_string();
            // Drop the `field` tag from the element's representation and
            // take the last node_width_characters (or as many as available)
            let least_significant: Vec<char> = element_str.chars().rev().take(node_width + 5).collect();
            let trimmed: String = least_significant.into_iter().skip(5).rev().collect();
            format!("| {trimmed:<node_width$}")
        }
    };

    let tree = merkle_tree.tree();
    let num_leaves = merkle_tree.number_of_leaves();
    let num_inner_nodes = tree.len() - num_leaves;

    ensure!(num_leaves > 0, "Cannot print a Merkle tree with no leaves");

    // If a (single) leaf was used to pad the last level, the number of inner
    // nodes needs to account for it.
    let num_original_inner_nodes = if num_leaves == 1 { 0 } else { num_inner_nodes - (num_leaves % 2) };

    let num_inner_levels = (num_original_inner_nodes + 1).ilog2();

    // Phase 1: Print the padded levels
    let num_padded_levels = DEPTH as u32 - num_inner_levels;

    let padded_roots = std::iter::successors(Some(tree[0]), |&root| path_hasher.hash_children(&root, &empty_hash).ok())
        .take(num_padded_levels as usize + 1)
        .skip(1)
        .collect_vec();

    for (level, root) in padded_roots.into_iter().rev().enumerate() {
        println!("Level {:<level_width$} {} \\ e", format!("{level}:"), node_string(root));
    }

    // Phase 2: Print the unpadded subtree

    let hdiv = format!(
        "{}{}",
        " ".repeat(level_width + "Level :".len()),
        "-".repeat(num_leaves.next_power_of_two() * (node_width + 3))
    );

    if num_leaves == 1 {
        println!("{}", &hdiv);
        println!("Level {:<level_width$} {}", format!("{num_padded_levels}:"), node_string(tree[0]));
        return Ok(());
    }

    println!("{}", &hdiv);
    println!("Level {:<level_width$} {}", format!("{num_padded_levels}:"), node_string(tree[0]));

    let mut start = 1;
    let mut end = 3;

    // The spacing is computed so that the leaf level is reached with spacing = 1
    let mut spacing = 2_usize.pow(num_inner_levels - 1) * (node_width + 3) - node_width - 2;

    for level in num_padded_levels + 1..num_padded_levels + num_inner_levels {
        println!("{}", &hdiv);
        print!("Level {:<level_width$} ", format!("{level}:"));
        let separator = " ".repeat(spacing);

        println!("{}", &tree[start..end].iter().map(|node| node_string(*node)).join(&separator));

        start = end;
        end = 2 * end + 1;

        spacing = (spacing - node_width - 2) / 2;
    }

    print!(
        "Level {:<level_width$} {}",
        format!("{}:", num_padded_levels + num_inner_levels),
        tree[num_original_inner_nodes..].iter().map(|node| node_string(*node)).join(" ")
    );

    // Print the (virtual) padding leaves
    for _ in 0..num_leaves.next_power_of_two() - num_leaves - (num_leaves % 2) {
        print!(" {padding_leaf_str}");
    }

    println!();

    Ok(())
}
