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

use snarkvm_console_algorithms::{bhp::hasher::BHPHasher, *};
use snarkvm_console_types::environment::Console;
use snarkvm_utilities::ToBytes;

/// The number of bits in a BHP chunk.
const BHP_CHUNK_SIZE: usize = 3;

/// Returns the deterministic input of the given length.
/// This must match `bits` in `src/bhp/hasher/tests.rs`.
fn bits(len: usize) -> Vec<bool> {
    let mut rng = TestRng::from_seed(1012147);
    (0..len).map(|_| bool::rand(&mut rng)).collect()
}

/// Returns the input lengths to hash.
/// This must match `representative_lengths` in `src/bhp/hasher/tests.rs`.
fn representative_lengths(min_len: usize, max_len: usize) -> Vec<usize> {
    let mid = (min_len + max_len) / 2;
    let mut v = vec![
        min_len,
        min_len + 1,
        min_len + BHP_CHUNK_SIZE - 1,
        min_len + BHP_CHUNK_SIZE,
        min_len + BHP_CHUNK_SIZE + 1,
        mid,
        mid - (mid % BHP_CHUNK_SIZE),
        max_len - 2 * BHP_CHUNK_SIZE,
        max_len - BHP_CHUNK_SIZE,
        max_len - 1,
        max_len,
    ];
    v.sort_unstable();
    v.dedup();
    v
}

fn print_row(label: &str, n: usize, bytes: &[u8]) {
    print!("EXPECTATIONS_{label} ({n}): [");
    for (i, b) in bytes.iter().enumerate() {
        if i > 0 {
            print!(", ");
        }
        print!("0x{b:02x}");
    }
    println!("]");
}

macro_rules! display_expectations {
    ($label:literal, $nw:literal, $ws:literal, $domain:literal) => {{
        let hasher = BHPHasher::<Console, $nw, $ws>::setup($domain)?;
        // The shortest input is one bit more than a window, and the longest fills every window.
        let min = $ws * BHP_CHUNK_SIZE + 1;
        let max = $nw * $ws * BHP_CHUNK_SIZE;
        println!("--- BHP {} (WINDOW_SIZE = {} windows, NUM_WINDOWS = {}, domain = {}) ---", $label, $ws, $nw, $domain);
        for n in representative_lengths(min, max) {
            print_row($label, n, &hasher.hash_uncompressed(&bits(n))?.to_bytes_le()?);
        }
    }};
}

/// Prints the test vectors that `src/bhp/hasher/tests.rs` expects.
/// `cargo run -p snarkvm-console-algorithms --example bhp_expectations`
fn main() -> Result<()> {
    display_expectations!("256", 3, 57, "BHPVec256");
    display_expectations!("512", 6, 43, "BHPVec512");
    display_expectations!("768", 15, 23, "BHPVec768");
    display_expectations!("1024", 8, 54, "BHPVec1024");
    Ok(())
}
