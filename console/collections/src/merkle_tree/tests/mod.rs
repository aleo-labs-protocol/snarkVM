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

use super::*;
use snarkvm_console_algorithms::Poseidon;
use snarkvm_console_types::prelude::Console;

use std::{
    io,
    sync::{Arc, Mutex},
};
use tracing_subscriber::{EnvFilter, fmt::format::FmtSpan, util::SubscriberInitExt};

mod append;
mod empty_hash;
mod remove;
mod state;
mod test_print;
mod update;
mod update_many;

macro_rules! run_tests {
    ($rng:expr, [$($i:expr),*]) => {
        $( assert!(run_test::<$i>($rng).is_ok()); )*
    };
}
use run_tests;

/// A writer that appends to a shared buffer.
#[derive(Clone, Default)]
struct Buffer(Arc<Mutex<Vec<u8>>>);

impl io::Write for Buffer {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        // The lock is only poisoned if another writer panicked, which fails the test regardless.
        self.0.lock().unwrap().extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

/// Runs `f` and returns the output of a subscriber that accepts `filter` and logs when a span closes.
fn capture(filter: &str, f: impl Fn()) -> String {
    let buffer = Buffer::default();
    let writer = buffer.clone();
    let guard = tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::new(filter))
        .with_span_events(FmtSpan::CLOSE)
        .with_ansi(false)
        .with_writer(move || writer.clone())
        .set_default();
    // `tracing` caches whether a callsite is enabled, and a callsite that another thread registered stays disabled.
    // The first run registers each callsite of `f`. The rebuild then asks this subscriber about each callsite.
    f();
    tracing::callsite::rebuild_interest_cache();
    // The lock is only poisoned if a writer panicked, which fails the test regardless.
    buffer.0.lock().unwrap().clear();
    f();
    drop(guard);
    // The lock is only poisoned if a writer panicked, which fails the test regardless.
    let bytes = buffer.0.lock().unwrap().clone();
    // The formatter only writes UTF-8.
    String::from_utf8(bytes).unwrap()
}

#[test]
fn test_new_emits_timing_span_and_events() -> Result<()> {
    type LH = Poseidon<Console, 4>;
    type PH = Poseidon<Console, 2>;

    let leaf_hasher = LH::setup("AleoMerkleTreeTest0")?;
    let path_hasher = PH::setup("AleoMerkleTreeTest1")?;
    let leaves = vec![vec![Field::<Console>::zero()]; 4];

    let output = capture("timing::snarkvm_console_collections=trace", || {
        // The construction is infallible for these hashers and leaves.
        MerkleTree::<Console, LH, PH, 3>::new(&leaf_hasher, &path_hasher, &leaves).unwrap();
    });

    // Each step is an event in the span, and the span reports its duration when it closes.
    let prefix = "TRACE MerkleTree::new: timing::snarkvm_console_collections::merkle_tree:";
    let expected = ["Hashed 4 leaves", "Hashed 2 levels", "Hashed 1 padding levels", "close time.busy="];
    let mut lines = output.lines();
    for expected in expected {
        assert!(lines.next().is_some_and(|line| line.contains(&format!("{prefix} {expected}"))), "{output}");
    }
    assert!(lines.next().is_none());
    Ok(())
}
