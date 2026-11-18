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

use snarkvm_ledger::{Block, Ledger};
use snarkvm_ledger_store::{BlockStorage, BlockStore, ConsensusStorage, StorageMode};
use snarkvm_utilities::{FromBytes, PrettyUnwrap};

use anyhow::{Result, ensure};
use std::{fs, path::PathBuf};
use tracing_subscriber::{EnvFilter, fmt, prelude::*};

pub type CurrentNetwork = snarkvm_console::network::MainnetV0;

/// Helper to initialize the `BlockStorage`.
#[allow(dead_code)]
pub fn create_storage<S: BlockStorage<CurrentNetwork>>(
    genesis_block: &Block<CurrentNetwork>,
) -> BlockStore<CurrentNetwork, S> {
    let store = BlockStore::<CurrentNetwork, S>::open(StorageMode::new_test(None)).expect("Failed to create storage");

    store.insert(genesis_block).unwrap();
    store
}

/// Helper to initialize the `Ledger`.
#[allow(dead_code)]
pub fn create_ledger<S: ConsensusStorage<CurrentNetwork>>(
    genesis_block: Block<CurrentNetwork>,
) -> Ledger<CurrentNetwork, S> {
    Ledger::load(genesis_block, StorageMode::new_test(None)).pretty_expect("Failed to create empty test ledger")
}

/// Load blocks, which were generated using `snarkvm-testchain-generator --no-ledger [..]` from the given path.
#[allow(dead_code)]
pub fn load_blocks(path: &str) -> Result<(Block<CurrentNetwork>, Vec<Block<CurrentNetwork>>)> {
    let mut current_height = 1;
    let mut blocks = vec![];

    let genesis_block = {
        let path: PathBuf = format!("{path}/genesis.data").into();

        let data = fs::read(path)?;
        Block::from_bytes_le_unchecked(&data)?
    };

    loop {
        let path: PathBuf = format!("{path}/block{current_height}.data").into();
        if !path.is_file() {
            break;
        }

        let data = fs::read(path)?;
        let block = Block::from_bytes_le_unchecked(&data)?;

        blocks.push(block);
        current_height += 1;
    }

    ensure!(!blocks.is_empty(), "found no blocks");

    println!("Loaded {num} blocks from disk", num = blocks.len());

    Ok((genesis_block, blocks))
}

pub fn initialize_logging() {
    tracing_subscriber::registry().with(fmt::layer()).with(EnvFilter::from_default_env()).init();
}
