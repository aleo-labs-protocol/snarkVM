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

use snarkvm_console::prelude::{
    CanaryV0,
    MainnetV0,
    Network,
    TEST_CONSENSUS_VERSION_HEIGHTS,
    TestRng,
    TestnetV0,
    ToBytes,
};
use snarkvm_ledger::{
    Ledger,
    Transaction,
    store::helpers::rocksdb::ConsensusDB,
    test_helpers::{TestChainBuilder, chain_builder::GenerateBlocksOptions},
};

use aleo_std::StorageMode;
use anyhow::{Context, Result, bail};
use clap::{Parser, builder::PossibleValuesParser};
use std::{fs, path::Path, str::FromStr};
use tracing::debug;

#[derive(Parser)]
struct Args {
    /// The number of validators active on the chain.
    /// (also corresponds to the number of certificates per round)
    num_validators: usize,
    /// The number of blocks to generator.
    num_blocks: usize,
    /// Load the genesis block for the chain from the specified path instead of generating it.
    #[clap(long)]
    genesis_path: Option<String>,
    /// Set a custom storage path for the ledger.
    /// By default, it will use the ledger of the first devnet validator.
    #[clap(long, short = 'p')]
    storage_path: Option<String>,
    /// Remove existing ledger if it already exists.
    #[clap(long, short = 'f')]
    force: bool,
    /// Load the transactions to be used with the generated blocks. They are expected to be
    /// stored in a JSON-encoded format.
    #[clap(long)]
    txs_path: Option<String>,
    /// The name of the network to generate the chain for.
    #[clap(long, value_parser=PossibleValuesParser::new(vec![CanaryV0::SHORT_NAME, TestnetV0::SHORT_NAME, MainnetV0::SHORT_NAME]), default_value=TestnetV0::SHORT_NAME)]
    network: String,
    /// Set the seed to used to generate the chain.
    #[clap(long)]
    seed: Option<u64>,
    /// Store serialized blocks directly on disk instead of going through ledger storage.
    #[clap(long, requires = "storage_path")]
    no_ledger: bool,
}

/// Removes an existing ledger (if any) from the filesystem.
fn remove_ledger(network: u16, storage_mode: &StorageMode, force: bool) -> Result<()> {
    let path = aleo_std::aleo_ledger_dir(network, storage_mode);

    if path.exists() && force {
        std::fs::remove_dir_all(&path).with_context(|| "Failed to remove existing ledger")?;

        println!("Removed existing ledger data at {path:?}");
    } else if path.exists() {
        bail!("There is already a ledger at {path:?}. Re-run with `--force` if you want to overwrite it");
    }

    Ok(())
}

fn main() -> Result<()> {
    // Enable logging.
    tracing_subscriber::fmt::init();

    let args = Args::parse();

    match args.network.as_str() {
        CanaryV0::SHORT_NAME => generate_testchain::<CanaryV0>(args),
        TestnetV0::SHORT_NAME => generate_testchain::<TestnetV0>(args),
        MainnetV0::SHORT_NAME => generate_testchain::<MainnetV0>(args),
        // This is caught by clap.
        _ => unreachable!(),
    }
}

fn generate_testchain<N: Network>(args: Args) -> Result<()> {
    let mut rng = if let Some(seed) = args.seed {
        println!("Using seed of {seed}");
        TestRng::from_seed(seed)
    } else {
        TestRng::default()
    };

    let storage_mode = if let Some(path) = args.storage_path.clone() {
        StorageMode::Custom(path.into(), None)
    } else {
        StorageMode::Development(0)
    };

    remove_ledger(N::ID, &storage_mode, args.force)?;

    let mut txs = if let Some(path) = args.txs_path {
        let path = Path::new(&path);

        if path.is_dir() {
            println!("Attempting to load transactions from \"{}\"", path.display());
        } else {
            bail!("Cannot load transactions from \"{}\": not a valid directory", path.display());
        }

        let mut txs = Vec::new();
        for entry in fs::read_dir(path)? {
            let entry = entry?;
            let path = entry.path();

            let buffer = fs::read_to_string(path)?;
            let tx = Transaction::<N>::from_str(&buffer)?;

            txs.push(tx);
        }

        println!("Loaded {} tranactionss from \"{}\"", txs.len(), path.display());
        txs
    } else {
        Default::default()
    };

    let num_validators = args.num_validators;
    let num_blocks = args.num_blocks;

    println!("Initializing test chain builder for {} with {num_validators} validators", N::SHORT_NAME);
    let mut builder: TestChainBuilder<N> = match args.genesis_path {
        Some(genesis_path) => TestChainBuilder::new_with_quorum_size_and_genesis_block(num_validators, genesis_path),
        None => TestChainBuilder::new_with_quorum_size(num_validators, &mut rng),
    }
    .with_context(|| "Failed to set up test chain builder")?;

    println!("Generating {num_blocks} blocks");

    let mut pos = 0;
    let mut blocks = vec![];

    // How many blocks to generate in a single batch.
    const BATCH_SIZE: usize = 100;

    // How many transactions to insert per block.
    let latest_consensus_height = TEST_CONSENSUS_VERSION_HEIGHTS.last().unwrap().1 as usize;
    let num_txn_blocks = num_blocks.saturating_sub(latest_consensus_height);
    let txns_per_block = txs.len().div_ceil(num_txn_blocks);

    while blocks.len() < num_blocks {
        let current_height = blocks.len();
        // How many blocks to generate in this batch.
        let batch_size = (num_blocks - current_height).min(BATCH_SIZE);
        // Generate set of transactions to insert in this batch.
        let num_empty_blocks = latest_consensus_height.saturating_sub(current_height);
        let num_txns = (batch_size.saturating_sub(num_empty_blocks)) * txns_per_block;
        let transactions = txs.drain(..num_txns).collect();

        debug!("Generating next batch with {batch_size} blocks and {num_txns} transactions");
        let mut batch = builder
            .generate_blocks_with_opts(
                batch_size,
                GenerateBlocksOptions { transactions, skip_to_current_version: true, ..Default::default() },
                &mut rng,
            )
            .with_context(|| "Failed to generate blocks")?;

        pos += batch_size;
        println!("Generated {pos} of {num_blocks} blocks");
        blocks.append(&mut batch);
    }

    if args.no_ledger {
        let base_path = args.storage_path.unwrap();
        fs::create_dir(base_path.clone())?;

        println!("Storing blocks as {base_path}/block{{height}}.data");

        // Store genesis block.
        {
            let path = format!("{base_path}/genesis.data");
            let data = builder.genesis_block().to_bytes_le()?;
            fs::write(path, data)?;
        }

        // Store remaining blocks.
        for block in blocks.into_iter() {
            let path = format!("{base_path}/block{}.data", block.height());
            let data = block.to_bytes_le()?;
            fs::write(path, data)?;
        }
    } else {
        println!("Done. Storing blocks to on-disk ledger.");

        let ledger = Ledger::<N, ConsensusDB<N>>::load_unchecked(builder.genesis_block().clone(), storage_mode)
            .with_context(|| "Failed to initialize ledger")?;

        // Ensure there is only one active ledger at a time.
        drop(builder);

        for block in blocks.into_iter() {
            ledger.advance_to_next_block(&block)?;

            if block.height().is_multiple_of(100) {
                println!("Stored {} blocks out of {num_blocks} to disk", block.height());
            }
        }
    }

    Ok(())
}
