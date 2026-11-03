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

//! Loads the shipped 'credits.aleo' and inclusion proving keys and holds them
//! all, as a prover would, then reports the points they own and the memory
//! the process holds.
//!
//! `cargo run --release --features filesystem --example srs_shared_keys [-- --with-srs | --grow-srs]`
//!
//! - With no flag, each key is read with `ProvingKey::from_bytes_le` and owns
//!   its points.
//! - With `--grow-srs`, the universal SRS is also grown to cover every key, as
//!   in a prover that holds the SRS anyway.
//! - With `--with-srs`, the SRS is grown the same way, and each key is read
//!   with `ProvingKey::from_bytes_le_with_srs`, which shares the points the SRS
//!   holds.

use snarkvm_console::network::MainnetV0;
use snarkvm_parameters::{errors::ParameterError, mainnet::*};
use snarkvm_synthesizer::snark::{ProvingKey, UniversalSRS};
use snarkvm_utilities::FromBytes;

use anyhow::Result;
use std::time::Instant;

type N = MainnetV0;

type LoadBytes = fn() -> Result<Vec<u8>, ParameterError>;

const KEYS: [(&str, LoadBytes); 16] = [
    ("bond_public", BondPublicProver::load_bytes),
    ("bond_validator", BondValidatorProver::load_bytes),
    ("unbond_public", UnbondPublicProver::load_bytes),
    ("claim_unbond_public", ClaimUnbondPublicProver::load_bytes),
    ("set_validator_state", SetValidatorStateProver::load_bytes),
    ("transfer_private", TransferPrivateProver::load_bytes),
    ("transfer_public", TransferPublicProver::load_bytes),
    ("transfer_public_as_signer", TransferPublicAsSignerProver::load_bytes),
    ("transfer_private_to_public", TransferPrivateToPublicProver::load_bytes),
    ("transfer_public_to_private", TransferPublicToPrivateProver::load_bytes),
    ("join", JoinProver::load_bytes),
    ("split", SplitProver::load_bytes),
    ("fee_private", FeePrivateProver::load_bytes),
    ("fee_public", FeePublicProver::load_bytes),
    ("upgrade", UpgradeProver::load_bytes),
    ("inclusion", InclusionProver::load_bytes),
];

/// The resident memory of this process in MiB, where `/proc` reports it.
fn resident_mib() -> Option<u64> {
    let status = std::fs::read_to_string("/proc/self/status").ok()?;
    let line = status.lines().find(|line| line.starts_with("VmRSS:"))?;
    Some(line.split_whitespace().nth(1)?.parse::<u64>().ok()? / 1024)
}

/// The points a key owns, rather than shares with the SRS.
fn owned_points(key: &ProvingKey<N>) -> usize {
    let committer_key = &key.committer_key;
    committer_key.powers_of_beta_g.owned_capacity()
        + committer_key.shifted_powers_of_beta_g.as_ref().map_or(0, |bases| bases.owned_capacity())
}

pub fn main() -> Result<()> {
    let with_srs = std::env::args().any(|arg| arg == "--with-srs");
    let grow_srs = with_srs || std::env::args().any(|arg| arg == "--grow-srs");
    let srs = UniversalSRS::<N>::load()?;

    if grow_srs {
        // A key shares the snapshot the SRS holds when it is read, so the SRS is
        // grown to cover every key first.
        for (_, load_bytes) in KEYS {
            // Read without the SRS, and dropped before the SRS grows: a key that
            // shared the SRS would make growing it copy the snapshot.
            let (powers, shifted) = {
                let key = ProvingKey::<N>::from_bytes_le(&load_bytes()?)?;
                let committer_key = &key.committer_key;
                (committer_key.powers_of_beta_g.len(), committer_key.shifted_powers_of_beta_g.as_ref().map_or(0, |b| b.len()))
            };
            srs.download_powers_for_ends(powers, shifted)?;
        }
    }

    println!("{:<28} {:>14} {:>10}", "key", "owned points", "read");
    let mut keys = Vec::with_capacity(KEYS.len());
    for (name, load_bytes) in KEYS {
        let bytes = load_bytes()?;
        let timer = Instant::now();
        let key = match with_srs {
            true => ProvingKey::<N>::from_bytes_le_with_srs(&bytes, &srs)?,
            false => ProvingKey::<N>::from_bytes_le(&bytes)?,
        };
        println!("{name:<28} {:>14} {:>10.1?}", owned_points(&key), timer.elapsed());
        keys.push(key);
    }

    let total: usize = keys.iter().map(owned_points).sum();
    println!("{:<28} {total:>14}", "total");
    if let Some(resident) = resident_mib() {
        println!("resident memory with every key held: {resident} MiB");
    }
    Ok(())
}
