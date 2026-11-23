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

//! Without a load, the inclusion proving key getter falls back to the shipped key. The key is set once per process,
//! so this test runs apart from the load tests in `load_inclusion_proving_key.rs`.

#![cfg(all(feature = "filesystem", not(feature = "wasm")))]

use snarkvm_algorithms::{
    polycommit::{kzg10::UniversalParams, sonic_pc::Bases},
    snark::varuna::{CircuitProvingKey, VarunaHidingMode},
};
use snarkvm_console_network::prelude::*;

type Srs<N> = UniversalParams<<N as Environment>::PairingCurve>;

/// The shipped testnet inclusion proving key file.
fn shipped_file() -> Vec<u8> {
    snarkvm_parameters::testnet::InclusionProver::load_bytes().expect("the shipped file loads")
}

/// Grows `srs` to hold the powers the inclusion proving key shares.
fn grow_srs_for_inclusion<N: Network>(srs: &Srs<N>, file: &[u8]) {
    // Read without the SRS, and dropped before the SRS grows.
    let (powers, shifted) = {
        let key = CircuitProvingKey::<N::PairingCurve, VarunaHidingMode>::from_bytes_le(&file[1..])
            .expect("the shipped key reads");
        let committer_key = &key.committer_key;
        (committer_key.powers_of_beta_g.len(), committer_key.shifted_powers_of_beta_g.as_ref().map(|b| b.len()))
    };
    let max_degree = srs.max_degree();
    srs.download_powers_for(0..powers).expect("the SRS grows");
    if let Some(shifted) = shifted {
        srs.download_powers_for(max_degree + 1 - shifted..max_degree + 1).expect("the SRS grows");
    }
}

/// Without a load, the getter returns the key read from the shipped bytes, which then cannot be replaced.
#[test]
fn testnet_falls_back_to_the_shipped_inclusion_proving_key() {
    type N = TestnetV0;
    let file = shipped_file();
    let srs = Srs::<N>::load().expect("the SRS loads");
    assert!(N::load_inclusion_proving_key(&file, &srs).is_err(), "the key loaded against an SRS that lacks its powers");

    let key = N::inclusion_proving_key();
    assert!(matches!(key.committer_key.powers_of_beta_g, Bases::Owned(_)), "the shipped key shares an SRS");
    // `assert!`, since a failing `assert_eq!` would print both keys.
    assert!(key.to_bytes_le().expect("the key writes") == file[1..], "the key is not the shipped one");

    grow_srs_for_inclusion::<N>(&srs, &file);
    assert!(N::load_inclusion_proving_key(&file, &srs).is_err(), "the key loaded after the getter set it");
}
