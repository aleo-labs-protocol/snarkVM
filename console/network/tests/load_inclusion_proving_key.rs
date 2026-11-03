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

//! The inclusion proving key loaded against the SRS shares it and is the shipped one. Each network's key is set
//! once per process, so each test owns one network.

#![cfg(all(feature = "filesystem", not(feature = "wasm")))]

use snarkvm_algorithms::{
    polycommit::{kzg10::UniversalParams, sonic_pc::Bases},
    snark::varuna::{CircuitProvingKey, VarunaHidingMode},
};
use snarkvm_console_network::prelude::*;

use std::sync::Arc;

type Srs<N> = UniversalParams<<N as Environment>::PairingCurve>;

/// The shipped inclusion proving key file.
fn shipped_file<N: Network>() -> Vec<u8> {
    match N::ID {
        MainnetV0::ID => snarkvm_parameters::mainnet::InclusionProver::load_bytes(),
        TestnetV0::ID => snarkvm_parameters::testnet::InclusionProver::load_bytes(),
        CanaryV0::ID => snarkvm_parameters::canary::InclusionProver::load_bytes(),
        id => panic!("no shipped inclusion proving key for network {id}"),
    }
    .expect("the shipped file loads")
}

/// Grows `srs` to hold the powers the inclusion proving key shares.
fn grow_srs_for_inclusion<N: Network>(srs: &Srs<N>) {
    // Read without the SRS, and dropped before the SRS grows.
    let (powers, shifted) = {
        let key = CircuitProvingKey::<N::PairingCurve, VarunaHidingMode>::from_bytes_le(&shipped_file::<N>()[1..])
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

/// Loading fails against an SRS that lacks the key's powers, and for a file that is not the shipped one, leaving the
/// key unset; against a grown SRS it sets the shipped key, sharing the SRS's current snapshot; loading again fails.
fn loads_the_shipped_key<N: Network>() {
    let file = shipped_file::<N>();
    let srs = Srs::<N>::load().expect("the SRS loads");
    assert!(N::load_inclusion_proving_key(&file, &srs).is_err(), "the key loaded against an SRS that lacks its powers");

    grow_srs_for_inclusion::<N>(&srs);
    let mut flipped = file.clone();
    flipped[file.len() / 2] ^= 1;
    assert!(N::load_inclusion_proving_key(&flipped, &srs).is_err(), "a file that is not the shipped one loaded");
    N::load_inclusion_proving_key(&file, &srs).expect("the key loads against the grown SRS");

    let key = N::inclusion_proving_key();
    let Bases::Shared { store, range } = &key.committer_key.powers_of_beta_g else { panic!("the bases were copied") };
    let (snapshot, _) = srs.shared_powers_of_beta_g(0, range.end).expect("the SRS holds the powers");
    assert!(Arc::ptr_eq(store, &snapshot), "the key's bases are not the SRS's current snapshot");
    // `assert!`, since a failing `assert_eq!` would print both keys.
    assert!(key.to_bytes_le().expect("the key writes") == file[1..], "the key is not the shipped one");

    assert!(N::load_inclusion_proving_key(&file, &srs).is_err(), "the key loaded twice");
}

#[test]
fn mainnet_loads_the_shipped_inclusion_proving_key() {
    loads_the_shipped_key::<MainnetV0>();
}

#[test]
fn testnet_loads_the_shipped_inclusion_proving_key() {
    loads_the_shipped_key::<TestnetV0>();
}

/// Without a load, the getter returns the key read from the shipped bytes, which then cannot be replaced.
#[test]
fn canary_falls_back_to_the_shipped_inclusion_proving_key() {
    type N = CanaryV0;
    let file = shipped_file::<N>();
    let srs = Srs::<N>::load().expect("the SRS loads");
    assert!(N::load_inclusion_proving_key(&file, &srs).is_err(), "the key loaded against an SRS that lacks its powers");

    let key = N::inclusion_proving_key();
    assert!(matches!(key.committer_key.powers_of_beta_g, Bases::Owned(_)), "the shipped key shares an SRS");
    // `assert!`, since a failing `assert_eq!` would print both keys.
    assert!(key.to_bytes_le().expect("the key writes") == file[1..], "the key is not the shipped one");

    grow_srs_for_inclusion::<N>(&srs);
    assert!(N::load_inclusion_proving_key(&file, &srs).is_err(), "the key loaded after the getter set it");
}
