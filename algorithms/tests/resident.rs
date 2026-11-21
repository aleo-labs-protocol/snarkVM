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

//! Device-resident SRS windows, tested against keys trimmed from the real SRS.
//! The windows load once per process at one length, so every test shares one
//! set of 2^15-point windows. The tests run in parallel, so nothing asserts an
//! exact process-wide counter.

#![cfg(all(feature = "cuda", target_arch = "x86_64"))]

use snarkvm_algorithms::{
    crypto_hash::PoseidonSponge,
    msm::variable_base::standard,
    polycommit::{
        kzg10::{KZG10, UniversalParams},
        sonic_pc::{CommitterKey, SonicKZG10},
    },
};
use snarkvm_algorithms_cuda::resident;
use snarkvm_curves::{
    AffineCurve,
    ProjectiveCurve,
    bls12_377::{Bls12_377, Fq, Fr, G1Affine},
};
use snarkvm_fields::PrimeField;
use snarkvm_utilities::rand::{TestRng, Uniform};

use std::sync::LazyLock;

const W: usize = 1 << 15;

static PP: LazyLock<UniversalParams<Bls12_377>> = LazyLock::new(|| {
    let pp = KZG10::<Bls12_377>::load_srs(W - 1).expect("the bundled SRS loads");
    resident::load_windows_of(&pp, W).expect("the windows load");
    pp
});

type Projective = <G1Affine as AffineCurve>::Projective;
type BigInt = <Fr as PrimeField>::BigInteger;
type PC = SonicKZG10<Bls12_377, PoseidonSponge<Fq, 2, 1>>;

/// A committer key with a prefix of `degree + 1` points and a suffix of
/// `bound + 1`, trimmed from the SRS the windows came from.
fn key(degree: usize, bound: usize) -> CommitterKey<Bls12_377> {
    PC::trim(&PP, degree, [], 1, Some(&[bound])).expect("the SRS holds every degree these tests trim to").0
}

/// The device MSM at any size, without `VariableBase`'s `> 1024` gate.
fn cuda_msm(bases: &[G1Affine], scalars: &[BigInt]) -> Projective {
    snarkvm_algorithms::cuda_must_succeed!(
        snarkvm_algorithms_cuda::msm::<G1Affine, Projective, BigInt>(bases, scalars),
        "MSM"
    )
}

fn scalars(rng: &mut TestRng, n: usize) -> Vec<BigInt> {
    (0..n).map(|_| Fr::rand(rng).to_bigint()).collect()
}

/// Bit-identical at every size from 2^2 to 2^14, at both ends, read at
/// an offset into each array so the window arithmetic is exercised: the
/// prefix from the window's start, the suffix from `W - len`.
#[test]
fn windows_match_the_host_at_every_size() {
    let mut rng = TestRng::default();
    let key = key((1 << 14) + 2, 1 << 14);
    let suffix = key.shifted_powers_of_beta_g.as_deref().expect("every key here has a degree bound");
    for i in 2..=14 {
        let n = 1usize << i;
        for (name, bases) in [("prefix", &key.powers_of_beta_g[3..3 + n]), ("suffix", &suffix[1..1 + n])] {
            let scalars = scalars(&mut rng, n);
            let want = standard::msm(bases, &scalars).to_affine();
            assert_eq!(cuda_msm(bases, &scalars).to_affine(), want, "{name} 2^{i}");
            assert!(resident::is_resident(bases), "{name} 2^{i} was not read from a window");
        }
    }
}

/// The same points copied out of the SRS are uploaded per call.
#[test]
fn points_copied_out_of_the_srs_miss() {
    let mut rng = TestRng::default();
    let key = key(4095, 1024);
    let copy = key.powers_of_beta_g.to_vec();
    let scalars = scalars(&mut rng, 4096);
    assert_eq!(cuda_msm(&copy, &scalars).to_affine(), standard::msm(&copy, &scalars).to_affine());
    assert!(!resident::is_resident(&copy));
}

/// An array a key owns is read from the host, and the key's other array, which
/// it still shares with the SRS, from its window.
#[test]
fn an_array_a_key_owns_is_read_from_the_host() {
    let mut rng = TestRng::default();
    let mut key = key(4095, 1024);
    key.powers_of_beta_g.to_mut().swap(0, 1);
    let scalars = scalars(&mut rng, 4096);
    let prefix = &key.powers_of_beta_g;
    assert_eq!(cuda_msm(prefix, &scalars).to_affine(), standard::msm(prefix, &scalars).to_affine());
    assert!(!resident::is_resident(prefix), "an owned prefix was read from a window");
    assert!(resident::is_resident(key.shifted_powers_of_beta_g.as_deref().expect("every key here has a degree bound")));
}

/// Another instance of the SRS holds other snapshots: loading the windows from
/// it is refused, and its keys are read from the host.
#[test]
fn another_instance_of_the_srs_is_refused_and_misses() {
    let _ = &*PP;
    let other = KZG10::<Bls12_377>::load_srs(W - 1).expect("the bundled SRS loads");
    assert!(matches!(resident::load_windows_of(&other, W), Err(resident::LoadError::OtherSrs)));
    let key = PC::trim(&other, 4095, [], 1, Some(&[1024])).expect("the SRS holds this degree").0;
    assert!(!resident::is_resident(&key.powers_of_beta_g), "a key from another instance was read from a window");
}

/// Both arrays of a key trimmed from the SRS are read from the windows.
#[test]
fn a_trimmed_key_is_read_from_the_windows() {
    let key = key(4095, 1024);
    assert!(resident::is_resident(&key.powers_of_beta_g));
    assert!(resident::is_resident(key.shifted_powers_of_beta_g.as_deref().expect("every key here has a degree bound")));
}

/// The opening's resident path agrees with its upload path.
#[test]
fn accumulate_open_resident_matches_the_host() {
    let mut rng = TestRng::default();
    let n = 1 << 13;
    let key = key(n + 2, 1024);
    let copy = key.powers_of_beta_g.to_vec();
    let polys: Vec<Vec<Fr>> = (0..3).map(|_| (0..n + 1).map(|_| Fr::rand(&mut rng)).collect()).collect();
    let none = snarkvm_algorithms_cuda::DeviceCopy::default();
    let terms: Vec<(Fr, &[Fr], _)> = polys.iter().map(|p| (Fr::rand(&mut rng), p.as_slice(), &none)).collect();
    let z = Fr::rand(&mut rng);
    let open = |bases: &[G1Affine]| {
        snarkvm_algorithms::cuda_must_succeed!(
            snarkvm_algorithms_cuda::accumulate_open::<G1Affine, Projective, Fr>(n + 1, &terms, &z, bases),
            "accumulate_open"
        )
    };
    let resident_point = open(&key.powers_of_beta_g);
    assert!(resident::is_resident(&key.powers_of_beta_g[..n]));
    assert_eq!(resident_point.to_affine(), open(&copy).to_affine());
}
