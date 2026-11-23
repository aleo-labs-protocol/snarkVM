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

//! Snapshot tests of the circuit shape of each Pedersen hash and commitment.
//!
//! Each test synthesizes one operation of Pedersen64 or Pedersen128 for every operand mode, a few input lengths and a
//! fixed set of inputs and randomizers, and compares the counts, output mode and structural digest with
//! `snapshots/{op}.snap`.
//!
//! Each job builds its Pedersen instance outside the measured operation, so the constants of the bases are not
//! counted.

use std::sync::LazyLock;

use snarkvm_circuit_algorithms::{Commit, CommitUncompressed, Hash, HashUncompressed, Pedersen};
use snarkvm_circuit_types::{
    Boolean,
    Scalar,
    environment::{
        Circuit,
        prelude::*,
        snapshot::{self, Array, Case, OperandName, SnapshotFiles, Values, assert_snapshot, mode_jobs, run_parallel},
        snapshot_files,
    },
};
use snarkvm_console_algorithms::{
    self as console,
    Commit as _,
    CommitUncompressed as _,
    Hash as _,
    HashUncompressed as _,
};
use snarkvm_utilities::{TestRng, Uniform};

/// The snapshot files of the hashes.
const HASH_FILES: SnapshotFiles = snapshot_files!("each operand mode, input length and a fixed set of inputs");

/// The snapshot files of the commitments.
const COMMIT_FILES: SnapshotFiles = SnapshotFiles {
    coverage: "each operand mode, input length and a fixed set of inputs and randomizers",
    ..HASH_FILES
};

type Network = <Circuit as Environment>::Network;

/// A console scalar.
type ConsoleScalar = console::Scalar<Network>;

/// An input of `N` bits.
type Bits<const N: usize> = Array<Boolean<Circuit>, N>;

/// The Pedersen64 instance with the setup message of the networks.
static PEDERSEN_64: LazyLock<console::Pedersen64<Network>> =
    LazyLock::new(|| console::Pedersen64::setup("AleoPedersen64"));

/// The Pedersen128 instance with the setup message of the networks.
static PEDERSEN_128: LazyLock<console::Pedersen128<Network>> =
    LazyLock::new(|| console::Pedersen128::setup("AleoPedersen128"));

/// Returns `n` bits that are all `false`, all `true` and, if `n > 1`, sampled from a fixed seed, with their labels.
/// Returns the empty input alone if `n` is 0.
fn bit_values(n: usize) -> Vec<(Vec<bool>, String)> {
    if n == 0 {
        return vec![(Vec::new(), "empty".to_string())];
    }
    let mut values = vec![(vec![false; n], "zeros".to_string()), (vec![true; n], "ones".to_string())];
    if n > 1 {
        let rng = &mut TestRng::from_seed(0);
        values.push(((0..n).map(|_| bool::rand(rng)).collect(), "sampled".to_string()));
    }
    values
}

/// Returns the randomizers 0, 1, -1 and a scalar sampled from a fixed seed, with their labels.
fn randomizer_values() -> Vec<(ConsoleScalar, String)> {
    let one = ConsoleScalar::one();
    vec![
        (ConsoleScalar::zero(), "0".to_string()),
        (one, "1".to_string()),
        (-one, "-1".to_string()),
        (Uniform::rand(&mut TestRng::from_seed(0)), "sampled".to_string()),
    ]
}

/// The number of bits of a mixed input.
const MIXED_BITS: usize = 8;

/// Returns the mode of bit `j` of a mixed input: constant, public and private in turn.
fn mixed_mode(j: usize) -> Mode {
    [Mode::Constant, Mode::Public, Mode::Private][j % 3]
}

/// Returns the mixed inputs. The constant bits are all `false`, all `true` or sampled, and the variable bits are all
/// `false` or all `true`.
fn mixed_inputs() -> Vec<Vec<bool>> {
    bit_values(MIXED_BITS)
        .into_iter()
        .flat_map(|(constant_bits, _)| {
            [false, true].map(|variable_bit| {
                constant_bits
                    .iter()
                    .enumerate()
                    .map(|(j, bit)| if mixed_mode(j).is_constant() { *bit } else { variable_bit })
                    .collect()
            })
        })
        .collect()
}

/// Returns the operand name `name`, the mode and the label `0` or `1` of each bit of a mixed input.
///
/// Each bit is an operand of its case, so the values of the case show each constant bit as `0` or `1` and each
/// variable bit as `_`. The two mixed inputs with the same constant bits then merge into one line.
fn mixed_operands<'a>(name: &'a str, bits: &[bool]) -> Vec<(&'a str, Mode, &'static str)> {
    bits.iter().enumerate().map(|(j, bit)| (name, mixed_mode(j), if *bit { "1" } else { "0" })).collect()
}

/// Injects each bit of a mixed input in its mode.
fn inject_mixed(bits: &[bool]) -> Vec<Boolean<Circuit>> {
    bits.iter().enumerate().map(|(j, bit)| Boolean::new(mixed_mode(j), *bit)).collect()
}

/// Defines a snapshot test of `$method` of `$native`, a Pedersen instance of `$size` bits, for inputs of 0, 1, 8,
/// `$size` and `$size + 1` bits, each with every bit in one mode, and for mixed inputs.
macro_rules! hash_snapshot {
    ($op:ident, $size:literal, $native:ident, $method:ident) => {
        #[test]
        fn $op() {
            fn cases<const N: usize>(modes: [Mode; 1]) -> Vec<Case> {
                let pedersen = Pedersen::<Circuit, $size>::constant($native.clone());
                snapshot::unary(
                    |bits: &Bits<N>| pedersen.$method(bits),
                    |bits: Vec<bool>| $native.$method(&bits).ok(),
                    None,
                    &bit_values(N),
                    modes,
                )
            }
            fn mixed([]: [Mode; 0]) -> Vec<Case> {
                let pedersen = Pedersen::<Circuit, $size>::constant($native.clone());
                let name = Boolean::<Circuit>::operand_name();
                mixed_inputs()
                    .iter()
                    .map(|bits| {
                        let expected = $native.$method(bits).ok();
                        let inject = || inject_mixed(bits);
                        let operands = mixed_operands(&name, bits);
                        snapshot::case(&operands, None, expected, None, inject, |a| pedersen.$method(&a))
                    })
                    .collect()
            }
            let jobs = [
                mode_jobs(0, cases::<0>),
                mode_jobs(1, cases::<1>),
                mode_jobs(8, cases::<8>),
                mode_jobs($size, cases::<$size>),
                mode_jobs($size + 1, cases::<{ $size + 1 }>),
            ];
            let jobs = jobs.into_iter().flatten().chain(mode_jobs(MIXED_BITS as u64, mixed));
            assert_snapshot(&HASH_FILES, stringify!($op), run_parallel(jobs));
        }
    };
}

/// Defines a snapshot test of `$method` of `$native`, a Pedersen instance of `$size` bits, for inputs of 0, 1, 8,
/// `$size` and `$size + 1` bits, each with every bit in one mode, and for mixed inputs, with each randomizer.
macro_rules! commit_snapshot {
    ($op:ident, $size:literal, $native:ident, $method:ident) => {
        #[test]
        fn $op() {
            fn cases<const N: usize>(modes: [Mode; 2]) -> Vec<Case> {
                let pedersen = Pedersen::<Circuit, $size>::constant($native.clone());
                snapshot::binary(
                    |bits: &Bits<N>, r: &Scalar<Circuit>| pedersen.$method(bits, r),
                    |bits: Vec<bool>, r: ConsoleScalar| $native.$method(&bits, &r).ok(),
                    None,
                    &Values::same(bit_values(N)),
                    &Values::same(randomizer_values()),
                    modes,
                )
            }
            fn mixed([mode_r]: [Mode; 1]) -> Vec<Case> {
                let pedersen = Pedersen::<Circuit, $size>::constant($native.clone());
                let (name, name_r) = (Boolean::<Circuit>::operand_name(), Scalar::<Circuit>::operand_name());
                let (inputs, randomizers) = (mixed_inputs(), randomizer_values());
                let mut cases = Vec::with_capacity(inputs.len() * randomizers.len());
                for bits in &inputs {
                    for (r, label_r) in &randomizers {
                        let mut operands = mixed_operands(&name, bits);
                        operands.push((&name_r, mode_r, label_r));
                        let inject = || (inject_mixed(bits), Scalar::new(mode_r, *r));
                        let expected = $native.$method(bits, r).ok();
                        cases.push(snapshot::case(&operands, None, expected, None, inject, |(a, r)| {
                            pedersen.$method(&a, &r)
                        }));
                    }
                }
                cases
            }
            let jobs = [
                mode_jobs(0, cases::<0>),
                mode_jobs(1, cases::<1>),
                mode_jobs(8, cases::<8>),
                mode_jobs($size, cases::<$size>),
                mode_jobs($size + 1, cases::<{ $size + 1 }>),
            ];
            let jobs = jobs.into_iter().flatten().chain(mode_jobs(MIXED_BITS as u64, mixed));
            assert_snapshot(&COMMIT_FILES, stringify!($op), run_parallel(jobs));
        }
    };
}

hash_snapshot!(pedersen64_hash, 64, PEDERSEN_64, hash);
hash_snapshot!(pedersen64_hash_uncompressed, 64, PEDERSEN_64, hash_uncompressed);
hash_snapshot!(pedersen128_hash, 128, PEDERSEN_128, hash);
hash_snapshot!(pedersen128_hash_uncompressed, 128, PEDERSEN_128, hash_uncompressed);

commit_snapshot!(pedersen64_commit, 64, PEDERSEN_64, commit);
commit_snapshot!(pedersen64_commit_uncompressed, 64, PEDERSEN_64, commit_uncompressed);
commit_snapshot!(pedersen128_commit, 128, PEDERSEN_128, commit);
commit_snapshot!(pedersen128_commit_uncompressed, 128, PEDERSEN_128, commit_uncompressed);
