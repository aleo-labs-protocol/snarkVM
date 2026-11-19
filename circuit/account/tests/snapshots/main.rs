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

//! Snapshot tests of the circuit shape of each compute key and signature operation.
//!
//! Each test synthesizes one operation for every operand mode and a fixed set of keys and signatures,
//! and compares the counts, output mode and structural digest with `snapshots/{op}.snap`.
//!
//! Each job first builds the global constants of `AleoV0` on its thread. Otherwise the first operation
//! that uses them on a thread counts their constants.

use std::sync::LazyLock;

use snarkvm_circuit_account::{ComputeKey, PrivateKey, Signature};
use snarkvm_circuit_network::{Aleo, AleoV0};
use snarkvm_circuit_types::{
    Address,
    Boolean,
    Field,
    environment::{
        prelude::*,
        snapshot::{self, Case, SnapshotFiles, Values, assert_snapshot, mode_jobs, run_parallel, value_label},
    },
};
use snarkvm_console_account as console;
use snarkvm_utilities::TestRng;

const FILES: SnapshotFiles = SnapshotFiles {
    directory: concat!(env!("CARGO_MANIFEST_DIR"), "/tests/snapshots"),
    coverage: "each operand mode and a fixed set of keys and signatures",
    command: "cargo test -p snarkvm-circuit-account --test snapshots",
};

type Network = <AleoV0 as Environment>::Network;

/// Defines `$name`, which wraps `$inner` and names it `$type_name` in the snapshot files.
macro_rules! named {
    ($name:ident, $inner:ident, $type_name:literal) => {
        struct $name($inner<AleoV0>);

        impl Inject for $name {
            type Primitive = <$inner<AleoV0> as Inject>::Primitive;

            fn new(mode: Mode, value: Self::Primitive) -> Self {
                Self($inner::new(mode, value))
            }
        }

        impl Eject for $name {
            type Primitive = <$inner<AleoV0> as Eject>::Primitive;

            fn eject_mode(&self) -> Mode {
                self.0.eject_mode()
            }

            fn eject_value(&self) -> Self::Primitive {
                self.0.eject_value()
            }
        }

        impl TypeName for $name {
            fn type_name() -> &'static str {
                $type_name
            }
        }
    };
}

named!(NamedPrivateKey, PrivateKey, "private_key");
named!(NamedComputeKey, ComputeKey, "compute_key");

/// Returns three private keys sampled from a fixed seed, with their labels.
fn private_keys() -> Vec<(console::PrivateKey<Network>, String)> {
    static KEYS: LazyLock<Vec<(console::PrivateKey<Network>, String)>> = LazyLock::new(|| {
        let rng = &mut TestRng::from_seed(0);
        (1..=3)
            .map(|i| {
                // Note: `expect` is safe as `PrivateKey::new` fails only if a Poseidon hash of two elements fails.
                let private_key = console::PrivateKey::new(rng).expect("the key derivation hashes two elements");
                (private_key, format!("key-{i}"))
            })
            .collect()
    });
    KEYS.clone()
}

/// Returns the compute key of each private key, with its label.
fn compute_keys() -> Vec<(console::ComputeKey<Network>, String)> {
    private_keys()
        .into_iter()
        // Note: `expect` is safe as a valid private key derives a compute key.
        .map(|(private_key, label)| (console::ComputeKey::try_from(&private_key).expect("a valid private key"), label))
        .collect()
}

/// Returns the address of the first two private keys, with their labels.
fn addresses() -> Vec<(console::Address<Network>, String)> {
    private_keys()
        .into_iter()
        .take(2)
        .map(|(private_key, label)| {
            // Note: `expect` is safe as a valid private key derives an address.
            let address = console::Address::try_from(&private_key).expect("a valid private key");
            (address, label.replace("key", "addr"))
        })
        .collect()
}

/// Returns the messages, with their labels. Each signature signs the first one.
fn messages() -> Vec<(Vec<console::Field<Network>>, String)> {
    [[1, 2], [1, 3]]
        .into_iter()
        .map(|message| (message.map(console::Field::from_u64).to_vec(), format!("[{},{}]", message[0], message[1])))
        .collect()
}

/// Returns the signature of the first message by each of the first two private keys, with its label.
fn signatures() -> Vec<(console::Signature<Network>, String)> {
    static SIGNATURES: LazyLock<Vec<(console::Signature<Network>, String)>> = LazyLock::new(|| {
        let rng = &mut TestRng::from_seed(1);
        let (message, _) = &messages()[0];
        private_keys()
            .into_iter()
            .take(2)
            .map(|(private_key, label)| {
                // Note: `expect` is safe as `sign` fails only on a message that is too long or whose second element
                // is the hash of its first.
                let signature = console::Signature::sign(&private_key, message, rng).expect("a valid message");
                (signature, label.replace("key", "sig"))
            })
            .collect()
    });
    SIGNATURES.clone()
}

#[test]
fn from_private_key() {
    fn cases(modes: [Mode; 1]) -> Vec<Case> {
        AleoV0::initialize_global_constants();
        snapshot::unary(
            |a: &NamedPrivateKey| ComputeKey::from_private_key(&a.0),
            |x| console::ComputeKey::try_from(&x).ok(),
            None,
            &private_keys(),
            modes,
        )
    }
    assert_snapshot(&FILES, "from_private_key", run_parallel(mode_jobs(1, cases)));
}

#[test]
fn to_address() {
    fn cases(modes: [Mode; 1]) -> Vec<Case> {
        AleoV0::initialize_global_constants();
        snapshot::unary(
            |a: &NamedComputeKey| a.0.to_address(),
            |x| console::Address::try_from(&x).ok(),
            None,
            &compute_keys(),
            modes,
        )
    }
    assert_snapshot(&FILES, "to_address", run_parallel(mode_jobs(1, cases)));
}

/// Defines a snapshot test of a binary operation on two operands of the same type that returns a boolean.
macro_rules! binary_snapshot {
    ($op:ident, $type:ty, $values:expr, |$a:ident, $b:ident| $circuit:expr, |$x:ident, $y:ident| $console:expr) => {
        #[test]
        fn $op() {
            fn cases(modes: [Mode; 2]) -> Vec<Case> {
                AleoV0::initialize_global_constants();
                let values = Values::same($values);
                snapshot::binary(
                    |$a: &$type, $b: &$type| -> Boolean<AleoV0> { $circuit },
                    |$x, $y| Some($console),
                    None,
                    &values,
                    &values,
                    modes,
                )
            }
            assert_snapshot(&FILES, stringify!($op), run_parallel(mode_jobs(1, cases)));
        }
    };
}

binary_snapshot!(compute_key_is_equal, NamedComputeKey, compute_keys(), |a, b| a.0.is_equal(&b.0), |x, y| x == y);
binary_snapshot!(compute_key_is_not_equal, NamedComputeKey, compute_keys(), |a, b| a.0.is_not_equal(&b.0), |x, y| x
    != y);
binary_snapshot!(signature_is_equal, Signature<AleoV0>, signatures(), |a, b| a.is_equal(b), |x, y| x == y);
binary_snapshot!(signature_is_not_equal, Signature<AleoV0>, signatures(), |a, b| a.is_not_equal(b), |x, y| x != y);

#[test]
fn compute_key_ternary() {
    fn cases(modes: [Mode; 3]) -> Vec<Case> {
        AleoV0::initialize_global_constants();
        snapshot::ternary(
            |c: &Boolean<AleoV0>, a: &NamedComputeKey, b: &NamedComputeKey| {
                NamedComputeKey(ComputeKey::ternary(c, &a.0, &b.0))
            },
            None,
            &compute_keys(),
            modes,
        )
    }
    assert_snapshot(&FILES, "compute_key_ternary", run_parallel(mode_jobs(1, cases)));
}

#[test]
fn signature_ternary() {
    fn cases(modes: [Mode; 3]) -> Vec<Case> {
        AleoV0::initialize_global_constants();
        snapshot::ternary(
            |c: &Boolean<AleoV0>, a: &Signature<AleoV0>, b: &Signature<AleoV0>| Signature::ternary(c, a, b),
            None,
            &signatures(),
            modes,
        )
    }
    assert_snapshot(&FILES, "signature_ternary", run_parallel(mode_jobs(1, cases)));
}

/// Covers each signature, address and message. A signature is valid only for its own address and the first message.
#[test]
fn verify() {
    fn cases([mode_s, mode_a, mode_m]: [Mode; 3]) -> Vec<Case> {
        AleoV0::initialize_global_constants();
        let (signatures, addresses, messages) = (signatures(), addresses(), messages());
        let block = format!(
            "{}.{mode_s} {}.{mode_a} {}[{}].{mode_m}",
            Signature::<AleoV0>::type_name(),
            Address::<AleoV0>::type_name(),
            Field::<AleoV0>::type_name(),
            messages[0].0.len()
        );
        let mut cases = Vec::with_capacity(signatures.len() * addresses.len() * messages.len());
        for (signature, label_s) in &signatures {
            for (address, label_a) in &addresses {
                for (message, label_m) in &messages {
                    AleoV0::reset();
                    let s = Signature::<AleoV0>::new(mode_s, *signature);
                    let a = Address::<AleoV0>::new(mode_a, *address);
                    let m: Vec<Field<AleoV0>> = Inject::new(mode_m, message.clone());
                    let label = format!("{block} {label_s} {label_a} {label_m}");
                    let expected = Some(signature.verify(address, message));
                    let outcome = snapshot::measure(&label, expected, None, || s.verify(&a, &m));
                    let values = format!(
                        "{} {} {}",
                        value_label(mode_s, label_s),
                        value_label(mode_a, label_a),
                        value_label(mode_m, label_m)
                    );
                    cases.push(Case { block: block.clone(), values, outcome });
                }
            }
        }
        cases
    }
    assert_snapshot(&FILES, "verify", run_parallel(mode_jobs(1, cases)));
}
