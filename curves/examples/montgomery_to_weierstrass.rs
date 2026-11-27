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

use snarkvm_curves::{
    edwards_bls12::{EdwardsParameters, Fq},
    traits::MontgomeryParameters,
};
use snarkvm_fields::{Field, One};

/// Prints the short Weierstrass coefficients of the Montgomery form of `edwards_bls12`.
/// `cargo run -p snarkvm-curves --example montgomery_to_weierstrass`
fn main() {
    const A: Fq = <EdwardsParameters as MontgomeryParameters>::MONTGOMERY_A;
    const B: Fq = <EdwardsParameters as MontgomeryParameters>::MONTGOMERY_B;

    let two = Fq::one() + Fq::one();
    let three = Fq::one() + two;
    let nine = three + (three + three);
    let twenty_seven = nine + (nine + nine);

    let a2 = A.square();
    let a3 = A * a2;
    let b2 = B.square();
    let b3 = B * b2;

    // Let a = (3 - A^2) / (3 * B^2).
    let numerator = three - a2;
    let denominator = three * b2;
    // `B` is nonzero, so the denominator has an inverse.
    let a = numerator * denominator.inverse().unwrap();

    // Let b = (2 * A^3 - 9 * A) / (27 * B^3).
    let numerator = (two * a3) - (nine * A);
    let denominator = twenty_seven * b3;
    // `B` is nonzero, so the denominator has an inverse.
    let b = numerator * denominator.inverse().unwrap();

    println!("A - {a}\nB - {b}");
}
