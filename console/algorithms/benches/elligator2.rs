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

#[macro_use]
extern crate criterion;

use snarkvm_console_algorithms::Elligator2;
use snarkvm_console_types::prelude::*;
use snarkvm_utilities::{TestRng, Uniform};

use criterion::Criterion;

fn elligator2_256(c: &mut Criterion) {
    let rng = &mut TestRng::default();

    let input = Field::rand(rng);
    c.bench_function(&format!("Elligator2 - Field of {}-bits", Field::<Console>::size_in_bits()), |b| {
        b.iter(|| {
            let (_group, _sign) = Elligator2::<Console>::encode(&input).unwrap();
        })
    });
}

criterion_group! {
    name = elligator2;
    config = Criterion::default().sample_size(10);
    targets = elligator2_256
}

criterion_main!(elligator2);
