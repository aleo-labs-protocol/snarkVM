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

use snarkvm_circuit::{
    environment::{Circuit, Eject, Environment, Inject, LinearCombination, Mode, One, prelude::num_traits::One as _},
    types::Field,
};

use criterion::Criterion;
use std::borrow::Cow;

fn add(c: &mut Criterion) {
    let one = <Circuit as Environment>::BaseField::one();
    let two = one + one;

    const ITERATIONS: u64 = 1000;

    c.bench_function("LinearCombination::add", move |b| {
        b.iter(|| {
            let mut candidate = <Circuit as Environment>::one();
            for _ in 0..ITERATIONS {
                candidate = &candidate + &LinearCombination::from(Circuit::new_variable(Mode::Public, two));
            }
        })
    });

    c.bench_function("LinearCombination::add_assign", move |b| {
        b.iter(|| {
            let mut candidate = <Circuit as Environment>::one();
            for _ in 0..ITERATIONS {
                candidate += Cow::Owned(LinearCombination::from(Circuit::new_variable(Mode::Public, two)));
            }
        })
    });
}

fn to_value(c: &mut Criterion) {
    let one = snarkvm_console_types::Field::<<Circuit as Environment>::Network>::one();
    let two = one + one;

    let mut candidate = Field::<Circuit>::one();
    (0..500_000).for_each(|_| {
        candidate += Field::new(Mode::Constant, two);
        candidate += Field::new(Mode::Public, two);
        candidate += Field::new(Mode::Private, two);
    });

    c.bench_function("to_value", move |b| {
        b.iter(|| {
            let _value = candidate.eject_value();
        })
    });
}

fn debug(c: &mut Criterion) {
    let one = snarkvm_console_types::Field::<<Circuit as Environment>::Network>::one();
    let two = one + one;

    let mut candidate = Field::<Circuit>::one();
    (0..500_000).for_each(|_| {
        candidate += Field::new(Mode::Constant, two);
        candidate += Field::new(Mode::Public, two);
        candidate += Field::new(Mode::Private, two);
    });

    c.bench_function("debug", move |b| {
        b.iter(|| {
            let _value = format!("{:?}", LinearCombination::from(&candidate));
        })
    });
}

criterion_group! {
    name = linear_combination;
    config = Criterion::default().sample_size(10);
    targets = add, to_value, debug
}

criterion_main!(linear_combination);
