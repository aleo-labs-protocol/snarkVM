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

use criterion::Criterion;
use snarkvm_console_network::{MainnetV0, environment::prelude::*};
use snarkvm_console_types::{Field, Group};

type CurrentNetwork = MainnetV0;

fn group_from_field(c: &mut Criterion) {
    let rng = &mut TestRng::default();

    c.bench_function("group_from_field", move |b| {
        let fields: Vec<Field<CurrentNetwork>> = (0..1000).map(|_| rng.random()).collect();

        b.iter(|| {
            for field in &fields {
                let group = Group::from_field(field);
                let _ = std::hint::black_box(group);
            }
        })
    });
}

fn group_from_field_on_curve(c: &mut Criterion) {
    let rng = &mut TestRng::default();

    c.bench_function("group_from_field_on_curve", move |b| {
        type Projective = <CurrentNetwork as Environment>::Projective;

        let fields: Vec<Field<CurrentNetwork>> =
            (0..1000).map(|_| rng.random::<Projective>().to_affine().to_x_coordinate()).map(Field::new).collect();

        b.iter(|| {
            for field in &fields {
                let group = Group::from_field(field);
                let _ = std::hint::black_box(group);
            }
        })
    });
}

fn group_from_field_off_curve(c: &mut Criterion) {
    let rng = &mut TestRng::default();

    c.bench_function("group_from_field_off_curve", move |b| {
        type Affine = <CurrentNetwork as Environment>::Affine;

        let fields: Vec<_> = std::iter::repeat(())
            .map(|_| rng.random::<Field<CurrentNetwork>>())
            .filter(|&field| Affine::from_x_coordinate(*field, true).is_none())
            .take(1000)
            .collect();

        b.iter(|| {
            for field in &fields {
                let group = Group::from_field(field);
                let _ = std::hint::black_box(group);
            }
        })
    });
}

criterion_group! {
    name = group;
    config = Criterion::default().sample_size(10);
    targets = group_from_field, group_from_field_on_curve, group_from_field_off_curve
}

criterion_main!(group);
