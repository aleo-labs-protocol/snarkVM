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

use criterion::{criterion_group, criterion_main};

mod bls12_377;

criterion_group!(
    bls12_377_ec,
    bls12_377::ec::g1::bench_g1_rand,
    bls12_377::ec::g1::bench_g1_mul_assign,
    bls12_377::ec::g1::bench_g1_add_assign,
    bls12_377::ec::g1::bench_g1_add_assign_mixed,
    bls12_377::ec::g1::bench_g1_double,
    bls12_377::ec::g1::bench_g1_check_subgroup_membership,
    bls12_377::ec::g2::bench_g2_rand,
    bls12_377::ec::g2::bench_g2_mul_assign,
    bls12_377::ec::g2::bench_g2_add_assign,
    bls12_377::ec::g2::bench_g2_add_assign_mixed,
    bls12_377::ec::g2::bench_g2_double,
);

criterion_group!(
    bls12_377_fq,
    bls12_377::fq::bench_fq_repr_add_nocarry,
    bls12_377::fq::bench_fq_repr_sub_noborrow,
    bls12_377::fq::bench_fq_repr_num_bits,
    bls12_377::fq::bench_fq_repr_mul2,
    bls12_377::fq::bench_fq_repr_div2,
    bls12_377::fq::bench_fq_add_assign,
    bls12_377::fq::bench_fq_sub_assign,
    bls12_377::fq::bench_fq_mul_assign,
    bls12_377::fq::bench_fq_double,
    bls12_377::fq::bench_fq_square,
    bls12_377::fq::bench_fq_inverse,
    bls12_377::fq::bench_fq_negate,
    bls12_377::fq::bench_fq_sqrt,
    bls12_377::fq::bench_fq_to_bigint,
    bls12_377::fq::bench_fq_from_bigint,
);

criterion_group!(
    bls12_377_fq12,
    bls12_377::fq12::bench_fq12_add_assign,
    bls12_377::fq12::bench_fq12_sub_assign,
    bls12_377::fq12::bench_fq12_mul_assign,
    bls12_377::fq12::bench_fq12_double,
    bls12_377::fq12::bench_fq12_square,
    bls12_377::fq12::bench_fq12_inverse,
    bls12_377::fq12::bench_fq12_cyclotomic_square,
    bls12_377::fq12::bench_fq12_cyclotomic_exp_x,
);

criterion_group!(
    bls12_377_fq2,
    bls12_377::fq2::bench_fq2_add_assign,
    bls12_377::fq2::bench_fq2_sub_assign,
    bls12_377::fq2::bench_fq2_mul_assign,
    bls12_377::fq2::bench_fq2_double,
    bls12_377::fq2::bench_fq2_square,
    bls12_377::fq2::bench_fq2_inverse,
    bls12_377::fq2::bench_fq2_sqrt,
);

criterion_group!(
    bls12_377_fr,
    bls12_377::fr::bench_fr_repr_add_nocarry,
    bls12_377::fr::bench_fr_repr_sub_noborrow,
    bls12_377::fr::bench_fr_repr_num_bits,
    bls12_377::fr::bench_fr_repr_mul2,
    bls12_377::fr::bench_fr_repr_div2,
    bls12_377::fr::bench_fr_add_assign,
    bls12_377::fr::bench_fr_sub_assign,
    bls12_377::fr::bench_fr_mul_assign,
    bls12_377::fr::bench_fr_double,
    bls12_377::fr::bench_fr_square,
    bls12_377::fr::bench_fr_inverse,
    bls12_377::fr::bench_fr_negate,
    bls12_377::fr::bench_fr_sqrt,
    bls12_377::fr::bench_fr_to_bigint,
    bls12_377::fr::bench_fr_from_bigint,
);

criterion_group!(
    bls12_377_pairing,
    bls12_377::pairing::bench_pairing_miller_loop,
    bls12_377::pairing::bench_pairing_final_exponentiation,
    bls12_377::pairing::bench_pairing_full,
    bls12_377::pairing::bench_pairing_miller_loop_6,
);

criterion_main!(bls12_377_ec, bls12_377_fq, bls12_377_fq12, bls12_377_fq2, bls12_377_fr, bls12_377_pairing,);
