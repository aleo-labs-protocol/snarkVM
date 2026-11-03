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

use snarkvm_console_algorithms::{ECDSASignature, Keccak256, Keccak384, Keccak512};
use snarkvm_console_types::prelude::*;
use snarkvm_utilities::{TestRng, Uniform};

use k256::{
    ecdsa::{SigningKey, VerifyingKey},
    elliptic_curve::Generate,
};

use criterion::Criterion;

fn ecdsa_keccak256(c: &mut Criterion) {
    let rng = &mut TestRng::default();
    let hasher = Keccak256::default();

    // Sample a random signing key.
    let signing_key = SigningKey::generate_from_rng(rng);
    let vk = VerifyingKey::from(&signing_key);

    // Sample a random message.
    let message: Vec<u8> = (0..256).map(|_| u8::rand(rng)).collect::<Vec<_>>();
    let message_bits = message.to_bits_le();

    // Sign the message.
    let signature = ECDSASignature::sign(&signing_key, &hasher, &message_bits).unwrap();

    c.bench_function(&format!("ECDSA (Keccak256) verify - input size {}", message.len()), |b| {
        b.iter(|| signature.verify(&vk, &hasher, &message_bits).unwrap())
    });
    let eth_address = ECDSASignature::ethereum_address_from_public_key(&vk).unwrap();
    c.bench_function(&format!("ECDSA (Keccak256) ETH verify - input size {}", message.len()), |b| {
        b.iter(|| signature.verify_ethereum(&eth_address, &hasher, &message_bits).unwrap())
    });
}

fn ecdsa_keccak384(c: &mut Criterion) {
    let rng = &mut TestRng::default();
    let hasher = Keccak384::default();

    // Sample a random signing key.
    let signing_key = SigningKey::generate_from_rng(rng);
    let vk = VerifyingKey::from(&signing_key);

    // Sample a random message.
    let message: Vec<u8> = (0..256).map(|_| u8::rand(rng)).collect::<Vec<_>>();
    let message_bits = message.to_bits_le();

    // Sign the message.
    let signature = ECDSASignature::sign(&signing_key, &hasher, &message_bits).unwrap();

    c.bench_function(&format!("ECDSA (Keccak384) verify - input size {}", message.len()), |b| {
        b.iter(|| signature.verify(&vk, &hasher, &message_bits).unwrap())
    });
    let eth_address = ECDSASignature::ethereum_address_from_public_key(&vk).unwrap();
    c.bench_function(&format!("ECDSA (Keccak384) ETH verify - input size {}", message.len()), |b| {
        b.iter(|| signature.verify_ethereum(&eth_address, &hasher, &message_bits).unwrap())
    });
}

fn ecdsa_keccak512(c: &mut Criterion) {
    let rng = &mut TestRng::default();
    let hasher = Keccak512::default();

    // Sample a random signing key.
    let signing_key = SigningKey::generate_from_rng(rng);
    let vk = VerifyingKey::from(&signing_key);

    // Sample a random message.
    let message: Vec<u8> = (0..256).map(|_| u8::rand(rng)).collect::<Vec<_>>();
    let message_bits = message.to_bits_le();

    // Sign the message.
    let signature = ECDSASignature::sign(&signing_key, &hasher, &message_bits).unwrap();

    c.bench_function(&format!("ECDSA (Keccak512) verify - input size {}", message.len()), |b| {
        b.iter(|| signature.verify(&vk, &hasher, &message_bits).unwrap())
    });
    let eth_address = ECDSASignature::ethereum_address_from_public_key(&vk).unwrap();
    c.bench_function(&format!("ECDSA (Keccak512) ETH verify - input size {}", message.len()), |b| {
        b.iter(|| signature.verify_ethereum(&eth_address, &hasher, &message_bits).unwrap())
    });
}

criterion_group! {
    name = keccak;
    config = Criterion::default().sample_size(1000);
    targets = ecdsa_keccak256, ecdsa_keccak384, ecdsa_keccak512
}

criterion_main!(keccak);
