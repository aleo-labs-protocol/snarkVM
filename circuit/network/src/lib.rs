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

#![forbid(unsafe_code)]
#![allow(clippy::too_many_arguments)]
#![warn(clippy::cast_possible_truncation)]

extern crate snarkvm_console_network as console;

pub mod canary_v0;
pub use canary_v0::*;

pub mod testnet_v0;
pub use testnet_v0::*;

pub mod v0;
pub use v0::*;

use snarkvm_circuit_collections::merkle_tree::MerklePath;
use snarkvm_circuit_types::{Boolean, Field, Group, Scalar, environment::Environment};

// Note: The functions of this trait are not thread safe.
pub trait Aleo: Environment {
    /// The maximum number of field elements in data (must not exceed u16::MAX).
    const MAX_DATA_SIZE_IN_FIELDS: u32 = <Self::Network as console::Network>::MAX_DATA_SIZE_IN_FIELDS;

    /// Initializes the global constants for the Aleo environment.
    fn initialize_global_constants();

    /// Returns the commitment domain as a constant field element.
    fn commitment_domain() -> Field<Self>;

    /// Returns the encryption domain as a constant field element.
    fn encryption_domain() -> Field<Self>;

    /// Returns the graph key domain as a constant field element.
    fn graph_key_domain() -> Field<Self>;

    /// Returns the serial number domain as a constant field element.
    fn serial_number_domain() -> Field<Self>;

    /// Returns the powers of `G`.
    fn g_powers() -> Vec<Group<Self>>;

    /// Returns the scalar multiplication on the generator `G`.
    fn g_scalar_multiply(scalar: &Scalar<Self>) -> Group<Self>;

    /// Returns a BHP commitment with an input hasher of 256-bits.
    fn commit_bhp256(input: &[Boolean<Self>], randomizer: &Scalar<Self>) -> Field<Self>;

    /// Returns a BHP commitment with an input hasher of 512-bits.
    fn commit_bhp512(input: &[Boolean<Self>], randomizer: &Scalar<Self>) -> Field<Self>;

    /// Returns a BHP commitment with an input hasher of 768-bits.
    fn commit_bhp768(input: &[Boolean<Self>], randomizer: &Scalar<Self>) -> Field<Self>;

    /// Returns a BHP commitment with an input hasher of 1024-bits.
    fn commit_bhp1024(input: &[Boolean<Self>], randomizer: &Scalar<Self>) -> Field<Self>;

    /// Returns a Pedersen commitment for the given (up to) 64-bit input and randomizer.
    fn commit_ped64(input: &[Boolean<Self>], randomizer: &Scalar<Self>) -> Field<Self>;

    /// Returns a Pedersen commitment for the given (up to) 128-bit input and randomizer.
    fn commit_ped128(input: &[Boolean<Self>], randomizer: &Scalar<Self>) -> Field<Self>;

    /// Returns a BHP commitment with an input hasher of 256-bits.
    fn commit_to_group_bhp256(input: &[Boolean<Self>], randomizer: &Scalar<Self>) -> Group<Self>;

    /// Returns a BHP commitment with an input hasher of 512-bits.
    fn commit_to_group_bhp512(input: &[Boolean<Self>], randomizer: &Scalar<Self>) -> Group<Self>;

    /// Returns a BHP commitment with an input hasher of 768-bits.
    fn commit_to_group_bhp768(input: &[Boolean<Self>], randomizer: &Scalar<Self>) -> Group<Self>;

    /// Returns a BHP commitment with an input hasher of 1024-bits.
    fn commit_to_group_bhp1024(input: &[Boolean<Self>], randomizer: &Scalar<Self>) -> Group<Self>;

    /// Returns a Pedersen commitment for the given (up to) 64-bit input and randomizer.
    fn commit_to_group_ped64(input: &[Boolean<Self>], randomizer: &Scalar<Self>) -> Group<Self>;

    /// Returns a Pedersen commitment for the given (up to) 128-bit input and randomizer.
    fn commit_to_group_ped128(input: &[Boolean<Self>], randomizer: &Scalar<Self>) -> Group<Self>;

    /// Returns the BHP hash with an input hasher of 256-bits.
    fn hash_bhp256(input: &[Boolean<Self>]) -> Field<Self>;

    /// Returns the BHP hash with an input hasher of 512-bits.
    fn hash_bhp512(input: &[Boolean<Self>]) -> Field<Self>;

    /// Returns the BHP hash with an input hasher of 768-bits.
    fn hash_bhp768(input: &[Boolean<Self>]) -> Field<Self>;

    /// Returns the BHP hash with an input hasher of 1024-bits.
    fn hash_bhp1024(input: &[Boolean<Self>]) -> Field<Self>;

    /// Returns the Keccak hash with a 256-bit output.
    fn hash_keccak256(input: &[Boolean<Self>]) -> Vec<Boolean<Self>>;

    /// Returns the Keccak hash with a 384-bit output.
    fn hash_keccak384(input: &[Boolean<Self>]) -> Vec<Boolean<Self>>;

    /// Returns the Keccak hash with a 512-bit output.
    fn hash_keccak512(input: &[Boolean<Self>]) -> Vec<Boolean<Self>>;

    /// Returns the Pedersen hash for a given (up to) 64-bit input.
    fn hash_ped64(input: &[Boolean<Self>]) -> Field<Self>;

    /// Returns the Pedersen hash for a given (up to) 128-bit input.
    fn hash_ped128(input: &[Boolean<Self>]) -> Field<Self>;

    /// Returns the Poseidon hash with an input rate of 2.
    fn hash_psd2(input: &[Field<Self>]) -> Field<Self>;

    /// Returns the Poseidon hash with an input rate of 4.
    fn hash_psd4(input: &[Field<Self>]) -> Field<Self>;

    /// Returns the Poseidon hash with an input rate of 8.
    fn hash_psd8(input: &[Field<Self>]) -> Field<Self>;

    /// Returns the SHA-3 hash with a 256-bit output.
    fn hash_sha3_256(input: &[Boolean<Self>]) -> Vec<Boolean<Self>>;

    /// Returns the SHA-3 hash with a 384-bit output.
    fn hash_sha3_384(input: &[Boolean<Self>]) -> Vec<Boolean<Self>>;

    /// Returns the SHA-3 hash with a 512-bit output.
    fn hash_sha3_512(input: &[Boolean<Self>]) -> Vec<Boolean<Self>>;

    /// Returns the extended Poseidon hash with an input rate of 2.
    fn hash_many_psd2(input: &[Field<Self>], num_outputs: u16) -> Vec<Field<Self>>;

    /// Returns the extended Poseidon hash with an input rate of 4.
    fn hash_many_psd4(input: &[Field<Self>], num_outputs: u16) -> Vec<Field<Self>>;

    /// Returns the extended Poseidon hash with an input rate of 8.
    fn hash_many_psd8(input: &[Field<Self>], num_outputs: u16) -> Vec<Field<Self>>;

    /// Returns the BHP hash with an input hasher of 256-bits.
    fn hash_to_group_bhp256(input: &[Boolean<Self>]) -> Group<Self>;

    /// Returns the BHP hash with an input hasher of 512-bits.
    fn hash_to_group_bhp512(input: &[Boolean<Self>]) -> Group<Self>;

    /// Returns the BHP hash with an input hasher of 768-bits.
    fn hash_to_group_bhp768(input: &[Boolean<Self>]) -> Group<Self>;

    /// Returns the BHP hash with an input hasher of 1024-bits.
    fn hash_to_group_bhp1024(input: &[Boolean<Self>]) -> Group<Self>;

    /// Returns the Pedersen hash for a given (up to) 64-bit input.
    fn hash_to_group_ped64(input: &[Boolean<Self>]) -> Group<Self>;

    /// Returns the Pedersen hash for a given (up to) 128-bit input.
    fn hash_to_group_ped128(input: &[Boolean<Self>]) -> Group<Self>;

    /// Returns the Poseidon hash with an input rate of 2 on the affine curve.
    fn hash_to_group_psd2(input: &[Field<Self>]) -> Group<Self>;

    /// Returns the Poseidon hash with an input rate of 4 on the affine curve.
    fn hash_to_group_psd4(input: &[Field<Self>]) -> Group<Self>;

    /// Returns the Poseidon hash with an input rate of 8 on the affine curve.
    fn hash_to_group_psd8(input: &[Field<Self>]) -> Group<Self>;

    /// Returns the Poseidon hash with an input rate of 2 on the scalar field.
    fn hash_to_scalar_psd2(input: &[Field<Self>]) -> Scalar<Self>;

    /// Returns the Poseidon hash with an input rate of 4 on the scalar field.
    fn hash_to_scalar_psd4(input: &[Field<Self>]) -> Scalar<Self>;

    /// Returns the Poseidon hash with an input rate of 8 on the scalar field.
    fn hash_to_scalar_psd8(input: &[Field<Self>]) -> Scalar<Self>;

    /// Returns `true` if the given Merkle path is valid for the given root and leaf.
    #[allow(clippy::ptr_arg)]
    fn verify_merkle_path_bhp<const DEPTH: u8>(
        path: &MerklePath<Self, DEPTH>,
        root: &Field<Self>,
        leaf: &Vec<Boolean<Self>>,
    ) -> Boolean<Self>;

    /// Returns `true` if the given Merkle path is valid for the given root and leaf.
    #[allow(clippy::ptr_arg)]
    fn verify_merkle_path_psd<const DEPTH: u8>(
        path: &MerklePath<Self, DEPTH>,
        root: &Field<Self>,
        leaf: &Vec<Field<Self>>,
    ) -> Boolean<Self>;
}
