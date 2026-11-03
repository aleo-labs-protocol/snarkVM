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

use crate::Aleo;
use snarkvm_circuit_algorithms::{
    BHP256,
    BHP512,
    BHP768,
    BHP1024,
    Commit,
    CommitUncompressed,
    Hash,
    HashMany,
    HashToGroup,
    HashToScalar,
    HashUncompressed,
    Keccak256,
    Keccak384,
    Keccak512,
    Pedersen64,
    Pedersen128,
    Poseidon2,
    Poseidon4,
    Poseidon8,
    Sha3_256,
    Sha3_384,
    Sha3_512,
};
use snarkvm_circuit_collections::merkle_tree::MerklePath;
use snarkvm_circuit_types::{
    Boolean,
    Field,
    Group,
    Scalar,
    environment::{Assignment, R1CS, TestnetCircuit, prelude::*},
};

use core::fmt;

type E = TestnetCircuit;

thread_local! {
    /// The group bases for the Aleo signature and encryption schemes.
    static GENERATOR_G: Vec<Group<AleoTestnetV0>> = Vec::constant(<console::TestnetV0 as console::Network>::g_powers().to_vec());

    /// The commitment domain as a constant field element.
    static COMMITMENT_DOMAIN: Field<AleoTestnetV0> = Field::constant(<console::TestnetV0 as console::Network>::commitment_domain());
    /// The encryption domain as a constant field element.
    static ENCRYPTION_DOMAIN: Field<AleoTestnetV0> = Field::constant(<console::TestnetV0 as console::Network>::encryption_domain());
    /// The graph key domain as a constant field element.
    static GRAPH_KEY_DOMAIN: Field<AleoTestnetV0> = Field::constant(<console::TestnetV0 as console::Network>::graph_key_domain());
    /// The serial number domain as a constant field element.
    static SERIAL_NUMBER_DOMAIN: Field<AleoTestnetV0> = Field::constant(<console::TestnetV0 as console::Network>::serial_number_domain());

    /// The BHP hash function, which can take an input of up to 256 bits.
    static BHP_256: BHP256<AleoTestnetV0> = BHP256::<AleoTestnetV0>::constant(console::TESTNET_BHP_256.clone());
    /// The BHP hash function, which can take an input of up to 512 bits.
    static BHP_512: BHP512<AleoTestnetV0> = BHP512::<AleoTestnetV0>::constant(console::TESTNET_BHP_512.clone());
    /// The BHP hash function, which can take an input of up to 768 bits.
    static BHP_768: BHP768<AleoTestnetV0> = BHP768::<AleoTestnetV0>::constant(console::TESTNET_BHP_768.clone());
    /// The BHP hash function, which can take an input of up to 1024 bits.
    static BHP_1024: BHP1024<AleoTestnetV0> = BHP1024::<AleoTestnetV0>::constant(console::TESTNET_BHP_1024.clone());

    /// The Keccak hash function, which outputs 256 bits.
    static KECCAK_256: Keccak256<AleoTestnetV0> = Keccak256::<AleoTestnetV0>::new();
    /// The Keccak hash function, which outputs 384 bits.
    static KECCAK_384: Keccak384<AleoTestnetV0> = Keccak384::<AleoTestnetV0>::new();
    /// The Keccak hash function, which outputs 512 bits.
    static KECCAK_512: Keccak512<AleoTestnetV0> = Keccak512::<AleoTestnetV0>::new();

    /// The Pedersen hash function, which can take an input of up to 64 bits.
    static PEDERSEN_64: Pedersen64<AleoTestnetV0> = Pedersen64::<AleoTestnetV0>::constant(console::TESTNET_PEDERSEN_64.clone());
    /// The Pedersen hash function, which can take an input of up to 128 bits.
    static PEDERSEN_128: Pedersen128<AleoTestnetV0> = Pedersen128::<AleoTestnetV0>::constant(console::TESTNET_PEDERSEN_128.clone());

    /// The Poseidon hash function, using a rate of 2.
    static POSEIDON_2: Poseidon2<AleoTestnetV0> = Poseidon2::<AleoTestnetV0>::constant(console::TESTNET_POSEIDON_2.clone());
    /// The Poseidon hash function, using a rate of 4.
    static POSEIDON_4: Poseidon4<AleoTestnetV0> = Poseidon4::<AleoTestnetV0>::constant(console::TESTNET_POSEIDON_4.clone());
    /// The Poseidon hash function, using a rate of 8.
    static POSEIDON_8: Poseidon8<AleoTestnetV0> = Poseidon8::<AleoTestnetV0>::constant(console::TESTNET_POSEIDON_8.clone());

    /// The SHA-3 hash function, which outputs 256 bits.
    static SHA3_256: Sha3_256<AleoTestnetV0> = Sha3_256::<AleoTestnetV0>::new();
    /// The SHA-3 hash function, which outputs 384 bits.
    static SHA3_384: Sha3_384<AleoTestnetV0> = Sha3_384::<AleoTestnetV0>::new();
    /// The SHA-3 hash function, which outputs 512 bits.
    static SHA3_512: Sha3_512<AleoTestnetV0> = Sha3_512::<AleoTestnetV0>::new();
}

#[derive(Copy, Clone, Debug, Eq, PartialEq, Hash)]
pub struct AleoTestnetV0;

impl Aleo for AleoTestnetV0 {
    /// Initializes the global constants for the Aleo environment.
    fn initialize_global_constants() {
        GENERATOR_G.with(|_| ());
        COMMITMENT_DOMAIN.with(|_| ());
        ENCRYPTION_DOMAIN.with(|_| ());
        GRAPH_KEY_DOMAIN.with(|_| ());
        SERIAL_NUMBER_DOMAIN.with(|_| ());
        BHP_256.with(|_| ());
        BHP_512.with(|_| ());
        BHP_768.with(|_| ());
        BHP_1024.with(|_| ());
        KECCAK_256.with(|_| ());
        KECCAK_384.with(|_| ());
        KECCAK_512.with(|_| ());
        PEDERSEN_64.with(|_| ());
        PEDERSEN_128.with(|_| ());
        POSEIDON_2.with(|_| ());
        POSEIDON_4.with(|_| ());
        POSEIDON_8.with(|_| ());
        SHA3_256.with(|_| ());
        SHA3_384.with(|_| ());
        SHA3_512.with(|_| ());
    }

    /// Returns the commitment domain as a constant field element.
    fn commitment_domain() -> Field<Self> {
        COMMITMENT_DOMAIN.with(|domain| domain.clone())
    }

    /// Returns the encryption domain as a constant field element.
    fn encryption_domain() -> Field<Self> {
        ENCRYPTION_DOMAIN.with(|domain| domain.clone())
    }

    /// Returns the graph key domain as a constant field element.
    fn graph_key_domain() -> Field<Self> {
        GRAPH_KEY_DOMAIN.with(|domain| domain.clone())
    }

    /// Returns the serial number domain as a constant field element.
    fn serial_number_domain() -> Field<Self> {
        SERIAL_NUMBER_DOMAIN.with(|domain| domain.clone())
    }

    /// Returns the powers of `G`.
    fn g_powers() -> Vec<Group<Self>> {
        GENERATOR_G.with(|g| g.clone())
    }

    /// Returns the scalar multiplication on the generator `G`.
    #[inline]
    fn g_scalar_multiply(scalar: &Scalar<Self>) -> Group<Self> {
        GENERATOR_G.with(|bases| {
            bases
                .iter()
                .zip_eq(&scalar.to_bits_le())
                .fold(Group::zero(), |output, (base, bit)| Group::ternary(bit, &(&output + base), &output))
        })
    }

    /// Returns a BHP commitment with an input hasher of 256-bits.
    fn commit_bhp256(input: &[Boolean<Self>], randomizer: &Scalar<Self>) -> Field<Self> {
        BHP_256.with(|bhp| bhp.commit(input, randomizer))
    }

    /// Returns a BHP commitment with an input hasher of 512-bits.
    fn commit_bhp512(input: &[Boolean<Self>], randomizer: &Scalar<Self>) -> Field<Self> {
        BHP_512.with(|bhp| bhp.commit(input, randomizer))
    }

    /// Returns a BHP commitment with an input hasher of 768-bits.
    fn commit_bhp768(input: &[Boolean<Self>], randomizer: &Scalar<Self>) -> Field<Self> {
        BHP_768.with(|bhp| bhp.commit(input, randomizer))
    }

    /// Returns a BHP commitment with an input hasher of 1024-bits.
    fn commit_bhp1024(input: &[Boolean<Self>], randomizer: &Scalar<Self>) -> Field<Self> {
        BHP_1024.with(|bhp| bhp.commit(input, randomizer))
    }

    /// Returns a Pedersen commitment for the given (up to) 64-bit input and randomizer.
    fn commit_ped64(input: &[Boolean<Self>], randomizer: &Scalar<Self>) -> Field<Self> {
        PEDERSEN_64.with(|pedersen| pedersen.commit(input, randomizer))
    }

    /// Returns a Pedersen commitment for the given (up to) 128-bit input and randomizer.
    fn commit_ped128(input: &[Boolean<Self>], randomizer: &Scalar<Self>) -> Field<Self> {
        PEDERSEN_128.with(|pedersen| pedersen.commit(input, randomizer))
    }

    /// Returns a BHP commitment with an input hasher of 256-bits.
    fn commit_to_group_bhp256(input: &[Boolean<Self>], randomizer: &Scalar<Self>) -> Group<Self> {
        BHP_256.with(|bhp| bhp.commit_uncompressed(input, randomizer))
    }

    /// Returns a BHP commitment with an input hasher of 512-bits.
    fn commit_to_group_bhp512(input: &[Boolean<Self>], randomizer: &Scalar<Self>) -> Group<Self> {
        BHP_512.with(|bhp| bhp.commit_uncompressed(input, randomizer))
    }

    /// Returns a BHP commitment with an input hasher of 768-bits.
    fn commit_to_group_bhp768(input: &[Boolean<Self>], randomizer: &Scalar<Self>) -> Group<Self> {
        BHP_768.with(|bhp| bhp.commit_uncompressed(input, randomizer))
    }

    /// Returns a BHP commitment with an input hasher of 1024-bits.
    fn commit_to_group_bhp1024(input: &[Boolean<Self>], randomizer: &Scalar<Self>) -> Group<Self> {
        BHP_1024.with(|bhp| bhp.commit_uncompressed(input, randomizer))
    }

    /// Returns a Pedersen commitment for the given (up to) 64-bit input and randomizer.
    fn commit_to_group_ped64(input: &[Boolean<Self>], randomizer: &Scalar<Self>) -> Group<Self> {
        PEDERSEN_64.with(|pedersen| pedersen.commit_uncompressed(input, randomizer))
    }

    /// Returns a Pedersen commitment for the given (up to) 128-bit input and randomizer.
    fn commit_to_group_ped128(input: &[Boolean<Self>], randomizer: &Scalar<Self>) -> Group<Self> {
        PEDERSEN_128.with(|pedersen| pedersen.commit_uncompressed(input, randomizer))
    }

    /// Returns the BHP hash with an input hasher of 256-bits.
    fn hash_bhp256(input: &[Boolean<Self>]) -> Field<Self> {
        BHP_256.with(|bhp| bhp.hash(input))
    }

    /// Returns the BHP hash with an input hasher of 512-bits.
    fn hash_bhp512(input: &[Boolean<Self>]) -> Field<Self> {
        BHP_512.with(|bhp| bhp.hash(input))
    }

    /// Returns the BHP hash with an input hasher of 768-bits.
    fn hash_bhp768(input: &[Boolean<Self>]) -> Field<Self> {
        BHP_768.with(|bhp| bhp.hash(input))
    }

    /// Returns the BHP hash with an input hasher of 1024-bits.
    fn hash_bhp1024(input: &[Boolean<Self>]) -> Field<Self> {
        BHP_1024.with(|bhp| bhp.hash(input))
    }

    /// Returns the Keccak hash with a 256-bit output.
    fn hash_keccak256(input: &[Boolean<Self>]) -> Vec<Boolean<Self>> {
        KECCAK_256.with(|keccak| keccak.hash(input))
    }

    /// Returns the Keccak hash with a 384-bit output.
    fn hash_keccak384(input: &[Boolean<Self>]) -> Vec<Boolean<Self>> {
        KECCAK_384.with(|keccak| keccak.hash(input))
    }

    /// Returns the Keccak hash with a 512-bit output.
    fn hash_keccak512(input: &[Boolean<Self>]) -> Vec<Boolean<Self>> {
        KECCAK_512.with(|keccak| keccak.hash(input))
    }

    /// Returns the Pedersen hash for a given (up to) 64-bit input.
    fn hash_ped64(input: &[Boolean<Self>]) -> Field<Self> {
        PEDERSEN_64.with(|pedersen| pedersen.hash(input))
    }

    /// Returns the Pedersen hash for a given (up to) 128-bit input.
    fn hash_ped128(input: &[Boolean<Self>]) -> Field<Self> {
        PEDERSEN_128.with(|pedersen| pedersen.hash(input))
    }

    /// Returns the Poseidon hash with an input rate of 2.
    fn hash_psd2(input: &[Field<Self>]) -> Field<Self> {
        POSEIDON_2.with(|poseidon| poseidon.hash(input))
    }

    /// Returns the Poseidon hash with an input rate of 4.
    fn hash_psd4(input: &[Field<Self>]) -> Field<Self> {
        POSEIDON_4.with(|poseidon| poseidon.hash(input))
    }

    /// Returns the Poseidon hash with an input rate of 8.
    fn hash_psd8(input: &[Field<Self>]) -> Field<Self> {
        POSEIDON_8.with(|poseidon| poseidon.hash(input))
    }

    /// Returns the SHA-3 hash with a 256-bit output.
    fn hash_sha3_256(input: &[Boolean<Self>]) -> Vec<Boolean<Self>> {
        SHA3_256.with(|sha3| sha3.hash(input))
    }

    /// Returns the SHA-3 hash with a 384-bit output.
    fn hash_sha3_384(input: &[Boolean<Self>]) -> Vec<Boolean<Self>> {
        SHA3_384.with(|sha3| sha3.hash(input))
    }

    /// Returns the SHA-3 hash with a 512-bit output.
    fn hash_sha3_512(input: &[Boolean<Self>]) -> Vec<Boolean<Self>> {
        SHA3_512.with(|sha3| sha3.hash(input))
    }

    /// Returns the extended Poseidon hash with an input rate of 2.
    fn hash_many_psd2(input: &[Field<Self>], num_outputs: u16) -> Vec<Field<Self>> {
        POSEIDON_2.with(|poseidon| poseidon.hash_many(input, num_outputs))
    }

    /// Returns the extended Poseidon hash with an input rate of 4.
    fn hash_many_psd4(input: &[Field<Self>], num_outputs: u16) -> Vec<Field<Self>> {
        POSEIDON_4.with(|poseidon| poseidon.hash_many(input, num_outputs))
    }

    /// Returns the extended Poseidon hash with an input rate of 8.
    fn hash_many_psd8(input: &[Field<Self>], num_outputs: u16) -> Vec<Field<Self>> {
        POSEIDON_8.with(|poseidon| poseidon.hash_many(input, num_outputs))
    }

    /// Returns the BHP hash with an input hasher of 256-bits.
    fn hash_to_group_bhp256(input: &[Boolean<Self>]) -> Group<Self> {
        BHP_256.with(|bhp| bhp.hash_uncompressed(input))
    }

    /// Returns the BHP hash with an input hasher of 512-bits.
    fn hash_to_group_bhp512(input: &[Boolean<Self>]) -> Group<Self> {
        BHP_512.with(|bhp| bhp.hash_uncompressed(input))
    }

    /// Returns the BHP hash with an input hasher of 768-bits.
    fn hash_to_group_bhp768(input: &[Boolean<Self>]) -> Group<Self> {
        BHP_768.with(|bhp| bhp.hash_uncompressed(input))
    }

    /// Returns the BHP hash with an input hasher of 1024-bits.
    fn hash_to_group_bhp1024(input: &[Boolean<Self>]) -> Group<Self> {
        BHP_1024.with(|bhp| bhp.hash_uncompressed(input))
    }

    /// Returns the Pedersen hash for a given (up to) 64-bit input.
    fn hash_to_group_ped64(input: &[Boolean<Self>]) -> Group<Self> {
        PEDERSEN_64.with(|pedersen| pedersen.hash_uncompressed(input))
    }

    /// Returns the Pedersen hash for a given (up to) 128-bit input.
    fn hash_to_group_ped128(input: &[Boolean<Self>]) -> Group<Self> {
        PEDERSEN_128.with(|pedersen| pedersen.hash_uncompressed(input))
    }

    /// Returns the Poseidon hash with an input rate of 2 on the affine curve.
    fn hash_to_group_psd2(input: &[Field<Self>]) -> Group<Self> {
        POSEIDON_2.with(|poseidon| poseidon.hash_to_group(input))
    }

    /// Returns the Poseidon hash with an input rate of 4 on the affine curve.
    fn hash_to_group_psd4(input: &[Field<Self>]) -> Group<Self> {
        POSEIDON_4.with(|poseidon| poseidon.hash_to_group(input))
    }

    /// Returns the Poseidon hash with an input rate of 8 on the affine curve.
    fn hash_to_group_psd8(input: &[Field<Self>]) -> Group<Self> {
        POSEIDON_8.with(|poseidon| poseidon.hash_to_group(input))
    }

    /// Returns the Poseidon hash with an input rate of 2 on the scalar field.
    fn hash_to_scalar_psd2(input: &[Field<Self>]) -> Scalar<Self> {
        POSEIDON_2.with(|poseidon| poseidon.hash_to_scalar(input))
    }

    /// Returns the Poseidon hash with an input rate of 4 on the scalar field.
    fn hash_to_scalar_psd4(input: &[Field<Self>]) -> Scalar<Self> {
        POSEIDON_4.with(|poseidon| poseidon.hash_to_scalar(input))
    }

    /// Returns the Poseidon hash with an input rate of 8 on the scalar field.
    fn hash_to_scalar_psd8(input: &[Field<Self>]) -> Scalar<Self> {
        POSEIDON_8.with(|poseidon| poseidon.hash_to_scalar(input))
    }

    /// Returns `true` if the given Merkle path is valid for the given root and leaf.
    fn verify_merkle_path_bhp<const DEPTH: u8>(
        path: &MerklePath<Self, DEPTH>,
        root: &Field<Self>,
        leaf: &Vec<Boolean<Self>>,
    ) -> Boolean<Self> {
        BHP_1024.with(|bhp1024| BHP_512.with(|bhp512| path.verify(bhp1024, bhp512, root, leaf)))
    }

    /// Returns `true` if the given Merkle path is valid for the given root and leaf.
    fn verify_merkle_path_psd<const DEPTH: u8>(
        path: &MerklePath<Self, DEPTH>,
        root: &Field<Self>,
        leaf: &Vec<Field<Self>>,
    ) -> Boolean<Self> {
        POSEIDON_4.with(|psd4| POSEIDON_2.with(|psd2| path.verify(psd4, psd2, root, leaf)))
    }
}

impl Environment for AleoTestnetV0 {
    type Affine = <E as Environment>::Affine;
    type BaseField = <E as Environment>::BaseField;
    type Network = <E as Environment>::Network;
    type ScalarField = <E as Environment>::ScalarField;

    /// Returns the `zero` constant.
    fn zero() -> LinearCombination<Self::BaseField> {
        E::zero()
    }

    /// Returns the `one` constant.
    fn one() -> LinearCombination<Self::BaseField> {
        E::one()
    }

    /// Returns a new variable of the given mode and value.
    fn new_variable(mode: Mode, value: Self::BaseField) -> Variable<Self::BaseField> {
        E::new_variable(mode, value)
    }

    /// Returns a new witness of the given mode and value.
    fn new_witness<Fn: FnOnce() -> Output::Primitive, Output: Inject>(mode: Mode, logic: Fn) -> Output {
        E::new_witness(mode, logic)
    }

    /// Enters a new scope for the environment.
    fn scope<S: Into<String>, Fn, Output>(name: S, logic: Fn) -> Output
    where
        Fn: FnOnce() -> Output,
    {
        E::scope(name, logic)
    }

    /// Adds one constraint enforcing that `(A * B) == C`.
    fn enforce<Fn, A, B, C>(constraint: Fn) -> Result<(), ConstraintUnsatisfied>
    where
        Fn: FnOnce() -> (A, B, C),
        A: Into<LinearCombination<Self::BaseField>>,
        B: Into<LinearCombination<Self::BaseField>>,
        C: Into<LinearCombination<Self::BaseField>>,
    {
        E::enforce(constraint)
    }

    /// Returns `true` if all constraints in the environment are satisfied.
    fn is_satisfied() -> bool {
        E::is_satisfied()
    }

    /// Returns `true` if all constraints in the current scope are satisfied.
    fn is_satisfied_in_scope() -> bool {
        E::is_satisfied_in_scope()
    }

    /// Returns the number of constants in the entire circuit.
    fn num_constants() -> u64 {
        E::num_constants()
    }

    /// Returns the number of public variables in the entire circuit.
    fn num_public() -> u64 {
        E::num_public()
    }

    /// Returns the number of private variables in the entire circuit.
    fn num_private() -> u64 {
        E::num_private()
    }

    /// Returns the number of constant, public, and private variables in the entire circuit.
    fn num_variables() -> u64 {
        E::num_variables()
    }

    /// Returns the number of constraints in the entire circuit.
    fn num_constraints() -> u64 {
        E::num_constraints()
    }

    /// Returns the number of nonzeros in the entire circuit.
    fn num_nonzeros() -> (u64, u64, u64) {
        E::num_nonzeros()
    }

    /// Returns the number of constants for the current scope.
    fn num_constants_in_scope() -> u64 {
        E::num_constants_in_scope()
    }

    /// Returns the number of public variables for the current scope.
    fn num_public_in_scope() -> u64 {
        E::num_public_in_scope()
    }

    /// Returns the number of private variables for the current scope.
    fn num_private_in_scope() -> u64 {
        E::num_private_in_scope()
    }

    /// Returns the number of constraints for the current scope.
    fn num_constraints_in_scope() -> u64 {
        E::num_constraints_in_scope()
    }

    /// Returns the number of nonzeros for the current scope.
    fn num_nonzeros_in_scope() -> (u64, u64, u64) {
        E::num_nonzeros_in_scope()
    }

    /// Returns the variable limit for the circuit, if one exists.
    fn get_variable_limit() -> Option<u64> {
        E::get_variable_limit()
    }

    /// Sets the variable limit for the circuit.
    fn set_variable_limit(limit: Option<u64>) {
        E::set_variable_limit(limit)
    }

    /// Returns the constraint limit for the circuit, if one exists.
    fn get_constraint_limit() -> Option<u64> {
        E::get_constraint_limit()
    }

    /// Sets the constraint limit for the circuit.
    fn set_constraint_limit(limit: Option<u64>) {
        E::set_constraint_limit(limit)
    }

    /// Returns the density limit for the circuit, if one exists.
    fn get_non_zero_limit() -> Option<(u64, u64, u64)> {
        E::get_non_zero_limit()
    }

    /// Sets the density limit for the circuit.
    fn set_non_zero_limit(limit: Option<(u64, u64, u64)>) {
        E::set_non_zero_limit(limit)
    }

    /// Halts the program from further synthesis, evaluation, and execution in the current environment.
    fn halt<S: Into<String>, T>(message: S) -> T {
        E::halt(message)
    }

    /// Returns the R1CS circuit, resetting the circuit.
    fn inject_r1cs(r1cs: R1CS<Self::BaseField>) {
        E::inject_r1cs(r1cs)
    }

    /// Returns the R1CS circuit, resetting the circuit.
    fn eject_r1cs_and_reset() -> R1CS<Self::BaseField> {
        E::eject_r1cs_and_reset()
    }

    /// Returns the R1CS assignment of the circuit, resetting the circuit.
    fn eject_assignment_and_reset() -> Assignment<<Self::Network as console::Environment>::Field> {
        E::eject_assignment_and_reset()
    }

    /// Clears the circuit and initializes an empty environment.
    fn reset() {
        E::reset()
    }
}

impl Display for AleoTestnetV0 {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        // TODO (howardwu): Find a better way to print the circuit.
        fmt::Display::fmt(&TestnetCircuit, f)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use console::{TestRng, prelude::Uniform};
    use snarkvm_circuit_types::Field;

    const ITERATIONS: usize = 100;

    type CurrentAleo = AleoTestnetV0;

    /// Compute 2^EXPONENT - 1, in a purposefully constraint-inefficient manner for testing.
    fn create_example_circuit<E: Environment>() -> Field<E> {
        let one = snarkvm_console_types::Field::<<E as Environment>::Network>::one();
        let two = one + one;

        const EXPONENT: u64 = 64;

        // Compute 2^EXPONENT - 1, in a purposefully constraint-inefficient manner for testing.
        let mut candidate = Field::<E>::new(Mode::Public, one);
        let mut accumulator = Field::new(Mode::Private, two);
        for _ in 0..EXPONENT {
            candidate += &accumulator;
            accumulator *= Field::new(Mode::Private, two);
        }

        assert_eq!((accumulator - Field::one()).eject_value(), candidate.eject_value());
        assert_eq!(2, E::num_public());
        assert_eq!(2 * EXPONENT + 1, E::num_private());
        assert_eq!(EXPONENT, E::num_constraints());
        assert!(E::is_satisfied());

        candidate
    }

    #[test]
    fn test_print_circuit() {
        let circuit = CurrentAleo {};
        let _candidate = create_example_circuit::<CurrentAleo>();
        let output = format!("{circuit}");
        println!("{output}");
    }

    #[test]
    fn test_circuit_scope() {
        CurrentAleo::scope("test_circuit_scope", || {
            assert_eq!(0, CurrentAleo::num_constants());
            assert_eq!(1, CurrentAleo::num_public());
            assert_eq!(0, CurrentAleo::num_private());
            assert_eq!(0, CurrentAleo::num_constraints());

            assert_eq!(0, CurrentAleo::num_constants_in_scope());
            assert_eq!(0, CurrentAleo::num_public_in_scope());
            assert_eq!(0, CurrentAleo::num_private_in_scope());
            assert_eq!(0, CurrentAleo::num_constraints_in_scope());
        })
    }

    #[test]
    fn test_g_scalar_multiply() {
        let rng = &mut TestRng::default();

        for _ in 0..ITERATIONS {
            let scalar = Scalar::<CurrentAleo>::new(Mode::Public, snarkvm_console_types::Scalar::rand(rng));
            let expected = CurrentAleo::g_scalar_multiply(&scalar);
            let g_powers = CurrentAleo::g_powers();
            let group = g_powers[0].clone() * scalar;
            assert_eq!(expected.eject_value(), group.eject_value());

            CurrentAleo::assert(expected.is_equal(&group)).unwrap();

            assert!(E::is_satisfied());
        }
    }
}
