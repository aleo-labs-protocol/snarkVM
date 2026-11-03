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

mod bytes;
mod equal;
mod parse;
mod to_bits;
mod to_fields;

use crate::{Argument, Boolean, Field, Future, Identifier, Network, ProgramID, Result, ToField, ToFields};

use snarkvm_console_algorithms::{Poseidon2, Poseidon8};
use snarkvm_console_collections::merkle_tree::MerkleTree;
use snarkvm_console_network::*;

/// The depth of the future argument tree.
pub const FUTURE_ARGUMENT_TREE_DEPTH: u8 = 4;

/// The future argument tree.
pub type FutureArgumentTree<E> = MerkleTree<E, Poseidon8<E>, Poseidon2<E>, FUTURE_ARGUMENT_TREE_DEPTH>;

/// A dynamic future is a fixed-size representation of a future. Like static
/// `Future`s, a dynamic future contains a program name, program network, and function name. These
/// are however represented as `Field` elements as opposed to `Identifier`s to
/// ensure a fixed size. Dynamic futures also store a checksum of the
/// arguments to the future instead of the arguments themselves. This ensures
/// that all dynamic futures have a constant size, regardless of the amount of
/// data they contain.
///
/// The checksum is computed as `truncate_252(Sha3_256(bits))`, where `bits` is constructed by:
///   1. Prefixing with the number of arguments as a `u8` in little-endian bits.
///   2. Appending the type-prefixed `to_bits_le()` of each argument.
///   3. Padding the result to the next multiple of 8 bits.
///
/// The 256-bit SHA-3 output is truncated to the field's data capacity (252 bits) and
/// packed into a field element.
#[derive(Clone)]
pub struct DynamicFuture<N: Network> {
    /// The program name.
    program_name: Field<N>,
    /// The program network.
    program_network: Field<N>,
    /// The function name.
    function_name: Field<N>,
    /// The checksum of the arguments.
    checksum: Field<N>,
    /// The optional arguments.
    arguments: Option<Vec<Argument<N>>>,
}

impl<N: Network> DynamicFuture<N> {
    /// Initializes a dynamic future without checking that the checksum and arguments are consistent.
    pub fn new_unchecked(
        program_name: Field<N>,
        program_network: Field<N>,
        function_name: Field<N>,
        checksum: Field<N>,
        arguments: Option<Vec<Argument<N>>>,
    ) -> Self {
        Self { program_name, program_network, function_name, checksum, arguments }
    }
}

impl<N: Network> DynamicFuture<N> {
    /// Returns the program name.
    pub const fn program_name(&self) -> &Field<N> {
        &self.program_name
    }

    /// Returns the program network.
    pub const fn program_network(&self) -> &Field<N> {
        &self.program_network
    }

    /// Returns the function name.
    pub const fn function_name(&self) -> &Field<N> {
        &self.function_name
    }

    /// Returns the checksum of the arguments.
    pub const fn checksum(&self) -> &Field<N> {
        &self.checksum
    }

    /// Returns the optional arguments.
    pub const fn arguments(&self) -> &Option<Vec<Argument<N>>> {
        &self.arguments
    }
}

impl<N: Network> DynamicFuture<N> {
    /// Creates a dynamic future from a static future.
    pub fn from_future(future: &Future<N>) -> Result<Self> {
        // Get the program name.
        let program_name = future.program_id().name().to_field()?;
        // Get the program network.
        let program_network = future.program_id().network().to_field()?;
        // Get the function name.
        let function_name = future.function_name().to_field()?;
        // Get the arguments.
        let arguments = future.arguments().to_vec();

        // Get the bits of the arguments.
        let mut bits = vec![];
        // Prefix the bits with the number of arguments to ensure that different numbers of arguments produce different hashes.
        // Note that the number of arguments is at most 16, so it fits in a single byte.
        u8::try_from(arguments.len())?.write_bits_le(&mut bits);
        // Then, append the bits of each argument.
        // Note that the argument bits themselves are type-prefixed.
        for argument in arguments.iter() {
            argument.write_bits_le(&mut bits);
        }
        // Then pad the bits to the next multiple of 8 to ensure that the hash is consistent regardless of the number of arguments.
        bits.resize(bits.len().div_ceil(8) * 8, false);

        // Hash the bits of the arguments using SHA-3 256, then truncate to fit in a field element.
        let hash_bits = N::hash_sha3_256(&bits)?;
        // Truncate the 256-bit hash to the field's data capacity (252 bits) and pack into a field element.
        let checksum = Field::<N>::from_bits_le(&hash_bits[..Field::<N>::size_in_data_bits()])?;

        Ok(Self::new_unchecked(program_name, program_network, function_name, checksum, Some(arguments)))
    }

    /// Creates a static future from a dynamic future.
    pub fn to_future(&self) -> Result<Future<N>> {
        // Ensure that the arguments are present.
        let Some(arguments) = &self.arguments else {
            bail!("Cannot convert dynamic future to a static future without the arguments being present");
        };

        Ok(Future::new(
            ProgramID::try_from((
                Identifier::from_field(&self.program_name)?,
                Identifier::from_field(&self.program_network)?,
            ))?,
            Identifier::from_field(&self.function_name)?,
            arguments.clone(),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use snarkvm_console_network::MainnetV0;

    use crate::Plaintext;

    use core::str::FromStr;

    type CurrentNetwork = MainnetV0;

    #[test]
    fn test_data_depth() {
        assert_eq!(CurrentNetwork::MAX_INPUTS.ilog2(), FUTURE_ARGUMENT_TREE_DEPTH as u32);
    }

    fn create_test_future(arguments: Vec<Argument<CurrentNetwork>>) -> Future<CurrentNetwork> {
        Future::new(ProgramID::from_str("test.aleo").unwrap(), Identifier::from_str("foo").unwrap(), arguments)
    }

    fn assert_round_trip(arguments: Vec<Argument<CurrentNetwork>>) {
        let future = create_test_future(arguments);
        let dynamic = DynamicFuture::from_future(&future).unwrap();
        let recovered = dynamic.to_future().unwrap();
        assert_eq!(future.program_id(), recovered.program_id());
        assert_eq!(future.function_name(), recovered.function_name());
        assert_eq!(future.arguments().len(), recovered.arguments().len(), "Argument count must be preserved");
        for (a, b) in future.arguments().iter().zip(recovered.arguments().iter()) {
            assert!(*a.is_equal(b));
        }
    }

    #[test]
    fn test_round_trip_various_arguments() {
        // No arguments.
        assert_round_trip(vec![]);

        // Plaintext literals.
        assert_round_trip(vec![
            Argument::Plaintext(Plaintext::from_str("true").unwrap()),
            Argument::Plaintext(Plaintext::from_str("100u64").unwrap()),
        ]);

        // Struct and array.
        assert_round_trip(vec![Argument::Plaintext(Plaintext::from_str("{ x: 1field, y: 2field }").unwrap())]);

        // Nested Future argument.
        let inner =
            Future::new(ProgramID::from_str("inner.aleo").unwrap(), Identifier::from_str("bar").unwrap(), vec![
                Argument::Plaintext(Plaintext::from_str("42u64").unwrap()),
            ]);
        assert_round_trip(vec![Argument::Future(inner.clone())]);

        // DynamicFuture argument.
        assert_round_trip(vec![Argument::DynamicFuture(DynamicFuture::from_future(&inner).unwrap())]);

        // Max arguments (16).
        let max_args: Vec<_> =
            (0..16).map(|i| Argument::Plaintext(Plaintext::from_str(&format!("{i}u64")).unwrap())).collect();
        assert_round_trip(max_args);
    }

    #[test]
    fn test_checksum_determinism() {
        let args1 = vec![Argument::Plaintext(Plaintext::from_str("100u64").unwrap())];
        let args2 = vec![Argument::Plaintext(Plaintext::from_str("100u64").unwrap())];
        let args3 = vec![Argument::Plaintext(Plaintext::from_str("200u64").unwrap())];

        let d1 = DynamicFuture::from_future(&create_test_future(args1)).unwrap();
        let d2 = DynamicFuture::from_future(&create_test_future(args2)).unwrap();
        let d3 = DynamicFuture::from_future(&create_test_future(args3)).unwrap();

        assert_eq!(d1.checksum(), d2.checksum(), "Same arguments should produce same checksum");
        assert_ne!(d1.checksum(), d3.checksum(), "Different arguments should produce different checksums");
    }

    #[test]
    fn test_to_fields_is_deterministic() {
        let args = vec![Argument::Plaintext(Plaintext::from_str("100u64").unwrap())];
        let dynamic = DynamicFuture::from_future(&create_test_future(args)).unwrap();

        // Two calls must return identical field elements.
        let fields1 = dynamic.to_fields().unwrap();
        let fields2 = dynamic.to_fields().unwrap();
        assert!(!fields1.is_empty(), "to_fields must return at least one field element");
        assert_eq!(fields1, fields2, "to_fields must be deterministic");
    }

    #[test]
    fn test_to_fields_differs_for_different_futures() {
        let args_a = vec![Argument::Plaintext(Plaintext::from_str("1u64").unwrap())];
        let args_b = vec![Argument::Plaintext(Plaintext::from_str("2u64").unwrap())];
        let da = DynamicFuture::from_future(&create_test_future(args_a)).unwrap();
        let db = DynamicFuture::from_future(&create_test_future(args_b)).unwrap();

        // Different futures must produce different field encodings.
        assert_ne!(da.to_fields().unwrap(), db.to_fields().unwrap());
    }
}
