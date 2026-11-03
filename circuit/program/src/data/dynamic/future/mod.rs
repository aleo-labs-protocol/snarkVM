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

mod equal;
mod to_bits;
mod to_fields;

use snarkvm_circuit_network::Aleo;
use snarkvm_circuit_types::{Boolean, Field, environment::prelude::*};

/// A dynamic future is a fixed-size representation of a future. Like static
/// `Future`s, a dynamic future contains a program name, program network, and function name. These
/// are however represented as `Field` elements as opposed to `Identifier`s to
/// ensure a fixed size. Dynamic futures also store a checksum of the
/// arguments to the future instead of the arguments themselves. This ensures
/// that all dynamic futures have a constant size, regardless of the amount of
/// data they contain.
///
/// Note: The checksum is never computed in circuit. It is computed in console
/// as `truncate_252(Sha3_256(length_prefix || type_prefixed_argument_bits))` and
/// injected as a witness field element.
#[derive(Clone)]
pub struct DynamicFuture<A: Aleo> {
    /// The program name.
    program_name: Field<A>,
    /// The program network.
    program_network: Field<A>,
    /// The function name.
    function_name: Field<A>,
    /// The checksum of the arguments.
    checksum: Field<A>,
    /// The optional console arguments.
    /// Note: This is NOT part of the circuit representation.
    arguments: Option<Vec<console::Argument<A::Network>>>,
}

impl<A: Aleo> Inject for DynamicFuture<A> {
    type Primitive = console::DynamicFuture<A::Network>;

    /// Initializes a circuit of the given mode and future.
    fn new(mode: Mode, value: Self::Primitive) -> Self {
        DynamicFuture {
            program_name: Inject::new(mode, *value.program_name()),
            program_network: Inject::new(mode, *value.program_network()),
            function_name: Inject::new(mode, *value.function_name()),
            checksum: Inject::new(mode, *value.checksum()),
            arguments: value.arguments().clone(),
        }
    }
}

impl<A: Aleo> DynamicFuture<A> {
    /// Returns the program name.
    pub const fn program_name(&self) -> &Field<A> {
        &self.program_name
    }

    /// Returns the program network.
    pub const fn program_network(&self) -> &Field<A> {
        &self.program_network
    }

    /// Returns the function name.
    pub const fn function_name(&self) -> &Field<A> {
        &self.function_name
    }

    /// Returns the checksum of the arguments.
    pub const fn checksum(&self) -> &Field<A> {
        &self.checksum
    }

    /// Returns the console arguments.
    pub const fn arguments(&self) -> &Option<Vec<console::Argument<A::Network>>> {
        &self.arguments
    }
}

impl<A: Aleo> Eject for DynamicFuture<A> {
    type Primitive = console::DynamicFuture<A::Network>;

    /// Ejects the mode of the dynamic future.
    fn eject_mode(&self) -> Mode {
        let program_name_mode = Eject::eject_mode(self.program_name());
        let program_network_mode = Eject::eject_mode(self.program_network());
        let function_name_mode = Eject::eject_mode(self.function_name());
        let checksum_mode = Eject::eject_mode(self.checksum());
        Mode::combine(program_name_mode, [program_network_mode, function_name_mode, checksum_mode])
    }

    /// Ejects the dynamic future.
    fn eject_value(&self) -> Self::Primitive {
        Self::Primitive::new_unchecked(
            Eject::eject_value(self.program_name()),
            Eject::eject_value(self.program_network()),
            Eject::eject_value(self.function_name()),
            Eject::eject_value(self.checksum()),
            self.arguments.clone(),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Circuit, console::ToFields as ConsoleToFields};
    use snarkvm_circuit_types::environment::Inject;

    use core::str::FromStr;

    type CurrentNetwork = <Circuit as Environment>::Network;
    type ConsoleFuture = console::Future<CurrentNetwork>;
    type ConsoleDynamicFuture = console::DynamicFuture<CurrentNetwork>;

    fn create_test_future(args: Vec<console::Argument<CurrentNetwork>>) -> ConsoleFuture {
        ConsoleFuture::new(
            console::ProgramID::from_str("test.aleo").unwrap(),
            console::Identifier::from_str("foo").unwrap(),
            args,
        )
    }

    /// Verifies that injecting a console DynamicFuture into a circuit and ejecting it
    /// reproduces the original value.
    fn check_inject_eject(console_dynamic: &ConsoleDynamicFuture) {
        let circuit_dynamic = DynamicFuture::<Circuit>::new(Mode::Private, console_dynamic.clone());

        assert_eq!(circuit_dynamic.program_name().eject_value(), *console_dynamic.program_name());
        assert_eq!(circuit_dynamic.program_network().eject_value(), *console_dynamic.program_network());
        assert_eq!(circuit_dynamic.function_name().eject_value(), *console_dynamic.function_name());
        assert_eq!(circuit_dynamic.checksum().eject_value(), *console_dynamic.checksum());

        let ejected = circuit_dynamic.eject_value();
        assert_eq!(ejected.program_name(), console_dynamic.program_name());
        assert_eq!(ejected.program_network(), console_dynamic.program_network());
        assert_eq!(ejected.function_name(), console_dynamic.function_name());
        assert_eq!(ejected.checksum(), console_dynamic.checksum());

        Circuit::reset();
    }

    /// Verifies that circuit to_bits_le produces the same bits as the console equivalent.
    fn check_to_bits_le(console_dynamic: &ConsoleDynamicFuture) {
        let circuit_dynamic = DynamicFuture::<Circuit>::new(Mode::Private, console_dynamic.clone());

        Circuit::scope("to_bits_le", || {
            let circuit_bits = circuit_dynamic.to_bits_le();
            let console_bits = console_dynamic.to_bits_le();
            for (circuit_bit, console_bit) in circuit_bits.iter().zip_eq(console_bits.iter()) {
                assert_eq!(circuit_bit.eject_value(), *console_bit, "Circuit and console bits must match");
            }
        });

        Circuit::reset();
    }

    /// Verifies that circuit to_fields produces the same field elements as the console equivalent.
    fn check_to_fields(console_dynamic: &ConsoleDynamicFuture) {
        let circuit_dynamic = DynamicFuture::<Circuit>::new(Mode::Private, console_dynamic.clone());

        Circuit::scope("to_fields", || {
            let circuit_fields = circuit_dynamic.to_fields();
            let console_fields = console_dynamic.to_fields().unwrap();
            for (circuit_field, console_field) in circuit_fields.iter().zip_eq(console_fields.iter()) {
                assert_eq!(circuit_field.eject_value(), *console_field, "Circuit and console fields must match");
            }
        });

        Circuit::reset();
    }

    #[test]
    fn test_inject_eject_no_arguments() {
        let future = create_test_future(vec![]);
        let dynamic = ConsoleDynamicFuture::from_future(&future).unwrap();
        check_inject_eject(&dynamic);
    }

    #[test]
    fn test_inject_eject_with_arguments() {
        let args = vec![
            console::Argument::Plaintext(console::Plaintext::from_str("100u64").unwrap()),
            console::Argument::Plaintext(console::Plaintext::from_str("true").unwrap()),
        ];
        let future = create_test_future(args);
        let dynamic = ConsoleDynamicFuture::from_future(&future).unwrap();
        check_inject_eject(&dynamic);
    }

    #[test]
    fn test_to_bits_le_console_circuit_equivalence() {
        let args = vec![console::Argument::Plaintext(console::Plaintext::from_str("42u64").unwrap())];
        let future = create_test_future(args);
        let dynamic = ConsoleDynamicFuture::from_future(&future).unwrap();
        check_to_bits_le(&dynamic);
    }

    #[test]
    fn test_to_fields_console_circuit_equivalence() {
        let args = vec![console::Argument::Plaintext(console::Plaintext::from_str("42u64").unwrap())];
        let future = create_test_future(args);
        let dynamic = ConsoleDynamicFuture::from_future(&future).unwrap();
        check_to_fields(&dynamic);
    }

    #[test]
    fn test_to_fields_no_arguments() {
        let future = create_test_future(vec![]);
        let dynamic = ConsoleDynamicFuture::from_future(&future).unwrap();
        check_to_fields(&dynamic);
    }
}
