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

/// Creates a new `struct` that implements the `Operation` trait.
///
/// # Examples
/// ```ignore
/// operation!(
///     pub struct AddOperation<AddOperator, "add"> {
///         (Field, Field) => Field,
///         (Group, Group) => Group,
///         (I8, I8) => I8,
///         (I16, I16) => I16,
///         (I32, I32) => I32,
///         (I64, I64) => I64,
///         (I128, I128) => I128,
///         (U8, U8) => U8,
///         (U16, U16) => U16,
///         (U32, U32) => U32,
///         (U64, U64) => U64,
///         (U128, U128) => U128,
///         (Scalar, Scalar) => Scalar,
///     }
/// );
/// ```
#[macro_export]
macro_rules! operation {
    // Unary operation.
    ($vis:vis struct $name:ident<$operator:path, $circuit_operator:path, $operate:ident, $opcode:tt> { $( $input:ident => $output:ident $( ($($condition:tt),+) )?, )+ }) => {
        $crate::operation!($vis struct $name<$operator, $circuit_operator, $operate, $opcode, 1> { $( ($input) => $output $( ( $($condition),+ ) )?, )+ });
    };
    // Unary operation with question mark (?).
    ($vis:vis struct $name:ident<$operator:path, $circuit_operator:path, $operate:ident?, $opcode:tt> { $( $input:ident => $output:ident $( ($($condition:tt),+) )?, )+ }) => {
        $crate::operation!($vis struct $name<$operator, $circuit_operator, $operate?, $opcode, 1> { $( ($input) => $output $( ( $($condition),+ ) )?, )+ });
    };
    // Binary operation.
    ($vis:vis struct $name:ident<$operator:path, $circuit_operator:path, $operate:ident, $opcode:tt> { $( ($input_a:ident, $input_b:ident) => $output:ident $( ($($condition:tt),+) )?, )+ }) => {
        $crate::operation!($vis struct $name<$operator, $circuit_operator, $operate, $opcode, 2> { $( ($input_a, $input_b) => $output $( ( $($condition),+ ) )?, )+ });
    };
    // Ternary operation.
    ($vis:vis struct $name:ident<$operator:path, $circuit_operator:path, $operate:ident, $opcode:tt> { $( ($input_a:ident, $input_b:ident, $input_c:ident) => $output:ident $( ($($condition:tt),+) )?, )+ }) => {
        $crate::operation!($vis struct $name<$operator, $circuit_operator, $operate, $opcode, 3> { $( ($input_a, $input_b, $input_c) => $output $( ( $($condition),+ ) )?, )+ });
    };
    // K-ary operation.
    ($vis:vis struct $name:ident<$operator:path, $circuit_operator:path, $operate:ident, $opcode:tt, $num_inputs:tt> { $( ( $($input:ident),+ ) => $output:ident $( ($($condition:tt),+) )?, )+ }) => {
        /// The implementation of the binary operation.
        #[derive(Clone, PartialEq, Eq, Hash)]
        $vis struct $name<N: Network>(core::marker::PhantomData<N>);

        impl<N: Network> $crate::Operation<N, console::program::Literal<N>, console::program::LiteralType, $num_inputs> for $name<N> {
            /// The opcode of the operation.
            const OPCODE: $crate::Opcode = Opcode::Literal($opcode);

            /// Returns the result of evaluating the operation on the given inputs.
            #[inline]
            fn evaluate(inputs: &[console::program::Literal<N>; $num_inputs]) -> Result<console::program::Literal<N>> {
                // Prepare the operator.
                use $operator as Operator;
                // Compute the output.
                Ok($crate::evaluate!(match Operator::$operate(inputs) { $( ( $($input),+ ) => $output, )+ }))
            }

            /// Returns the result of executing the operation on the given circuit inputs.
            #[inline]
            fn execute<A: circuit::Aleo<Network = N>>(inputs: &[circuit::Literal<A>; $num_inputs]) -> Result<circuit::Literal<A>> {
                // Prepare the circuit operator.
                use $circuit_operator as Operator;
                // Compute the output.
                Ok($crate::execute!(match Operator::$operate(inputs) { $( ( $($input),+ ) => $output, )+ }))
            }

            /// Returns the output type from the given input types.
            #[inline]
            fn output_type(inputs: &[console::program::LiteralType; $num_inputs]) -> Result<console::program::LiteralType> {
                // Compute the output type.
                Ok($crate::output_type!(match inputs { $( ( $($input),+ ) => $output, )+ }))
            }
        }

        paste::paste! {
            #[cfg(test)]
            mod [<test _ $operate>] {
                use super::*;
                use console::types::*;

                // Prepare the environment.
                type CurrentNetwork = console::network::MainnetV0;
                type CurrentAleo = circuit::network::AleoV0;

                // Prepare the operator.
                use $operator as Operator;
                // Prepare the operation.
                type Operation = $name::<CurrentNetwork>;
                // Execute the test cases for the operation.
                $crate::test_execute!(Operator::$operate == Operation::execute { $( ( $($input),+ ) => $output $( ($($condition),+) )?, )+ });
            }
        }
    };
    // K-ary operation with question mark (?).
    ($vis:vis struct $name:ident<$operator:path, $circuit_operator:path, $operate:ident?, $opcode:tt, $num_inputs:tt> { $( ( $($input:ident),+ ) => $output:ident $( ($($condition:tt),+) )?, )+ }) => {
        /// The implementation of the binary operation.
        #[derive(Clone, PartialEq, Eq, Hash)]
        $vis struct $name<N: Network>(core::marker::PhantomData<N>);

        impl<N: Network> $crate::Operation<N, console::program::Literal<N>, console::program::LiteralType, $num_inputs> for $name<N> {
            /// The opcode of the operation.
            const OPCODE: $crate::Opcode = Opcode::Literal($opcode);

            /// Returns the result of evaluating the operation on the given inputs.
            #[inline]
            fn evaluate(inputs: &[console::program::Literal<N>; $num_inputs]) -> Result<console::program::Literal<N>> {
                // Prepare the operator.
                use $operator as Operator;
                // Compute the output.
                Ok($crate::evaluate!(match Operator::$operate(inputs)? { $( ( $($input),+ ) => $output, )+ }))
            }

            /// Returns the result of executing the operation on the given circuit inputs.
            #[inline]
            fn execute<A: circuit::Aleo<Network = N>>(inputs: &[circuit::Literal<A>; $num_inputs]) -> Result<circuit::Literal<A>> {
                // Prepare the circuit operator.
                use $circuit_operator as Operator;
                // Compute the output.
                Ok($crate::execute!(match Operator::$operate(inputs) { $( ( $($input),+ ) => $output, )+ }))
            }

            /// Returns the output type from the given input types.
            #[inline]
            fn output_type(inputs: &[console::program::LiteralType; $num_inputs]) -> Result<console::program::LiteralType> {
                // Compute the output type.
                Ok($crate::output_type!(match inputs { $( ( $($input),+ ) => $output, )+ }))
            }
        }

        paste::paste! {
            #[cfg(test)]
            mod [<test _ $operate>] {
                use super::*;
                use console::types::*;

                // Prepare the environment.
                type CurrentNetwork = console::network::MainnetV0;
                type CurrentAleo = circuit::network::AleoV0;

                // Prepare the operator.
                use $operator as Operator;
                // Prepare the operation.
                type Operation = $name::<CurrentNetwork>;
                // Execute the test cases for the operation.
                $crate::test_execute!(Operator::$operate == Operation::execute? { $( ( $($input),+ ) => $output $( ($($condition),+) )?, )+ });
            }
        }
    };
}

/// Creates a match statement that evaluates the operation.
///
/// ## Example
/// ```ignore
/// evaluate!(
///     match Operator::add(inputs) {
///         (I8, I8) => I8,
///         (I16, I16) => I16,
///         (I32, I32) => I32,
///         (I64, I64) => I64,
///         (I128, I128) => I128,
///         (U8, U8) => U8,
///         (U16, U16) => U16,
///         (U32, U32) => U32,
///         (U64, U64) => U64,
///         (U128, U128) => U128,
///     }
/// )
/// ```
#[macro_export]
macro_rules! evaluate {
    // Unary operation.
    (match $operator:tt::$operate:tt($inputs:expr) { $( ($input:ident) => $output:ident, )+ }) => {{
        // Retrieve the operand.
        let [first] = $inputs;
        // Compute the output.
        match first {
            $(console::program::Literal::$input(first) => console::program::Literal::$output(first.$operate()),)+
            _ => bail!("Invalid operand for the '{}' instruction", Self::OPCODE),
        }
    }};
    // Unary operation with question mark (?).
    (match $operator:tt::$operate:tt($inputs:expr)? { $( ( $input:ident ) => $output:ident, )+ }) => {{
        // Retrieve the operand.
        let [first] = $inputs;
        // Compute the output.
        match first {
            $(console::program::Literal::$input(first) => console::program::Literal::$output(first.$operate()?),)+
            _ => bail!("Invalid operand for the '{}' instruction", Self::OPCODE),
        }
    }};
    // Binary operation.
    (match $operator:tt::$operate:tt($inputs:expr) { $( ($input_a:ident, $input_b:ident) => $output:ident, )+ }) => {{
        // Retrieve the operands.
        let [first, second] = $inputs;
        // Compute the output.
        match (first, second) {
            $((console::program::Literal::$input_a(first), console::program::Literal::$input_b(second)) => console::program::Literal::$output(first.$operate(second)),)+
            _ => bail!("Invalid operands for the '{}' instruction", Self::OPCODE),
        }
    }};
    // Ternary operation.
    (match $operator:tt::$operate:tt($inputs:expr) { $( ($input_a:ident, $input_b:ident, $input_c:ident) => $output:ident, )+ }) => {{
        // Retrieve the operands.
        let [first, second, third] = $inputs;
        // Compute the output.
        match (first, second, third) {
            $((console::program::Literal::$input_a(first), console::program::Literal::$input_b(second), console::program::Literal::$input_c(third)) => console::program::Literal::$output($operator::$operate(first, second, third)),)+
            _ => bail!("Invalid operands for the '{}' instruction", Self::OPCODE),
        }
    }};
}

/// Creates a match statement that executes the operation.
///
/// ## Example
/// ```ignore
/// execute!(
///     match Operator::add(inputs) {
///         (I8, I8) => I8,
///         (I16, I16) => I16,
///         (I32, I32) => I32,
///         (I64, I64) => I64,
///         (I128, I128) => I128,
///         (U8, U8) => U8,
///         (U16, U16) => U16,
///         (U32, U32) => U32,
///         (U64, U64) => U64,
///         (U128, U128) => U128,
///     }
/// )
/// ```
#[macro_export]
macro_rules! execute {
    // Unary operation.
    (match $operator:tt::$operate:tt($inputs:expr) { $( ($input:ident) => $output:ident, )+ }) => {{
        // Retrieve the operand.
        let [first] = $inputs.to_owned();
        // Compute the output.
        match first {
            $(circuit::Literal::$input(first) => circuit::Literal::$output(first.$operate()),)+
            _ => bail!("Invalid operand for the '{}' instruction", Self::OPCODE),
        }
    }};
    // Binary operation.
    (match $operator:tt::$operate:tt($inputs:expr) { $( ($input_a:ident, $input_b:ident) => $output:ident, )+ }) => {{
        // Retrieve the operands.
        let [first, second] = $inputs.to_owned();
        // Compute the output.
        match (first, second) {
            $((circuit::Literal::$input_a(first), circuit::Literal::$input_b(second)) => circuit::Literal::$output(first.$operate(&second)),)+
            _ => bail!("Invalid operands for the '{}' instruction", Self::OPCODE),
        }
    }};
    // Ternary operation.
    (match $operator:tt::$operate:tt($inputs:expr) { $( ($input_a:ident, $input_b:ident, $input_c:ident) => $output:ident, )+ }) => {{
        // Retrieve the operands.
        let [first, second, third] = $inputs.to_owned();
        // Compute the output.
        match (first, second, third) {
            $((circuit::Literal::$input_a(first), circuit::Literal::$input_b(second), circuit::Literal::$input_c(third)) => circuit::Literal::$output($operator::$operate(&first, &second, &third)),)+
            _ => bail!("Invalid operands for the '{}' instruction", Self::OPCODE),
        }
    }};
}

/// Creates a match statement that returns the output type given the input types.
///
/// ## Example
/// ```ignore
/// output_type!(
///     match (first, second) {
///         (I8, I8) => I8,
///         (I16, I16) => I16,
///         (I32, I32) => I32,
///         (I64, I64) => I64,
///         (I128, I128) => I128,
///         (U8, U8) => U8,
///         (U16, U16) => U16,
///         (U32, U32) => U32,
///         (U64, U64) => U64,
///         (U128, U128) => U128,
///     }
/// )
/// ```
#[macro_export]
macro_rules! output_type {
    // Unary operation.
    (match $inputs:ident { $( ($input:ident) => $output:ident, )+ }) => {{
        // Retrieve the operand.
        let [first] = $inputs;
        // Compute the output type.
        match first {
            $(console::program::LiteralType::$input => console::program::LiteralType::$output,)+
            _ => bail!("Invalid operand types for the '{}' instruction", Self::OPCODE),
        }
    }};
    // Binary operation.
    (match $inputs:ident { $( ($input_a:ident, $input_b:ident) => $output:ident, )+ }) => {{
        // Retrieve the operands.
        let [first, second] = $inputs;
        // Compute the output type.
        match (first, second) {
            $((console::program::LiteralType::$input_a, console::program::LiteralType::$input_b) => console::program::LiteralType::$output,)+
            _ => bail!("Invalid operand types for the '{}' instruction", Self::OPCODE),
        }
    }};
    // Ternary operation.
    (match $inputs:ident { $( ($input_a:ident, $input_b:ident, $input_c:ident) => $output:ident, )+ }) => {{
        // Retrieve the operands.
        let [first, second, third] = $inputs;
        // Compute the output type.
        match (first, second, third) {
            $((console::program::LiteralType::$input_a, console::program::LiteralType::$input_b, console::program::LiteralType::$input_c) => console::program::LiteralType::$output,)+
            _ => bail!("Invalid operand types for the '{}' instruction", Self::OPCODE),
        }
    }};
}

#[cfg(test)]
mod tests {
    /// Samples a random value for each literal type.
    #[macro_export]
    macro_rules! sample_literals {
        ($network:ident, $rng:expr) => {
            [
                console::program::Literal::<$network>::Address(console::types::Address::rand($rng)),
                console::program::Literal::Boolean(console::types::Boolean::rand($rng)),
                console::program::Literal::Field(console::types::Field::rand($rng)),
                console::program::Literal::Group(console::types::Group::rand($rng)),
                console::program::Literal::I8(console::types::I8::rand($rng)),
                console::program::Literal::I16(console::types::I16::rand($rng)),
                console::program::Literal::I32(console::types::I32::rand($rng)),
                console::program::Literal::I64(console::types::I64::rand($rng)),
                console::program::Literal::I128(console::types::I128::rand($rng)),
                console::program::Literal::U8(console::types::U8::rand($rng)),
                console::program::Literal::U16(console::types::U16::rand($rng)),
                console::program::Literal::U32(console::types::U32::rand($rng)),
                console::program::Literal::U64(console::types::U64::rand($rng)),
                console::program::Literal::U128(console::types::U128::rand($rng)),
                console::program::Literal::Scalar(console::types::Scalar::rand($rng)),
                console::program::Literal::sample(console::program::LiteralType::Signature, $rng),
                console::program::Literal::String(console::types::StringType::rand($rng)),
            ]
        };
    }

    ///
    /// Creates a test of the given operation for each declared case.
    ///
    /// For each declared case, this macro samples random values and checks that
    /// the output of the operator (LHS) matches the output of the operation (RHS).
    /// In addition, this macro ensures all combinations of literal types that
    /// do **not** match these declared cases fail on evaluation.
    ///
    /// ## Example
    /// ```ignore
    /// ```text
    ///     test_execute!(
    ///         Operator::add == AddOp::execute {
    ///             (Field, Field) => Field,
    ///             (Group, Group) => Group,
    ///             (I8, I8) => I8,
    ///             (I16, I16) => I16,
    ///             (I32, I32) => I32,
    ///             (I64, I64) => I64,
    ///             (I128, I128) => I128,
    ///             (U8, U8) => U8,
    ///             (U16, U16) => U16,
    ///             (U32, U32) => U32,
    ///             (U64, U64) => U64,
    ///             (U128, U128) => U128,
    ///             (Scalar, Scalar) => Scalar,
    ///         }
    ///     );
    /// ```
    #[macro_export]
    macro_rules! test_execute {
        // Case 0: Unary operation.
        ($operator:tt::$operate:tt == $operation:tt::$execute:tt { $( ($input:ident) => $output:ident $( ($($condition:tt),+) )?, )+ }) => {
            // For each given case of inputs and outputs, invoke `Case 0-A` or `Case 0-B` (see below).
            $( $crate::test_execute!{$operator::$operate == $operation::$execute for $input => $output $( ($($condition),+) )?} )+
            // For each non-existent case of inputs and outputs, invoke the following test to ensure the operation **fails**.
            paste::paste! {
                #[test]
                fn [<test _ $operate _ fails _ on _ invalid _ operands>]() -> Result<()> {
                    // Prepare the rng.
                    let mut rng = TestRng::default();

                    for i in 0..8 {
                        for literal_a in $crate::sample_literals!(CurrentNetwork, &mut rng).iter() {
                            for mode_a in &[circuit::Mode::Constant, circuit::Mode::Public, circuit::Mode::Private] {
                                // Skip this iteration, if this is **not** an invalid operand case.
                                $(if literal_a.to_type() == console::program::LiteralType::$input {
                                    continue;
                                })+

                                // Attempt to compute the invalid operand case.
                                #[allow(clippy::cloned_ref_to_slice_refs)]
                                let result_a = <$operation as $crate::Operation<_, _, _, 1>>::evaluate(&[literal_a.clone()]);
                                // Ensure the computation failed.
                                assert!(result_a.is_err(), "An invalid operand case (on iteration {i}) did not fail (console): {literal_a}");

                                // Attempt to compute the invalid operand case.
                                let result_b = <$operation as $crate::Operation<_, _, _, 1>>::$execute::<CurrentAleo>(&[
                                    circuit::program::Literal::from_str(&format!("{literal_a}.{mode_a}"))?,
                                ]);
                                // Ensure the computation failed.
                                assert!(result_b.is_err(), "An invalid operand case (on iteration {i}) did not fail (circuit): {literal_a}");
                                // Reset the circuit.
                                <CurrentAleo as circuit::Environment>::reset();
                            }
                        }
                    }
                    Ok(())
                }
            }
        };

        // Case 0Q: Unary operation with question mark (?).
        ($operator:tt::$operate:tt == $operation:tt::$execute:tt? { $( ($input:ident) => $output:ident $( ($($condition:tt),+) )?, )+ }) => {
            // For each given case of inputs and outputs, invoke `Case 0Q-A` or `Case 0Q-B` (see below).
            $( $crate::test_execute!{$operator::$operate == $operation::$execute (.unwrap()) for $input => $output $( ($($condition),+) )?} )+
            // For each non-existent case of inputs and outputs, invoke the following test to ensure the operation **fails**.
            paste::paste! {
                #[test]
                fn [<test _ $operate _ fails _ on _ invalid _ operands>]() -> Result<()> {
                    // Prepare the rng.
                    let mut rng = TestRng::default();

                    for i in 0..8 {
                        for literal_a in $crate::sample_literals!(CurrentNetwork, &mut rng).iter() {
                            for mode_a in &[circuit::Mode::Constant, circuit::Mode::Public, circuit::Mode::Private] {
                                // Skip this iteration, if this is **not** an invalid operand case.
                                $(if literal_a.to_type() == console::program::LiteralType::$input {
                                    continue;
                                })+

                                // Attempt to compute the invalid operand case.
                                #[allow(clippy::cloned_ref_to_slice_refs)]
                                let result_a = <$operation as $crate::Operation<_, _, _, 1>>::evaluate(&[literal_a.clone()]);
                                // Ensure the computation failed.
                                assert!(result_a.is_err(), "An invalid operand case (on iteration {i}) did not fail (console): {literal_a}");

                                // Attempt to compute the invalid operand case.
                                let result_b = <$operation as $crate::Operation<_, _, _, 1>>::$execute::<CurrentAleo>(&[
                                    circuit::program::Literal::from_str(&format!("{literal_a}.{mode_a}"))?,
                                ]);
                                // Ensure the computation failed.
                                assert!(result_b.is_err(), "An invalid operand case (on iteration {i}) did not fail (circuit): {literal_a}");
                                // Reset the circuit.
                                <CurrentAleo as circuit::Environment>::reset();
                            }
                        }
                    }
                    Ok(())
                }
            }
        };

        // Case 1: Binary operation.
        ($operator:tt::$operate:tt == $operation:tt::$execute:tt { $( ($input_a:ident, $input_b:ident) => $output:ident $( ($($condition:tt),+) )?, )+ }) => {
            // For each given case of inputs and outputs, invoke `Case 1-A` or `Case 1-B` (see below).
            $( $crate::test_execute!{$operator::$operate == $operation::$execute for ($input_a, $input_b) => $output $( ($($condition),+) )?} )+

            // For each non-existent case of inputs and outputs, invoke the following test to ensure the operation **fails**.
            paste::paste! {
                #[test]
                fn [<test _ $operate _ fails _ on _ invalid _ operands>]() -> Result<()> {
                    // Prepare the rng.
                    let mut rng = TestRng::default();

                    for i in 0..8 {
                        for literal_a in $crate::sample_literals!(CurrentNetwork, &mut rng).iter() {
                            for literal_b in $crate::sample_literals!(CurrentNetwork, &mut rng).iter() {
                                for mode_a in &[circuit::Mode::Constant, circuit::Mode::Public, circuit::Mode::Private] {
                                    for mode_b in &[circuit::Mode::Constant, circuit::Mode::Public, circuit::Mode::Private] {
                                        // Skip this iteration, if this is **not** an invalid operand case.
                                        $(if literal_a.to_type() == console::program::LiteralType::$input_a
                                          && literal_b.to_type() == console::program::LiteralType::$input_b {
                                            continue;
                                        })+

                                        // Attempt to compute the invalid operand case.
                                        let result_a = <$operation as $crate::Operation<_, _, _, 2>>::evaluate(&[literal_a.clone(), literal_b.clone()]);
                                        // Ensure the computation failed.
                                        assert!(result_a.is_err(), "An invalid operands case (on iteration {i}) did not fail (console): {literal_a} {literal_b}");

                                        // Attempt to compute the invalid operand case.
                                        let result_b = <$operation as $crate::Operation<_, _, _, 2>>::$execute::<CurrentAleo>(&[
                                            circuit::program::Literal::from_str(&format!("{literal_a}.{mode_a}"))?,
                                            circuit::program::Literal::from_str(&format!("{literal_b}.{mode_b}"))?,
                                        ]);
                                        // Ensure the computation failed.
                                        assert!(result_b.is_err(), "An invalid operands case (on iteration {i}) did not fail (circuit): {literal_a} {literal_b}");
                                        // Reset the circuit.
                                        <CurrentAleo as circuit::Environment>::reset();
                                    }
                                }
                            }
                        }
                    }
                    Ok(())
                }
            }
        };

        // Case 2: Ternary operation.
        ($operator:tt::$operate:tt == $operation:tt::$execute:tt { $( ($input_a:ident, $input_b:ident, $input_c:ident) => $output:ident $( ($($condition:tt),+) )?, )+ }) => {
            // For each given case of inputs and outputs, invoke `Case 2-A` or `Case 2-B` (see below).
            $( $crate::test_execute!{$operator::$operate == $operation::$execute for ($input_a, $input_b, $input_c) => $output $( ($($condition),+) )?} )+

            // For each non-existent case of inputs and outputs, invoke the following test to ensure the operation **fails**.
            paste::paste! {
                #[test]
                fn [<test _ $operate _ fails _ on _ invalid _ operands>]() -> Result<()> {
                    // Prepare the rng.
                    let mut rng = TestRng::default();

                    for literal_a in $crate::sample_literals!(CurrentNetwork, &mut rng).iter() {
                        for literal_b in $crate::sample_literals!(CurrentNetwork, &mut rng).iter() {
                            for literal_c in $crate::sample_literals!(CurrentNetwork, &mut rng).iter() {
                                for mode_a in &[circuit::Mode::Constant, circuit::Mode::Public, circuit::Mode::Private] {
                                    for mode_b in &[circuit::Mode::Constant, circuit::Mode::Public, circuit::Mode::Private] {
                                        for mode_c in &[circuit::Mode::Constant, circuit::Mode::Public, circuit::Mode::Private] {
                                            // Skip this iteration, if this is **not** an invalid operand case.
                                            $(if literal_a.to_type() == console::program::LiteralType::$input_a
                                              && literal_b.to_type() == console::program::LiteralType::$input_b
                                              && literal_c.to_type() == console::program::LiteralType::$input_c {
                                                continue;
                                            })+

                                            // Attempt to compute the invalid operand case.
                                            let result_a = <$operation as $crate::Operation<_, _, _, 3>>::evaluate(&[literal_a.clone(), literal_b.clone(), literal_c.clone()]);
                                            // Ensure the computation failed.
                                            assert!(result_a.is_err(), "An invalid operands case did not fail (console): {literal_a} {literal_b}");

                                            // Attempt to compute the invalid operand case.
                                            let result_b = <$operation as $crate::Operation<_, _, _, 3>>::$execute::<CurrentAleo>(&[
                                                circuit::program::Literal::from_str(&format!("{literal_a}.{mode_a}"))?,
                                                circuit::program::Literal::from_str(&format!("{literal_b}.{mode_b}"))?,
                                                circuit::program::Literal::from_str(&format!("{literal_c}.{mode_c}"))?,
                                            ]);
                                            // Ensure the computation failed.
                                            assert!(result_b.is_err(), "An invalid operands case did not fail (circuit): {literal_a} {literal_b} {literal_c}");
                                            // Reset the circuit.
                                            <CurrentAleo as circuit::Environment>::reset();
                                        }
                                    }
                                }
                            }
                        }
                    }
                    Ok(())
                }
            }
        };

        ////////////////////
        // Private Macros //
        ////////////////////

        // Case 0-A: Unary operation.
        // Case 0-B: Unary operation, where:
        //   1. "ensure overflow halts"
        //     - If the sampled values overflow on evaluation, ensure it halts.
        //     - If the sampled values **do not** overflow on evaluation, ensure it succeeds.
        ($operator:tt::$operate:tt == $operation:tt::$execute:tt $((.$unwrap:tt()))? for $input:ident => $output:ident $( ($($condition:tt),+) )?) => {
            paste::paste! {
                #[test]
                fn [<test _ $operate _ $input:lower _ into _ $output:lower>]() -> Result<()> {
                    // Prepare the rng.
                    let mut rng = TestRng::default();

                    // Ensure the expected output type is correct.
                    assert_eq!(
                        console::program::LiteralType::$output,
                        <$operation as $crate::Operation<_, _, _, 1>>::output_type(&[console::program::LiteralType::$input.into()])?
                    );

                    // Check the operation on randomly-sampled values.
                    for i in 0..150u64 {
                        // Sample the first and second value.
                        #[allow(deprecated)]
                        let a = match i {
                            0 => $input::zero(),
                            1.. => $input::<CurrentNetwork>::rand(&mut rng)
                        };

                        // Initialize an indicator whether the operation should succeed or not.
                        #[allow(unused_mut)]
                        let mut should_succeed = true;
                        /// A helper macro to check the conditions.
                        #[allow(unused_macros)]
                        macro_rules! check_condition {
                            ("ensure overflows halt") => {
                                match *<$operation as $crate::Operation<_, _, _, 1>>::OPCODE {
                                    "abs" => should_succeed &= (*a).checked_abs().is_some(),
                                    "neg" => should_succeed &= (*a).checked_neg().is_some(),
                                    _ => panic!("Unsupported test enforcement for '{}'", <$operation as $crate::Operation<_, _, _, 1>>::OPCODE),
                                }
                            };
                            ("ensure inverse of zero halts") => {
                                should_succeed &= !(*a).is_zero()
                            };
                            ("ensure quadratic nonresidues halt") => {
                                should_succeed &= (*a).sqrt().is_some()
                            };
                        }
                        // Check the conditions.
                        $( $( check_condition!($condition); )+ )?

                        // If `should_succeed` is `true`, compute the expected output.
                        let expected = match should_succeed {
                            true => Some(console::program::Literal::$output(a.$operate()$(.$unwrap())?)),
                            false => None
                        };

                        for mode_a in &[circuit::Mode::Constant, circuit::Mode::Public, circuit::Mode::Private] {
                            // Initialize the operands.
                            let a = console::program::Literal::from_str(&format!("{a}"))?;

                            // Initialize the operands.
                            let first = circuit::program::Literal::from_str(&format!("{a}.{mode_a}"))?;

                            // If this iteration should succeed, ensure the evaluated and executed outputs match the expected output.
                            if should_succeed {
                                // Compute the evaluated output.
                                let candidate_a = <$operation as $crate::Operation<_, _, _, 1>>::evaluate(&[a])?;
                                // Compute the executed output.
                                let candidate_b = <$operation as $crate::Operation<_, _, _, 1>>::$execute::<CurrentAleo>(&[first])?;

                                // Ensure the outputs match.
                                assert_eq!(expected, Some(candidate_a));
                                // Ensure the outputs match.
                                assert_eq!(expected, Some(circuit::Eject::eject_value(&candidate_b)));

                            }
                            // If the sampled values overflow on evaluation, ensure it halts.
                            else {
                                // Halt the evaluation.
                                #[allow(clippy::cloned_ref_to_slice_refs)]
                                let result_a = std::panic::catch_unwind(|| <$operation as $crate::Operation<_, _, _, 1>>::evaluate(&[a.clone()]).unwrap());
                                // Ensure the evaluation halted.
                                assert!(result_a.is_err(), "Failure case (on iteration {i}) did not halt (console): {a}");

                                // Halt the execution.
                                if mode_a.is_constant() {
                                    // Attempt to execute a failure case.
                                    let result_b = std::panic::catch_unwind(|| <$operation as $crate::Operation<_, _, _, 1>>::$execute::<CurrentAleo>(&[first]).unwrap());
                                    // Ensure the execution halted.
                                    assert!(result_b.is_err(), "Failure case (on iteration {i}) did not halt (circuit): {a}");
                                } else {
                                    // Attempt to execute a failure case.
                                    let _result_b = <$operation as $crate::Operation<_, _, _, 1>>::$execute::<CurrentAleo>(&[first])?;
                                    // Ensure the execution halted.
                                    assert!(!<CurrentAleo as circuit::Environment>::is_satisfied(), "Failure case (on iteration {i}) should not be satisfied (circuit): {a}");
                                }
                            }
                            // Reset the circuit.
                            <CurrentAleo as circuit::Environment>::reset();
                        }
                    }

                    Ok(())
                }
            }
        };

        // Case 1-A: Binary operation.
        // Case 1-B: Binary operation, where:
        //   1. "ensure overflow halts" | "ensure exponentiation overflow halts" | "ensure shifting past boundary halts"
        //     - If the sampled values overflow or underflow on evaluation, ensure it halts.
        //     - If the sampled values **do not** overflow or underflow on evaluation, ensure it succeeds.
        //   2. "ensure divide by zero halts"
        //     - If the sampled divisor is zero, ensure it halts.
        //     - If the sampled divisor is **not** zero, ensure it succeeds.
        ($operator:tt::$operate:tt == $operation:tt::$execute:tt for ($input_a:ident, $input_b:ident) => $output:ident $( ($($condition:tt),+) )?) => {
            paste::paste! {
                #[test]
                fn [<test _ $operate _ $input_a:lower _ $input_b:lower _ into _ $output:lower>]() -> Result<()> {
                    // Prepare the rng.
                    let mut rng = TestRng::default();

                    // Ensure the expected output type is correct.
                    assert_eq!(
                        console::program::LiteralType::$output,
                        <$operation as $crate::Operation<_, _, _, 2>>::output_type(&[console::program::LiteralType::$input_a.into(), console::program::LiteralType::$input_b.into()])?
                    );

                    // Determine the number of iterations to run, based on the opcode.
                    let num_iterations: u64 = match *<$operation as $crate::Operation<_, _, _, 2>>::OPCODE {
                        "pow" | "pow.w" => 10,
                        _ => 100
                    };

                    // Check the operation on randomly-sampled values.
                    for i in 0..num_iterations {
                        macro_rules! sample_value {
                            (I8, I8) => { sample_value!(I128, I128) };
                            (I16, I16) => { sample_value!(I128, I128) };
                            (I32, I32) => { sample_value!(I128, I128) };
                            (I64, I64) => { sample_value!(I128, I128) };
                            (I128, I128) => {
                                match i {
                                    0 => ($input_a::zero(), $input_b::zero()),
                                    1 => ($input_a::<CurrentNetwork>::rand(&mut rng), $input_b::zero()),
                                    2 => ($input_a::zero(), $input_b::<CurrentNetwork>::rand(&mut rng)),
                                    3 => ($input_a::MIN, $input_b::zero() - $input_b::one()),
                                    4.. => ($input_b::<CurrentNetwork>::rand(&mut rng), $input_b::<CurrentNetwork>::rand(&mut rng))
                                }
                            };
                            ($lhs:ident, $rhs:ident) => {
                                match i {
                                    0 => ($lhs::zero(), $rhs::zero()),
                                    1 => ($lhs::<CurrentNetwork>::rand(&mut rng), $rhs::zero()),
                                    2 => ($lhs::zero(), $rhs::<CurrentNetwork>::rand(&mut rng)),
                                    3.. => ($lhs::<CurrentNetwork>::rand(&mut rng), $rhs::<CurrentNetwork>::rand(&mut rng))
                                }
                            }
                        }
                        // Sample the first and second value.
                        #[allow(deprecated)]
                        let (a, b) = sample_value!($input_a, $input_b);

                        // This flag is used to determine halting conditions.
                        #[allow(deprecated)]
                        let is_rhs_zero = (*b) == *$input_b::<CurrentNetwork>::zero();

                        // Initialize an indicator whether the operation should succeed or not.
                        #[allow(unused_mut)]
                        let mut should_succeed = true;
                        #[allow(unused_mut)]
                        let mut is_shift_operator = false;
                        #[allow(unused_mut)]
                        let mut shift_exceeds_bitwidth = false;
                        #[allow(unused_mut)]
                        let mut is_division_operator = false;
                        /// A helper macro to check the conditions.
                        #[allow(unused_macros)]
                        macro_rules! check_condition {
                            ("ensure overflows halt") => {
                                match *<$operation as $crate::Operation<_, _, _, 2>>::OPCODE {
                                    "add" => should_succeed &= (*a).checked_add(*b).is_some(),
                                    "div" => should_succeed &= (*a).checked_div(*b).is_some(),
                                    "mul" => should_succeed &= (*a).checked_mul(*b).is_some(),
                                    "rem" => should_succeed &= (*a).checked_rem(*b).is_some(),
                                    "sub" => should_succeed &= (*a).checked_sub(*b).is_some(),
                                    _ => panic!("Unsupported test enforcement for '{}'", <$operation as $crate::Operation<_, _, _, 2>>::OPCODE),
                                }
                            };
                            ("ensure exponentiation overflows halt") => {
                                should_succeed &= (*a).checked_pow((*b) as u32).is_some()
                            };
                            ("ensure shifting past boundary halts") => {
                                match *<$operation as $crate::Operation<_, _, _, 2>>::OPCODE {
                                    // Note that this case needs special handling, since the desired behavior of `checked_shl` deviates from Rust semantics.
                                    "shl" => should_succeed &= console::prelude::CheckedShl::checked_shl(&*a, &(*b as u32)).is_some(),
                                    "shr" => should_succeed &= (*a).checked_shr(*b as u32).is_some(),
                                    _ => panic!("Unsupported test enforcement for '{}'", <$operation as $crate::Operation<_, _, _, 2>>::OPCODE),
                                }
                                // These indicators are later used in the for-loops below.
                                is_shift_operator |= true;
                                let input_a_size_in_bits = u32::try_from($input_a::<CurrentNetwork>::size_in_bits()).expect("Input size in bits exceeded u32::MAX");
                                shift_exceeds_bitwidth |= ((*b as u32) >= input_a_size_in_bits);
                            };
                            ("ensure divide by zero halts") => {
                                should_succeed &= (*b) != *$input_b::<CurrentNetwork>::zero();
                                // This indicator is later used in the for-loops below.
                                is_division_operator |= true;
                            };
                        }
                        // Check the conditions.
                        $( $( check_condition!($condition); )+ )?

                        // If `should_succeed` is `true`, compute the expected output.
                        let expected = match should_succeed {
                            true => Some(console::program::Literal::$output(a.$operate(&b))),
                            false => None
                        };

                        for mode_a in &[circuit::Mode::Constant, circuit::Mode::Public, circuit::Mode::Private] {
                            for mode_b in &[circuit::Mode::Constant, circuit::Mode::Public, circuit::Mode::Private] {
                                // Initialize the operands.
                                let a = console::program::Literal::from_str(&format!("{a}"))?;
                                let b = console::program::Literal::from_str(&format!("{b}"))?;

                                // Initialize the operands.
                                let first = circuit::program::Literal::from_str(&format!("{a}.{mode_a}"))?;
                                let second = circuit::program::Literal::from_str(&format!("{b}.{mode_b}"))?;

                                // This indicator bit is used to check that a case panics on halt,
                                // instead of checking that the circuit is not satisfied (i.e. for `Public|Private && Constant`).
                                let mut should_panic_on_halt = false;
                                // If the operation is a shift operator, check if the mode of the RHS is a constant and if the shift amount exceeds the bitwidth.
                                should_panic_on_halt |= is_shift_operator && shift_exceeds_bitwidth && mode_b.is_constant();
                                // If the operation is a division operator, check if both operands are constant or if the RHS is a constant and zero.
                                should_panic_on_halt |= is_division_operator && (
                                    mode_b.is_constant() && (mode_a.is_constant() || is_rhs_zero)
                                );

                                // If this iteration should succeed, ensure the evaluated and executed outputs match the expected output.
                                if should_succeed {
                                    // Compute the evaluated output.
                                    let candidate_a = <$operation as $crate::Operation<_, _, _, 2>>::evaluate(&[a, b])?;
                                    // Compute the executed output.
                                    let candidate_b = <$operation as $crate::Operation<_, _, _, 2>>::$execute::<CurrentAleo>(&[first, second])?;

                                    // Ensure the outputs match.
                                    assert_eq!(expected, Some(candidate_a));
                                    // Ensure the outputs match.
                                    assert_eq!(expected, Some(circuit::Eject::eject_value(&candidate_b)));

                                }
                                // If the sampled values overflow on evaluation, ensure it halts.
                                else {
                                    // Halt the evaluation.
                                    let result_a = std::panic::catch_unwind(|| <$operation as $crate::Operation<_, _, _, 2>>::evaluate(&[a.clone(), b.clone()]).unwrap());
                                    // Ensure the evaluation halted.
                                    assert!(result_a.is_err(), "Failure case (on iteration {i}) did not halt (console): {a} {b}");

                                    // Halt the execution.
                                    if (mode_a.is_constant() && mode_b.is_constant()) || should_panic_on_halt {
                                        // Attempt to execute a failure case.
                                        let result_b = std::panic::catch_unwind(|| <$operation as $crate::Operation<_, _, _, 2>>::$execute::<CurrentAleo>(&[first, second]).unwrap());
                                        // Ensure the execution halted.
                                        assert!(result_b.is_err(), "Failure case (on iteration {i}) did not halt (circuit): {a} {b}");
                                    } else {
                                        // Attempt to execute a failure case.
                                        let _result_b = <$operation as $crate::Operation<_, _, _, 2>>::$execute::<CurrentAleo>(&[first, second])?;
                                        // Ensure the execution halted.
                                        assert!(!<CurrentAleo as circuit::Environment>::is_satisfied(), "Failure case (on iteration {i}) should not be satisfied (circuit): {a} {b}");
                                    }
                                }
                                // Reset the circuit.
                                <CurrentAleo as circuit::Environment>::reset();
                            }
                        }
                    }

                    Ok(())
                }
            }
        };

        // Case 2-A: Ternary operation.
        // Case 2-B: Ternary operation, where:
        //   1. "ensure overflow halts" | "ensure exponentiation overflow halts" | "ensure shifting past boundary halts"
        //     - If the sampled values overflow or underflow on evaluation, ensure it halts.
        //     - If the sampled values **do not** overflow or underflow on evaluation, ensure it succeeds.
        //   2. "ensure divide by zero halts"
        //     - If the sampled divisor is zero, ensure it halts.
        //     - If the sampled divisor is **not** zero, ensure it succeeds.
        ($operator:tt::$operate:tt == $operation:tt::$execute:tt for ($input_a:ident, $input_b:ident, $input_c:ident) => $output:ident $( ($($condition:tt),+) )?) => {
            paste::paste! {
                #[test]
                fn [<test _ $operate _ $input_a:lower _ $input_b:lower _ $input_c:lower _ into _ $output:lower>]() -> Result<()> {
                    // Prepare the rng.
                    let mut rng = TestRng::default();

                    // Ensure the expected output type is correct.
                    assert_eq!(
                        console::program::LiteralType::$output,
                        <$operation as $crate::Operation<_, _, _, 3>>::output_type(&[console::program::LiteralType::$input_a.into(), console::program::LiteralType::$input_b.into(), console::program::LiteralType::$input_c.into()])?
                    );

                    // Determine the number of iterations to run, based on the opcode.
                    let num_iterations: u64 = match *<$operation as $crate::Operation<_, _, _, 3>>::OPCODE {
                        _ => 100
                    };

                    // Check the operation on randomly-sampled values.
                    for i in 0..num_iterations {
                        // Sample the first, second, and third values.
                        #[allow(deprecated)]
                        let (a, b, c) = match i {
                            0 => ($input_a::zero(), $input_b::zero(), $input_c::zero()),
                            1 => ($input_a::<CurrentNetwork>::rand(&mut rng), $input_b::<CurrentNetwork>::rand(&mut rng), $input_c::zero()),
                            2 => ($input_a::<CurrentNetwork>::rand(&mut rng), $input_b::zero(), $input_c::<CurrentNetwork>::rand(&mut rng)),
                            3 => ($input_a::<CurrentNetwork>::rand(&mut rng), $input_b::zero(), $input_c::zero()),
                            4 => ($input_a::zero(), $input_b::<CurrentNetwork>::rand(&mut rng), $input_c::<CurrentNetwork>::rand(&mut rng)),
                            5 => ($input_a::zero(), $input_b::<CurrentNetwork>::rand(&mut rng), $input_c::<CurrentNetwork>::zero()),
                            6 => ($input_a::zero(), $input_b::zero(), $input_c::<CurrentNetwork>::rand(&mut rng)),
                            7.. => ($input_a::<CurrentNetwork>::rand(&mut rng), $input_b::<CurrentNetwork>::rand(&mut rng), $input_c::<CurrentNetwork>::rand(&mut rng))
                        };

                        // Initialize an indicator whether the operation should succeed or not.
                        #[allow(unused_mut)]
                        let mut should_succeed = true;

                        // If `should_succeed` is `true`, compute the expected output.
                        let expected = match should_succeed {
                            true => Some(console::program::Literal::from_str(&format!("{}", $operator::$operate(&a, &b, &c)))?),
                            false => None
                        };

                        for mode_a in &[circuit::Mode::Constant, circuit::Mode::Public, circuit::Mode::Private] {
                            for mode_b in &[circuit::Mode::Constant, circuit::Mode::Public, circuit::Mode::Private] {
                                for mode_c in &[circuit::Mode::Constant, circuit::Mode::Public, circuit::Mode::Private] {
                                    // Initialize the operands.
                                    let a = console::program::Literal::from_str(&format!("{a}"))?;
                                    let b = console::program::Literal::from_str(&format!("{b}"))?;
                                    let c = console::program::Literal::from_str(&format!("{c}"))?;

                                    // Initialize the operands.
                                    let first = circuit::program::Literal::from_str(&format!("{a}.{mode_a}"))?;
                                    let second = circuit::program::Literal::from_str(&format!("{b}.{mode_b}"))?;
                                    let third = circuit::program::Literal::from_str(&format!("{c}.{mode_c}"))?;

                                    // If this iteration should succeed, ensure the evaluated and executed outputs match the expected output.
                                    if should_succeed {
                                        // Compute the evaluated output.
                                        let candidate_a = <$operation as $crate::Operation<_, _, _, 3>>::evaluate(&[a, b, c])?;
                                        // Compute the executed output.
                                        let candidate_b = <$operation as $crate::Operation<_, _, _, 3>>::$execute::<CurrentAleo>(&[first, second, third])?;

                                        // Ensure the outputs match.
                                        assert_eq!(expected, Some(candidate_a));
                                        // Ensure the outputs match.
                                        assert_eq!(expected, Some(circuit::Eject::eject_value(&candidate_b)));
                                    }
                                    // If the sampled values overflow on evaluation, ensure it halts.
                                    else {
                                        // Halt the evaluation.
                                        let result_a = std::panic::catch_unwind(|| <$operation as $crate::Operation<_, _, _, 3>>::evaluate(&[a.clone(), b.clone(), c.clone()]).unwrap());
                                        // Ensure the evaluation halted.
                                        assert!(result_a.is_err(), "Failure case (on iteration {i}) did not halt (console): {a} {b} {c}");

                                        // Halt the execution.
                                        if (mode_a.is_constant() && mode_b.is_constant() && mode_c.is_constant()) {
                                            // Attempt to execute a failure case.
                                            let result_b = std::panic::catch_unwind(|| <$operation as $crate::Operation<_, _, _, 3>>::$execute::<CurrentAleo>(&[first, second, third]).unwrap());
                                            // Ensure the execution halted.
                                            assert!(result_b.is_err(), "Failure case (on iteration {i}) did not halt (circuit): {a} {b} {c}");
                                        } else {
                                            // Attempt to execute a failure case.
                                            let _result_b = <$operation as $crate::Operation<_, _, _, 3>>::$execute::<CurrentAleo>(&[first, second, third])?;
                                            // Ensure the execution halted.
                                            assert!(!<CurrentAleo as circuit::Environment>::is_satisfied(), "Failure case (on iteration {i}) should not be satisfied (circuit): {a} {b} {c}");
                                        }
                                    }
                                    // Reset the circuit.
                                    <CurrentAleo as circuit::Environment>::reset();
                                }
                            }
                        }
                    }

                    Ok(())
                }
            }
        };
    }
}
