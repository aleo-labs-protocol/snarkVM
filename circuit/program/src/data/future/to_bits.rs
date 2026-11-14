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

use super::*;
use snarkvm_circuit_types::{U8, U32};

impl<A: Aleo> ToBits for Future<A> {
    type Boolean = Boolean<A>;

    /// Returns the circuit future as a list of **little-endian** bits.
    #[inline]
    fn write_bits_le(&self, vec: &mut Vec<Boolean<A>>) {
        // Write the bits for the program ID.
        let program_id_bits = self.program_id.to_bits_le();
        let program_id_size =
            u16::try_from(program_id_bits.len()).unwrap_or_else(|_| A::halt("Program ID exceeds u16::MAX bits"));
        U16::constant(console::U16::new(program_id_size)).write_bits_le(vec);
        vec.extend_from_slice(&program_id_bits);

        // Write the bits for the function name.
        let function_name_bits = self.function_name.to_bits_le();
        let function_name_size =
            u16::try_from(function_name_bits.len()).unwrap_or_else(|_| A::halt("Function name exceeds u16::MAX bits"));
        U16::constant(console::U16::new(function_name_size)).write_bits_le(vec);
        vec.extend_from_slice(&function_name_bits);

        // Write the number of arguments.
        let num_arguments = u8::try_from(self.arguments.len()).unwrap_or_else(|_| A::halt("arguments exceed u8::MAX"));
        U8::constant(console::U8::new(num_arguments)).write_bits_le(vec);

        // Write the arguments.
        for argument in &self.arguments {
            let argument_bits = argument.to_bits_le();
            // Write the size of the argument.
            let argument_length = argument_bits.len();
            match u16::try_from(argument_length) {
                Ok(argument_length) => U16::constant(console::U16::new(argument_length)).write_bits_le(vec),
                Err(_) => match u32::try_from(argument_length) {
                    Ok(argument_length) => U32::constant(console::U32::new(argument_length)).write_bits_le(vec),
                    Err(_) => A::halt("argument exceeds u32::MAX bits"),
                },
            }
            // Write the argument.
            vec.extend_from_slice(&argument_bits);
        }
    }

    /// Returns the circuit future as a list of **big-endian** bits.
    #[inline]
    fn write_bits_be(&self, vec: &mut Vec<Boolean<A>>) {
        // Write the bits for the program ID.
        let program_id_bits = self.program_id.to_bits_be();
        let program_id_size =
            u16::try_from(program_id_bits.len()).unwrap_or_else(|_| A::halt("Program ID exceeds u16::MAX bits"));
        U16::constant(console::U16::new(program_id_size)).write_bits_be(vec);
        vec.extend_from_slice(&program_id_bits);

        // Write the bits for the function name.
        let function_name_bits = self.function_name.to_bits_be();
        let function_name_size =
            u16::try_from(function_name_bits.len()).unwrap_or_else(|_| A::halt("Function name exceeds u16::MAX bits"));
        U16::constant(console::U16::new(function_name_size)).write_bits_be(vec);
        vec.extend_from_slice(&function_name_bits);

        // Write the number of arguments.
        let num_arguments = u8::try_from(self.arguments.len()).unwrap_or_else(|_| A::halt("arguments exceed u8::MAX"));
        U8::constant(console::U8::new(num_arguments)).write_bits_be(vec);

        // Write the arguments.
        for argument in &self.arguments {
            let argument_bits = argument.to_bits_be();
            // Write the size of the argument.
            let argument_length = argument_bits.len();
            match u16::try_from(argument_length) {
                Ok(argument_length) => U16::constant(console::U16::new(argument_length)).write_bits_be(vec),
                Err(_) => match u32::try_from(argument_length) {
                    Ok(argument_length) => U32::constant(console::U32::new(argument_length)).write_bits_be(vec),
                    Err(_) => A::halt("argument exceeds u32::MAX bits"),
                },
            }
            // Write the argument.
            vec.extend_from_slice(&argument_bits);
        }
    }
}
