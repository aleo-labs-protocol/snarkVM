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

impl<E: Environment, I: IntegerType> One for Integer<E, I> {
    type Boolean = Boolean<E>;

    fn one() -> Self {
        Integer::constant(console::Integer::one())
    }

    fn is_one(&self) -> Self::Boolean {
        self.is_equal(&Integer::one())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use snarkvm_circuit_environment::Circuit;

    fn check_one<I: IntegerType>() {
        Circuit::scope("One", || {
            assert_scope!(0, 0, 0, 0);
            let candidate = Integer::<Circuit, I>::one();
            assert_eq!(console::Integer::one(), candidate.eject_value());
            assert!(candidate.is_constant());
            assert_scope!(I::BITS, 0, 0, 0);
        });
        // Should equal 1.
        assert!(Integer::<Circuit, I>::one().is_one().eject_value());
        // Should not equal 0.
        assert!(!Integer::<Circuit, I>::one().is_zero().eject_value());
        // Reset the circuit.
        Circuit::reset();
    }

    test_integer_static!(check_one, i8, one);
    test_integer_static!(check_one, i16, one);
    test_integer_static!(check_one, i32, one);
    test_integer_static!(check_one, i64, one);
    test_integer_static!(check_one, i128, one);

    test_integer_static!(check_one, u8, one);
    test_integer_static!(check_one, u16, one);
    test_integer_static!(check_one, u32, one);
    test_integer_static!(check_one, u64, one);
    test_integer_static!(check_one, u128, one);
}
