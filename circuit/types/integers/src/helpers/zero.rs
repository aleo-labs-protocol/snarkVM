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

impl<E: Environment, I: IntegerType> Zero for Integer<E, I> {
    type Boolean = Boolean<E>;

    fn zero() -> Self {
        Integer::constant(console::Integer::zero())
    }

    fn is_zero(&self) -> Self::Boolean {
        self.is_equal(&Integer::zero())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use snarkvm_circuit_environment::Circuit;

    fn check_zero<I: IntegerType>() {
        Circuit::scope("Zero", || {
            assert_scope!(0, 0, 0, 0);
            let candidate = Integer::<Circuit, I>::zero();
            assert_eq!(console::Integer::zero(), candidate.eject_value());
            assert!(candidate.is_constant());
            assert_scope!(I::BITS, 0, 0, 0);
        });
        // Should equal 0.
        assert!(Integer::<Circuit, I>::zero().is_zero().eject_value());
        // Should not equal 1.
        assert!(!Integer::<Circuit, I>::zero().is_one().eject_value());
        // Reset the circuit.
        Circuit::reset();
    }

    test_integer_static!(check_zero, i8, zero);
    test_integer_static!(check_zero, i16, zero);
    test_integer_static!(check_zero, i32, zero);
    test_integer_static!(check_zero, i64, zero);
    test_integer_static!(check_zero, i128, zero);

    test_integer_static!(check_zero, u8, zero);
    test_integer_static!(check_zero, u16, zero);
    test_integer_static!(check_zero, u32, zero);
    test_integer_static!(check_zero, u64, zero);
    test_integer_static!(check_zero, u128, zero);
}
