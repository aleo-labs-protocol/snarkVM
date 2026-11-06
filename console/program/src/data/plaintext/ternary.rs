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

impl<N: Network> Ternary for Plaintext<N> {
    type Boolean = Boolean<N>;
    type Output = Self;

    /// Returns `first` if `condition` is `true`, otherwise returns `second`.
    /// The `first` and `second` plaintexts must have the same shape: same variant, arrays of equal
    /// length with matching element shapes, or structs with matching keys in the same order.
    /// Callers are expected to enforce this via type-checking before invocation; mismatched shapes
    /// are treated as unreachable.
    fn ternary(condition: &<Self as Ternary>::Boolean, first: &Self, second: &Self) -> <Self as Ternary>::Output {
        match (first, second) {
            (Self::Literal(a, _), Self::Literal(b, _)) => {
                Self::Literal(Literal::ternary(condition, a, b), OnceLock::new())
            }
            (Self::Array(a, _), Self::Array(b, _)) if a.len() == b.len() => {
                let elements = a.iter().zip_eq(b.iter()).map(|(x, y)| Plaintext::ternary(condition, x, y)).collect();
                Self::Array(elements, OnceLock::new())
            }
            (Self::Struct(a, _), Self::Struct(b, _))
                if a.len() == b.len() && a.keys().zip(b.keys()).all(|(ka, kb)| ka == kb) =>
            {
                let fields = a
                    .iter()
                    .zip_eq(b.iter())
                    .map(|((key, x), (_, y))| (*key, Plaintext::ternary(condition, x, y)))
                    .collect();
                Self::Struct(fields, OnceLock::new())
            }
            _ => unreachable!("ternary operands must have equivalent shape after type-checking"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use snarkvm_console_network::MainnetV0;

    use core::str::FromStr;

    type CurrentNetwork = MainnetV0;

    fn check_both_branches(first: &Plaintext<CurrentNetwork>, second: &Plaintext<CurrentNetwork>) {
        let true_ = Boolean::<CurrentNetwork>::new(true);
        let false_ = Boolean::<CurrentNetwork>::new(false);
        assert_eq!(first, &Plaintext::ternary(&true_, first, second));
        assert_eq!(second, &Plaintext::ternary(&false_, first, second));
    }

    #[test]
    fn test_plaintext_ternary_literal() {
        let first = Plaintext::<CurrentNetwork>::from_str("1field").unwrap();
        let second = Plaintext::<CurrentNetwork>::from_str("2field").unwrap();
        check_both_branches(&first, &second);
    }

    #[test]
    fn test_plaintext_ternary_flat_array() {
        let first = Plaintext::<CurrentNetwork>::from_str("[ 1field, 2field, 3field ]").unwrap();
        let second = Plaintext::<CurrentNetwork>::from_str("[ 4field, 5field, 6field ]").unwrap();
        check_both_branches(&first, &second);
    }

    #[test]
    fn test_plaintext_ternary_nested_array() {
        let first = Plaintext::<CurrentNetwork>::from_str("[ [ 1u8, 2u8 ], [ 3u8, 4u8 ] ]").unwrap();
        let second = Plaintext::<CurrentNetwork>::from_str("[ [ 5u8, 6u8 ], [ 7u8, 8u8 ] ]").unwrap();
        check_both_branches(&first, &second);
    }

    #[test]
    fn test_plaintext_ternary_struct() {
        let first = Plaintext::<CurrentNetwork>::from_str("{ x: 1field, y: 2field }").unwrap();
        let second = Plaintext::<CurrentNetwork>::from_str("{ x: 3field, y: 4field }").unwrap();
        check_both_branches(&first, &second);
    }

    #[test]
    fn test_plaintext_ternary_struct_of_arrays() {
        let first = Plaintext::<CurrentNetwork>::from_str("{ a: [ 1u8, 2u8 ], b: 3field }").unwrap();
        let second = Plaintext::<CurrentNetwork>::from_str("{ a: [ 4u8, 5u8 ], b: 6field }").unwrap();
        check_both_branches(&first, &second);
    }

    #[test]
    fn test_plaintext_ternary_array_of_structs() {
        let first =
            Plaintext::<CurrentNetwork>::from_str("[ { x: 1field, y: 2field }, { x: 3field, y: 4field } ]").unwrap();
        let second =
            Plaintext::<CurrentNetwork>::from_str("[ { x: 5field, y: 6field }, { x: 7field, y: 8field } ]").unwrap();
        check_both_branches(&first, &second);
    }

    #[test]
    #[should_panic(expected = "ternary operands must have equivalent shape")]
    fn test_plaintext_ternary_array_length_mismatch_panics() {
        let first = Plaintext::<CurrentNetwork>::from_str("[ 1field, 2field ]").unwrap();
        let second = Plaintext::<CurrentNetwork>::from_str("[ 3field, 4field, 5field ]").unwrap();
        let cond = Boolean::<CurrentNetwork>::new(false);
        let _ = Plaintext::ternary(&cond, &first, &second);
    }

    #[test]
    #[should_panic(expected = "ternary operands must have equivalent shape")]
    fn test_plaintext_ternary_struct_key_order_mismatch_panics() {
        let first = Plaintext::<CurrentNetwork>::from_str("{ x: 1field, y: 2field }").unwrap();
        let second = Plaintext::<CurrentNetwork>::from_str("{ y: 3field, x: 4field }").unwrap();
        let cond = Boolean::<CurrentNetwork>::new(false);
        let _ = Plaintext::ternary(&cond, &first, &second);
    }

    #[test]
    #[should_panic(expected = "ternary operands must have equivalent shape")]
    fn test_plaintext_ternary_variant_mismatch_panics() {
        let first = Plaintext::<CurrentNetwork>::from_str("1field").unwrap();
        let second = Plaintext::<CurrentNetwork>::from_str("[ 1field ]").unwrap();
        let cond = Boolean::<CurrentNetwork>::new(false);
        let _ = Plaintext::ternary(&cond, &first, &second);
    }
}
