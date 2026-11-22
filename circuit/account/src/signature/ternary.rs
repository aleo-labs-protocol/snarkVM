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

impl<A: Aleo> Ternary for Signature<A> {
    type Boolean = Boolean<A>;
    type Output = Signature<A>;

    /// Returns `first` if `condition` is `true`, otherwise returns `second`.
    fn ternary(condition: &Self::Boolean, first: &Self, second: &Self) -> Self::Output {
        Self {
            challenge: Scalar::ternary(condition, &first.challenge, &second.challenge),
            response: Scalar::ternary(condition, &first.response, &second.response),
            compute_key: ComputeKey::ternary(condition, &first.compute_key, &second.compute_key),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Circuit;
    use console::{TestRng, Uniform};

    fn check_ternary(
        name: &str,
        expected: console::Signature<<Circuit as Environment>::Network>,
        condition: Boolean<Circuit>,
        a: Signature<Circuit>,
        b: Signature<Circuit>,
    ) {
        Circuit::scope(name, || {
            let case = format!("({} ? {} : {})", condition.eject_value(), a.eject_value(), b.eject_value());
            let candidate = Signature::ternary(&condition, &a, &b);
            assert_eq!(expected, candidate.eject_value(), "{case}");
            assert_scope!();
        });
    }

    #[test]
    fn test_constant_condition() {
        let mut rng = TestRng::default();

        let first = console::Signature::from((
            Uniform::rand(&mut rng),
            Uniform::rand(&mut rng),
            console::ComputeKey::try_from(console::PrivateKey::new(&mut rng).unwrap()).unwrap(),
        ));
        let second = console::Signature::from((
            Uniform::rand(&mut rng),
            Uniform::rand(&mut rng),
            console::ComputeKey::try_from(console::PrivateKey::new(&mut rng).unwrap()).unwrap(),
        ));

        // false ? Constant : Constant
        let expected = second;
        let condition = Boolean::<Circuit>::new(Mode::Constant, false);
        let a = Signature::<Circuit>::new(Mode::Constant, first);
        let b = Signature::<Circuit>::new(Mode::Constant, second);
        check_ternary("false ? Constant : Constant", expected, condition, a, b);

        // false ? Constant : Public
        let expected = second;
        let condition = Boolean::<Circuit>::new(Mode::Constant, false);
        let a = Signature::<Circuit>::new(Mode::Constant, first);
        let b = Signature::<Circuit>::new(Mode::Public, second);
        check_ternary("false ? Constant : Public", expected, condition, a, b);

        // false ? Public : Constant
        let expected = second;
        let condition = Boolean::<Circuit>::new(Mode::Constant, false);
        let a = Signature::<Circuit>::new(Mode::Public, first);
        let b = Signature::<Circuit>::new(Mode::Constant, second);
        check_ternary("false ? Public : Constant", expected, condition, a, b);

        // false ? Public : Public
        let expected = second;
        let condition = Boolean::<Circuit>::new(Mode::Constant, false);
        let a = Signature::<Circuit>::new(Mode::Public, first);
        let b = Signature::<Circuit>::new(Mode::Public, second);
        check_ternary("false ? Public : Public", expected, condition, a, b);

        // false ? Public : Private
        let expected = second;
        let condition = Boolean::<Circuit>::new(Mode::Constant, false);
        let a = Signature::<Circuit>::new(Mode::Public, first);
        let b = Signature::<Circuit>::new(Mode::Private, second);
        check_ternary("false ? Public : Private", expected, condition, a, b);

        // false ? Private : Private
        let expected = second;
        let condition = Boolean::<Circuit>::new(Mode::Constant, false);
        let a = Signature::<Circuit>::new(Mode::Private, first);
        let b = Signature::<Circuit>::new(Mode::Private, second);
        check_ternary("false ? Private : Private", expected, condition, a, b);

        // true ? Constant : Constant
        let expected = first;
        let condition = Boolean::<Circuit>::new(Mode::Constant, true);
        let a = Signature::<Circuit>::new(Mode::Constant, first);
        let b = Signature::<Circuit>::new(Mode::Constant, second);
        check_ternary("true ? Constant : Constant", expected, condition, a, b);

        // true ? Constant : Public
        let expected = first;
        let condition = Boolean::<Circuit>::new(Mode::Constant, true);
        let a = Signature::<Circuit>::new(Mode::Constant, first);
        let b = Signature::<Circuit>::new(Mode::Public, second);
        check_ternary("true ? Constant : Public", expected, condition, a, b);

        // true ? Public : Constant
        let expected = first;
        let condition = Boolean::<Circuit>::new(Mode::Constant, true);
        let a = Signature::<Circuit>::new(Mode::Public, first);
        let b = Signature::<Circuit>::new(Mode::Constant, second);
        check_ternary("true ? Public : Constant", expected, condition, a, b);

        // true ? Public : Public
        let expected = first;
        let condition = Boolean::<Circuit>::new(Mode::Constant, true);
        let a = Signature::<Circuit>::new(Mode::Public, first);
        let b = Signature::<Circuit>::new(Mode::Public, second);
        check_ternary("true ? Public : Public", expected, condition, a, b);

        // true ? Public : Private
        let expected = first;
        let condition = Boolean::<Circuit>::new(Mode::Constant, true);
        let a = Signature::<Circuit>::new(Mode::Public, first);
        let b = Signature::<Circuit>::new(Mode::Private, second);
        check_ternary("true ? Public : Private", expected, condition, a, b);

        // true ? Private : Private
        let expected = first;
        let condition = Boolean::<Circuit>::new(Mode::Constant, true);
        let a = Signature::<Circuit>::new(Mode::Private, first);
        let b = Signature::<Circuit>::new(Mode::Private, second);
        check_ternary("true ? Private : Private", expected, condition, a, b);
    }

    #[test]
    fn test_public_condition_and_constant_inputs() {
        let mut rng = TestRng::default();

        let first = console::Signature::from((
            Uniform::rand(&mut rng),
            Uniform::rand(&mut rng),
            console::ComputeKey::try_from(console::PrivateKey::new(&mut rng).unwrap()).unwrap(),
        ));
        let second = console::Signature::from((
            Uniform::rand(&mut rng),
            Uniform::rand(&mut rng),
            console::ComputeKey::try_from(console::PrivateKey::new(&mut rng).unwrap()).unwrap(),
        ));

        // false ? Constant : Constant
        let expected = second;
        let condition = Boolean::<Circuit>::new(Mode::Public, false);
        let a = Signature::<Circuit>::new(Mode::Constant, first);
        let b = Signature::<Circuit>::new(Mode::Constant, second);
        check_ternary("false ? Constant : Constant", expected, condition, a, b);

        // true ? Constant : Constant
        let expected = first;
        let condition = Boolean::<Circuit>::new(Mode::Public, true);
        let a = Signature::<Circuit>::new(Mode::Constant, first);
        let b = Signature::<Circuit>::new(Mode::Constant, second);
        check_ternary("true ? Constant : Constant", expected, condition, a, b);
    }

    #[test]
    fn test_public_condition_and_mixed_inputs() {
        let mut rng = TestRng::default();

        let first = console::Signature::from((
            Uniform::rand(&mut rng),
            Uniform::rand(&mut rng),
            console::ComputeKey::try_from(console::PrivateKey::new(&mut rng).unwrap()).unwrap(),
        ));
        let second = console::Signature::from((
            Uniform::rand(&mut rng),
            Uniform::rand(&mut rng),
            console::ComputeKey::try_from(console::PrivateKey::new(&mut rng).unwrap()).unwrap(),
        ));

        // false ? Constant : Public
        let expected = second;
        let condition = Boolean::<Circuit>::new(Mode::Public, false);
        let a = Signature::<Circuit>::new(Mode::Constant, first);
        let b = Signature::<Circuit>::new(Mode::Public, second);
        check_ternary("false ? Constant : Public", expected, condition, a, b);

        // false ? Public : Constant
        let expected = second;
        let condition = Boolean::<Circuit>::new(Mode::Public, false);
        let a = Signature::<Circuit>::new(Mode::Public, first);
        let b = Signature::<Circuit>::new(Mode::Constant, second);
        check_ternary("false ? Public : Constant", expected, condition, a, b);

        // true ? Constant : Public
        let expected = first;
        let condition = Boolean::<Circuit>::new(Mode::Public, true);
        let a = Signature::<Circuit>::new(Mode::Constant, first);
        let b = Signature::<Circuit>::new(Mode::Public, second);
        check_ternary("true ? Constant : Public", expected, condition, a, b);

        // true ? Public : Constant
        let expected = first;
        let condition = Boolean::<Circuit>::new(Mode::Public, true);
        let a = Signature::<Circuit>::new(Mode::Public, first);
        let b = Signature::<Circuit>::new(Mode::Constant, second);
        check_ternary("true ? Public : Constant", expected, condition, a, b);
    }

    #[test]
    fn test_private_condition_and_constant_inputs() {
        let mut rng = TestRng::default();

        let first = console::Signature::from((
            Uniform::rand(&mut rng),
            Uniform::rand(&mut rng),
            console::ComputeKey::try_from(console::PrivateKey::new(&mut rng).unwrap()).unwrap(),
        ));
        let second = console::Signature::from((
            Uniform::rand(&mut rng),
            Uniform::rand(&mut rng),
            console::ComputeKey::try_from(console::PrivateKey::new(&mut rng).unwrap()).unwrap(),
        ));

        // false ? Constant : Constant
        let expected = second;
        let condition = Boolean::<Circuit>::new(Mode::Private, false);
        let a = Signature::<Circuit>::new(Mode::Constant, first);
        let b = Signature::<Circuit>::new(Mode::Constant, second);
        check_ternary("false ? Constant : Constant", expected, condition, a, b);

        // true ? Constant : Constant
        let expected = first;
        let condition = Boolean::<Circuit>::new(Mode::Private, true);
        let a = Signature::<Circuit>::new(Mode::Constant, first);
        let b = Signature::<Circuit>::new(Mode::Constant, second);
        check_ternary("true ? Constant : Constant", expected, condition, a, b);
    }

    #[test]
    fn test_private_condition_and_mixed_inputs() {
        let mut rng = TestRng::default();

        let first = console::Signature::from((
            Uniform::rand(&mut rng),
            Uniform::rand(&mut rng),
            console::ComputeKey::try_from(console::PrivateKey::new(&mut rng).unwrap()).unwrap(),
        ));
        let second = console::Signature::from((
            Uniform::rand(&mut rng),
            Uniform::rand(&mut rng),
            console::ComputeKey::try_from(console::PrivateKey::new(&mut rng).unwrap()).unwrap(),
        ));

        // false ? Constant : Public
        let expected = second;
        let condition = Boolean::<Circuit>::new(Mode::Private, false);
        let a = Signature::<Circuit>::new(Mode::Constant, first);
        let b = Signature::<Circuit>::new(Mode::Public, second);
        check_ternary("false ? Constant : Public", expected, condition, a, b);

        // false ? Public : Constant
        let expected = second;
        let condition = Boolean::<Circuit>::new(Mode::Private, false);
        let a = Signature::<Circuit>::new(Mode::Public, first);
        let b = Signature::<Circuit>::new(Mode::Constant, second);
        check_ternary("false ? Public : Constant", expected, condition, a, b);

        // true ? Constant : Public
        let expected = first;
        let condition = Boolean::<Circuit>::new(Mode::Private, true);
        let a = Signature::<Circuit>::new(Mode::Constant, first);
        let b = Signature::<Circuit>::new(Mode::Public, second);
        check_ternary("true ? Constant : Public", expected, condition, a, b);

        // true ? Public : Constant
        let expected = first;
        let condition = Boolean::<Circuit>::new(Mode::Private, true);
        let a = Signature::<Circuit>::new(Mode::Public, first);
        let b = Signature::<Circuit>::new(Mode::Constant, second);
        check_ternary("true ? Public : Constant", expected, condition, a, b);
    }

    #[test]
    fn test_public_condition_and_variable_inputs() {
        let mut rng = TestRng::default();

        let first = console::Signature::from((
            Uniform::rand(&mut rng),
            Uniform::rand(&mut rng),
            console::ComputeKey::try_from(console::PrivateKey::new(&mut rng).unwrap()).unwrap(),
        ));
        let second = console::Signature::from((
            Uniform::rand(&mut rng),
            Uniform::rand(&mut rng),
            console::ComputeKey::try_from(console::PrivateKey::new(&mut rng).unwrap()).unwrap(),
        ));

        // false ? Public : Public
        let expected = second;
        let condition = Boolean::<Circuit>::new(Mode::Public, false);
        let a = Signature::<Circuit>::new(Mode::Public, first);
        let b = Signature::<Circuit>::new(Mode::Public, second);
        check_ternary("false ? Public : Public", expected, condition, a, b);

        // false ? Public : Private
        let expected = second;
        let condition = Boolean::<Circuit>::new(Mode::Public, false);
        let a = Signature::<Circuit>::new(Mode::Public, first);
        let b = Signature::<Circuit>::new(Mode::Private, second);
        check_ternary("false ? Public : Private", expected, condition, a, b);

        // false ? Private : Public
        let expected = second;
        let condition = Boolean::<Circuit>::new(Mode::Public, false);
        let a = Signature::<Circuit>::new(Mode::Private, first);
        let b = Signature::<Circuit>::new(Mode::Public, second);
        check_ternary("false ? Private : Public", expected, condition, a, b);

        // false ? Private : Private
        let expected = second;
        let condition = Boolean::<Circuit>::new(Mode::Public, false);
        let a = Signature::<Circuit>::new(Mode::Private, first);
        let b = Signature::<Circuit>::new(Mode::Private, second);
        check_ternary("false ? Private : Private", expected, condition, a, b);

        // true ? Public : Public
        let expected = first;
        let condition = Boolean::<Circuit>::new(Mode::Public, true);
        let a = Signature::<Circuit>::new(Mode::Public, first);
        let b = Signature::<Circuit>::new(Mode::Public, second);
        check_ternary("true ? Public : Public", expected, condition, a, b);

        // true ? Public : Private
        let expected = first;
        let condition = Boolean::<Circuit>::new(Mode::Public, true);
        let a = Signature::<Circuit>::new(Mode::Public, first);
        let b = Signature::<Circuit>::new(Mode::Private, second);
        check_ternary("true ? Public : Private", expected, condition, a, b);

        // true ? Private : Public
        let expected = first;
        let condition = Boolean::<Circuit>::new(Mode::Public, true);
        let a = Signature::<Circuit>::new(Mode::Private, first);
        let b = Signature::<Circuit>::new(Mode::Public, second);
        check_ternary("true ? Private : Public", expected, condition, a, b);

        // true ? Private : Private
        let expected = first;
        let condition = Boolean::<Circuit>::new(Mode::Public, true);
        let a = Signature::<Circuit>::new(Mode::Private, first);
        let b = Signature::<Circuit>::new(Mode::Private, second);
        check_ternary("true ? Private : Private", expected, condition, a, b);
    }

    #[test]
    fn test_private_condition_and_variable_inputs() {
        let mut rng = TestRng::default();

        let first = console::Signature::from((
            Uniform::rand(&mut rng),
            Uniform::rand(&mut rng),
            console::ComputeKey::try_from(console::PrivateKey::new(&mut rng).unwrap()).unwrap(),
        ));
        let second = console::Signature::from((
            Uniform::rand(&mut rng),
            Uniform::rand(&mut rng),
            console::ComputeKey::try_from(console::PrivateKey::new(&mut rng).unwrap()).unwrap(),
        ));

        // false ? Public : Public
        let expected = second;
        let condition = Boolean::<Circuit>::new(Mode::Private, false);
        let a = Signature::<Circuit>::new(Mode::Public, first);
        let b = Signature::<Circuit>::new(Mode::Public, second);
        check_ternary("false ? Public : Public", expected, condition, a, b);

        // false ? Public : Private
        let expected = second;
        let condition = Boolean::<Circuit>::new(Mode::Private, false);
        let a = Signature::<Circuit>::new(Mode::Public, first);
        let b = Signature::<Circuit>::new(Mode::Private, second);
        check_ternary("false ? Public : Private", expected, condition, a, b);

        // false ? Private : Public
        let expected = second;
        let condition = Boolean::<Circuit>::new(Mode::Private, false);
        let a = Signature::<Circuit>::new(Mode::Private, first);
        let b = Signature::<Circuit>::new(Mode::Public, second);
        check_ternary("false ? Private : Public", expected, condition, a, b);

        // false ? Private : Private
        let expected = second;
        let condition = Boolean::<Circuit>::new(Mode::Private, false);
        let a = Signature::<Circuit>::new(Mode::Private, first);
        let b = Signature::<Circuit>::new(Mode::Private, second);
        check_ternary("false ? Private : Private", expected, condition, a, b);

        // true ? Public : Public
        let expected = first;
        let condition = Boolean::<Circuit>::new(Mode::Private, true);
        let a = Signature::<Circuit>::new(Mode::Public, first);
        let b = Signature::<Circuit>::new(Mode::Public, second);
        check_ternary("true ? Public : Public", expected, condition, a, b);

        // true ? Public : Private
        let expected = first;
        let condition = Boolean::<Circuit>::new(Mode::Private, true);
        let a = Signature::<Circuit>::new(Mode::Public, first);
        let b = Signature::<Circuit>::new(Mode::Private, second);
        check_ternary("true ? Public : Private", expected, condition, a, b);

        // true ? Private : Public
        let expected = first;
        let condition = Boolean::<Circuit>::new(Mode::Private, true);
        let a = Signature::<Circuit>::new(Mode::Private, first);
        let b = Signature::<Circuit>::new(Mode::Public, second);
        check_ternary("true ? Private : Public", expected, condition, a, b);

        // true ? Private : Private
        let expected = first;
        let condition = Boolean::<Circuit>::new(Mode::Private, true);
        let a = Signature::<Circuit>::new(Mode::Private, first);
        let b = Signature::<Circuit>::new(Mode::Private, second);
        check_ternary("true ? Private : Private", expected, condition, a, b);
    }
}
