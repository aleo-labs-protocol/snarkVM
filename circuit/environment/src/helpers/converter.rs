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

use crate::{CanaryCircuit, Circuit, LinearCombination, R1CS, TestnetCircuit, Variable};
use snarkvm_curves::edwards_bls12::Fq;
use snarkvm_fields::PrimeField;

use indexmap::IndexMap;

/// A struct for tracking the mapping of variables from the virtual machine (first) to the gadget constraint system (second).
struct Converter {
    public: IndexMap<u64, snarkvm_algorithms::r1cs::Variable>,
    private: IndexMap<u64, snarkvm_algorithms::r1cs::Variable>,
}

impl snarkvm_algorithms::r1cs::ConstraintSynthesizer<Fq> for Circuit {
    /// Synthesizes the constraints from the environment into a `snarkvm_algorithms::r1cs`-compliant constraint system.
    fn generate_constraints<CS: snarkvm_algorithms::r1cs::ConstraintSystem<Fq>>(
        &self,
        cs: &mut CS,
    ) -> Result<(), snarkvm_algorithms::r1cs::SynthesisError> {
        crate::circuit::CIRCUIT.with(|circuit| circuit.borrow().generate_constraints(cs))
    }
}

impl snarkvm_algorithms::r1cs::ConstraintSynthesizer<Fq> for TestnetCircuit {
    /// Synthesizes the constraints from the environment into a `snarkvm_algorithms::r1cs`-compliant constraint system.
    fn generate_constraints<CS: snarkvm_algorithms::r1cs::ConstraintSystem<Fq>>(
        &self,
        cs: &mut CS,
    ) -> Result<(), snarkvm_algorithms::r1cs::SynthesisError> {
        crate::testnet_circuit::TESTNET_CIRCUIT.with(|circuit| circuit.borrow().generate_constraints(cs))
    }
}

impl snarkvm_algorithms::r1cs::ConstraintSynthesizer<Fq> for CanaryCircuit {
    /// Synthesizes the constraints from the environment into a `snarkvm_algorithms::r1cs`-compliant constraint system.
    fn generate_constraints<CS: snarkvm_algorithms::r1cs::ConstraintSystem<Fq>>(
        &self,
        cs: &mut CS,
    ) -> Result<(), snarkvm_algorithms::r1cs::SynthesisError> {
        crate::canary_circuit::CANARY_CIRCUIT.with(|circuit| circuit.borrow().generate_constraints(cs))
    }
}

impl<F: PrimeField> R1CS<F> {
    /// Synthesizes the constraints from the environment into a `snarkvm_algorithms::r1cs`-compliant constraint system.
    fn generate_constraints<CS: snarkvm_algorithms::r1cs::ConstraintSystem<F>>(
        &self,
        cs: &mut CS,
    ) -> Result<(), snarkvm_algorithms::r1cs::SynthesisError> {
        let mut converter = Converter { public: Default::default(), private: Default::default() };

        // Ensure the given `cs` is starting off clean.
        assert_eq!(1, cs.num_public_variables());
        assert_eq!(0, cs.num_private_variables());
        assert_eq!(0, cs.num_constraints());

        let result = converter.public.insert(0, CS::one());
        assert!(result.is_none(), "Overwrote an existing public variable in the converter");

        // Allocate the public variables.
        // NOTE: we skip the first public `One` variable because we already allocated it in the `ConstraintSystem` constructor.
        for (i, public) in self.to_public_variables().iter().skip(1).enumerate() {
            match public {
                Variable::Public(index_value) => {
                    let (index, value) = index_value.as_ref();

                    assert_eq!(
                        (i + 1) as u64,
                        *index,
                        "Public vars in first system must be processed in lexicographic order"
                    );

                    let gadget = cs.alloc_input(|| format!("Public {i}"), || Ok(*value))?;

                    assert_eq!(
                        snarkvm_algorithms::r1cs::Index::Public(*index as usize),
                        gadget.get_unchecked(),
                        "Public variables in the second system must match the first system"
                    );

                    let result = converter.public.insert(*index, gadget);

                    assert!(result.is_none(), "Overwrote an existing public variable in the converter");
                }
                _ => unreachable!("Public variables in the first system are not well-formed"),
            }
        }

        // Allocate the private variables.
        for (i, private) in self.to_private_variables().iter().enumerate() {
            match private {
                Variable::Private(index_value) => {
                    let (index, value) = index_value.as_ref();

                    assert_eq!(
                        i as u64, *index,
                        "Private variables in first system must be processed in lexicographic order"
                    );

                    let gadget = cs.alloc(|| format!("Private {i}"), || Ok(*value))?;

                    assert_eq!(
                        snarkvm_algorithms::r1cs::Index::Private(i),
                        gadget.get_unchecked(),
                        "Private variables in the second system must match the first system"
                    );

                    let result = converter.private.insert(*index, gadget);

                    assert!(result.is_none(), "Overwrote an existing private variable in the converter");
                }
                _ => unreachable!("Private variables in the first system are not well-formed"),
            }
        }

        // Enforce all of the constraints.
        for (i, constraint) in self.to_constraints().iter().enumerate() {
            // Converts terms from one linear combination in the first system to the second system.
            let convert_linear_combination =
                |lc: &LinearCombination<F>| -> snarkvm_algorithms::r1cs::LinearCombination<F> {
                    // Initialize a linear combination for the second system.
                    let mut linear_combination = snarkvm_algorithms::r1cs::LinearCombination::<F>::zero();

                    // Process every term in the linear combination.
                    for (variable, coefficient) in lc.to_terms() {
                        match variable {
                            Variable::Constant(_) => {
                                unreachable!(
                                    "Failed during constraint translation. The first system by definition cannot have constant variables in the terms"
                                )
                            }
                            Variable::Public(index_value) => {
                                let (index, _value) = index_value.as_ref();
                                let gadget = converter.public.get(index).unwrap();
                                linear_combination += (*coefficient, *gadget);
                            }
                            Variable::Private(index_value) => {
                                let (index, _value) = index_value.as_ref();
                                let gadget = converter.private.get(index).unwrap();
                                linear_combination += (*coefficient, *gadget);
                            }
                        }
                    }

                    // Finally, add the accumulated constant value to the linear combination.
                    if !lc.to_constant().is_zero() {
                        linear_combination += (
                            lc.to_constant(),
                            snarkvm_algorithms::r1cs::Variable::new_unchecked(snarkvm_algorithms::r1cs::Index::Public(
                                0,
                            )),
                        );
                    }

                    // Return the linear combination of the second system.
                    linear_combination
                };

            let (a, b, c) = constraint.to_terms();

            cs.enforce(
                || format!("Constraint {i}"),
                |lc| lc + convert_linear_combination(a),
                |lc| lc + convert_linear_combination(b),
                |lc| lc + convert_linear_combination(c),
            );
        }

        // Ensure the given `cs` matches in size with the first system.
        assert_eq!(self.num_public(), cs.num_public_variables() as u64);
        assert_eq!(self.num_private(), cs.num_private_variables() as u64);
        assert_eq!(self.num_constraints(), cs.num_constraints() as u64);

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use snarkvm_algorithms::{AlgebraicSponge, SNARK, r1cs::ConstraintSynthesizer, snark::varuna::VarunaVersion};
    use snarkvm_circuit::prelude::*;
    use snarkvm_curves::bls12_377::Fr;

    /// Compute 2^EXPONENT - 1, in a purposefully constraint-inefficient manner for testing.
    fn create_example_circuit<E: Environment>() -> Field<E> {
        let one = snarkvm_console_types::Field::<E::Network>::one();
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

    /// Converts the circuit into a `TestConstraintSystem` and checks its sizes and satisfiability.
    fn assert_converts() {
        use snarkvm_algorithms::r1cs::ConstraintSystem;

        let mut cs = snarkvm_algorithms::r1cs::TestConstraintSystem::new();
        Circuit.generate_constraints(&mut cs).unwrap();
        assert_eq!(Circuit::num_public(), cs.num_public_variables() as u64);
        assert_eq!(Circuit::num_private(), cs.num_private_variables() as u64);
        assert_eq!(Circuit::num_constraints(), cs.num_constraints() as u64);
        assert!(cs.is_satisfied());
    }

    #[test]
    fn test_constraint_converter() {
        let _candidate_output = create_example_circuit::<Circuit>();
        assert_converts();
    }

    #[test]
    fn test_constraint_converter_with_public_terms() {
        let one = snarkvm_console_types::Field::<<Circuit as Environment>::Network>::one();
        let two = one + one;
        let three = two + one;
        let public = Field::<Circuit>::new(Mode::Public, two);
        let private = Field::<Circuit>::new(Mode::Private, three);
        // The product constraint has the public variable as a term.
        let _product = &public * &private;
        assert_eq!(1, Circuit::num_constraints());
        assert_converts();
    }

    #[test]
    fn test_varuna() {
        let _candidate_output = create_example_circuit::<Circuit>();
        let one = snarkvm_console_types::Field::<<Circuit as Environment>::Network>::one();

        // Varuna setup, prove, and verify.

        use snarkvm_algorithms::{
            crypto_hash::PoseidonSponge,
            snark::varuna::{VarunaHidingMode, VarunaSNARK, ahp::AHPForR1CS},
        };
        use snarkvm_curves::bls12_377::{Bls12_377, Fq};
        use snarkvm_utilities::rand::TestRng;

        type FS = PoseidonSponge<Fq, 2, 1>;
        type VarunaInst = VarunaSNARK<Bls12_377, FS, VarunaHidingMode>;

        let rng = &mut TestRng::default();

        let max_degree = AHPForR1CS::<Fr, VarunaHidingMode>::max_degree(200, 200, 300).unwrap();
        let universal_srs = VarunaInst::universal_setup(max_degree).unwrap();
        let universal_prover = &universal_srs.to_universal_prover().unwrap();
        let universal_verifier = &universal_srs.to_universal_verifier().unwrap();
        let fs_pp = FS::sample_parameters();

        let (index_pk, index_vk) = VarunaInst::circuit_setup(&universal_srs, &Circuit).unwrap();
        let varuna_version = VarunaVersion::V2;
        println!("Called circuit setup");

        let proof = VarunaInst::prove(universal_prover, &fs_pp, &index_pk, varuna_version, &Circuit, rng).unwrap();
        println!("Called prover");

        assert!(
            VarunaInst::verify(universal_verifier, &fs_pp, &index_vk, varuna_version, [*one, *one], &proof).unwrap()
        );
        println!("Called verifier");
        println!("\nShould not verify (i.e. verifier messages should print below):");
        assert!(
            !VarunaInst::verify(universal_verifier, &fs_pp, &index_vk, varuna_version, [*one, *one + *one], &proof)
                .unwrap()
        );
    }
}
