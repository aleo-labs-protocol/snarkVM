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

mod helpers;

mod hash;
mod hash_many;
mod hash_to_group;
mod hash_to_scalar;
mod prf;

use crate::{Elligator2, poseidon::helpers::*};
use snarkvm_console_types::prelude::*;
use snarkvm_fields::{PoseidonDefaultField, PoseidonParameters};

use std::sync::{Arc, OnceLock};

const CAPACITY: usize = 1;

/// Poseidon2 is a cryptographic hash function of input rate 2.
pub type Poseidon2<E> = Poseidon<E, 2>;
/// Poseidon4 is a cryptographic hash function of input rate 4.
pub type Poseidon4<E> = Poseidon<E, 4>;
/// Poseidon8 is a cryptographic hash function of input rate 8.
pub type Poseidon8<E> = Poseidon<E, 8>;

#[derive(Clone, Debug)]
pub struct Poseidon<E: Environment, const RATE: usize> {
    /// The domain separator for the Poseidon hash function.
    domain: Field<E>,
    /// The Poseidon parameters for hashing.
    parameters: Arc<PoseidonParameters<E::Field, RATE, CAPACITY>>,
    /// The Merkle empty hash of this instance, once something has asked for it.
    empty_hash: OnceLock<Field<E>>,
}

impl<E: Environment, const RATE: usize> PartialEq for Poseidon<E, RATE> {
    /// Ignores the cached empty hash, which is derived from the domain and parameters.
    fn eq(&self, other: &Self) -> bool {
        // Destructured so that a new field must be considered here.
        let Self { domain, parameters, empty_hash: _ } = self;
        *domain == other.domain && *parameters == other.parameters
    }
}

impl<E: Environment, const RATE: usize> Poseidon<E, RATE> {
    /// Initializes a new instance of Poseidon.
    pub fn setup(domain: &str) -> Result<Self> {
        // Ensure the given domain is within the allowed size in bits.
        let num_bits = domain.len().saturating_mul(8);
        let max_bits = Field::<E>::size_in_data_bits();
        ensure!(num_bits <= max_bits, "Domain cannot exceed {max_bits} bits, found {num_bits} bits");

        Ok(Self {
            domain: Field::<E>::new_domain_separator(domain),
            parameters: Arc::new(E::Field::default_poseidon_parameters::<RATE>()?),
            empty_hash: OnceLock::new(),
        })
    }

    /// Returns the domain separator for the hash function.
    pub fn domain(&self) -> Field<E> {
        self.domain
    }

    /// Returns the Poseidon parameters for hashing.
    pub fn parameters(&self) -> &Arc<PoseidonParameters<E::Field, RATE, CAPACITY>> {
        &self.parameters
    }

    /// Returns the Merkle empty hash of this instance, computing it on first use.
    ///
    /// This is `PathHash::hash_children(0, 0)` from `snarkvm-console-collections`, and
    /// `test_cached_empty_hash_matches_the_computed_one` checks that the two agree. The
    /// hash depends on the domain, so it is cached per instance, not per type.
    pub fn merkle_empty_hash(&self) -> Result<Field<E>> {
        if let Some(empty_hash) = self.empty_hash.get() {
            return Ok(*empty_hash);
        }
        // Prepend the nodes with a `1field` byte.
        let input = [Field::<E>::one(), Field::<E>::zero(), Field::<E>::zero()];
        let empty_hash = Hash::hash(self, &input)?;
        Ok(*self.empty_hash.get_or_init(|| empty_hash))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use snarkvm_console_types::environment::Console;
    use snarkvm_curves::edwards_bls12::Fq;
    use snarkvm_fields::{PoseidonDefaultField, PoseidonGrainLFSR};

    type CurrentEnvironment = Console;

    use std::{path::PathBuf, sync::Arc};

    /// Returns the path to the `resources` folder for this module.
    fn resources_path() -> PathBuf {
        // Construct the path for the `resources` folder.
        let mut path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        path.push("src");
        path.push("poseidon");
        path.push("resources");

        // Create the `resources` folder, if it does not exist.
        if !path.exists() {
            std::fs::create_dir_all(&path).unwrap_or_else(|_| panic!("Failed to create resources folder: {path:?}"));
        }
        // Output the path.
        path
    }

    /// Loads the given `test_folder/test_file` and asserts the given `candidate` matches the expected values.
    #[track_caller]
    fn assert_snapshot<S1: Into<String>, S2: Into<String>, C: Debug>(test_folder: S1, test_file: S2, candidate: C) {
        // Construct the path for the test folder.
        let mut path = resources_path();
        path.push(test_folder.into());

        // Create the test folder, if it does not exist.
        if !path.exists() {
            std::fs::create_dir(&path).unwrap_or_else(|_| panic!("Failed to create test folder: {path:?}"));
        }

        // Construct the path for the test file.
        path.push(test_file.into());
        path.set_extension("snap");

        // Create the test file, if it does not exist.
        if !path.exists() {
            std::fs::File::create(&path).unwrap_or_else(|_| panic!("Failed to create file: {path:?}"));
        }

        // Assert the test file is equal to the expected value.
        expect_test::expect_file![path].assert_eq(&format!("{candidate:?}"));
    }

    #[test]
    fn test_grain_lfsr() -> Result<()> {
        let mut lfsr = PoseidonGrainLFSR::new(false, 253, 3, 8, 31);
        assert_snapshot("test_grain_lfsr", "first_sample", lfsr.get_field_elements_rejection_sampling::<Fq>(1)?);
        assert_snapshot("test_grain_lfsr", "second_sample", lfsr.get_field_elements_rejection_sampling::<Fq>(1)?);
        Ok(())
    }

    #[test]
    fn test_sponge() {
        const RATE: usize = 2;
        let parameters = Arc::new(Fq::default_poseidon_parameters::<RATE>().unwrap());

        for absorb in 0..10 {
            for squeeze in 0..10 {
                let iteration = format!("absorb_{absorb}_squeeze_{squeeze}");

                let mut sponge = PoseidonSponge::<CurrentEnvironment, RATE, CAPACITY>::new(&parameters);
                sponge.absorb(&vec![Field::<CurrentEnvironment>::from_u64(1237812u64); absorb]);

                let next_absorb_index = if absorb % RATE != 0 || absorb == 0 { absorb % RATE } else { RATE };
                assert_eq!(sponge.mode, DuplexSpongeMode::Absorbing { next_absorb_index }, "{iteration}");

                assert_snapshot("test_sponge", &iteration, sponge.squeeze(u16::try_from(squeeze).unwrap()));

                let next_squeeze_index = if squeeze % RATE != 0 || squeeze == 0 { squeeze % RATE } else { RATE };
                match squeeze == 0 {
                    true => assert_eq!(sponge.mode, DuplexSpongeMode::Absorbing { next_absorb_index }, "{iteration}"),
                    false => assert_eq!(sponge.mode, DuplexSpongeMode::Squeezing { next_squeeze_index }, "{iteration}"),
                }
            }
        }
    }

    #[test]
    fn test_parameters() {
        fn single_rate_test<const RATE: usize>() {
            let parameters = Fq::default_poseidon_parameters::<RATE>().unwrap();
            assert_snapshot("test_parameters", format!("rate_{RATE}_ark"), parameters.ark);
            assert_snapshot("test_parameters", format!("rate_{RATE}_mds"), parameters.mds);
        }
        // Optimized for constraints.
        single_rate_test::<2>();
        single_rate_test::<3>();
        single_rate_test::<4>();
        single_rate_test::<5>();
        single_rate_test::<6>();
        single_rate_test::<7>();
        single_rate_test::<8>();
    }

    #[test]
    fn test_suite_hash2() {
        fn test_case_hash2(index: u8, input: Vec<Field<CurrentEnvironment>>) {
            let poseidon2 = Poseidon2::<Console>::setup("Poseidon2").unwrap();
            assert_snapshot("test_hash", format!("rate_2_test_{index}"), poseidon2.hash(&input).unwrap());
        }
        test_case_hash2(0, vec![]);
        test_case_hash2(1, vec![Field::<Console>::from_u8(0)]);
        test_case_hash2(2, vec![Field::<Console>::from_u8(1)]);
        test_case_hash2(3, vec![Field::<Console>::from_u8(0), Field::<Console>::from_u8(1)]);
        test_case_hash2(4, vec![Field::<Console>::from_u8(7), Field::<Console>::from_u8(6)]);
    }

    #[test]
    fn test_suite_hash4() {
        fn test_case_hash4(index: u8, input: Vec<Field<CurrentEnvironment>>) {
            let poseidon4 = Poseidon4::<Console>::setup("Poseidon4").unwrap();
            assert_snapshot("test_hash", format!("rate_4_test_{index}"), poseidon4.hash(&input).unwrap());
        }
        test_case_hash4(0, vec![]);
        test_case_hash4(1, vec![Field::<Console>::from_u8(0)]);
        test_case_hash4(2, vec![Field::<Console>::from_u8(1)]);
        test_case_hash4(3, vec![Field::<Console>::from_u8(0), Field::<Console>::from_u8(1)]);
        test_case_hash4(4, vec![Field::<Console>::from_u8(7), Field::<Console>::from_u8(6)]);
        test_case_hash4(5, vec![
            Field::<Console>::from_str(
                "3801852864665033841774715284518384682376829752661853198612247855579120198106field",
            )
            .unwrap(),
            Field::<Console>::from_str(
                "8354898322875240371401674517397790035008442020361740574117886421279083828480field",
            )
            .unwrap(),
            Field::<Console>::from_str(
                "4810388512520169167962815122521832339992376865086300759308552937986944510606field",
            )
            .unwrap(),
        ]);
        test_case_hash4(6, vec![
            Field::<Console>::from_str(
                "3801852864665033841774715284518384682376829752661853198612247855579120198106field",
            )
            .unwrap(),
            Field::<Console>::from_str(
                "8354898322875240371401674517397790035008442020361740574117886421279083828480field",
            )
            .unwrap(),
            Field::<Console>::from_str(
                "4810388512520169167962815122521832339992376865086300759308552937986944510606field",
            )
            .unwrap(),
            Field::<Console>::from_str(
                "1806278863067630397941269234951941896370617486625414347832536440203404317871field",
            )
            .unwrap(),
        ]);
        test_case_hash4(7, vec![
            Field::<Console>::from_str(
                "3801852864665033841774715284518384682376829752661853198612247855579120198106field",
            )
            .unwrap(),
            Field::<Console>::from_str(
                "8354898322875240371401674517397790035008442020361740574117886421279083828480field",
            )
            .unwrap(),
            Field::<Console>::from_str(
                "4810388512520169167962815122521832339992376865086300759308552937986944510606field",
            )
            .unwrap(),
            Field::<Console>::from_str(
                "1806278863067630397941269234951941896370617486625414347832536440203404317871field",
            )
            .unwrap(),
            Field::<Console>::from_str(
                "4017177598231920767921734423139954103557056461408532722673217828464276314809field",
            )
            .unwrap(),
        ]);
    }

    #[test]
    fn test_suite_hash8() {
        fn test_case_hash8(index: u16, input: Vec<Field<CurrentEnvironment>>) {
            let poseidon8 = Poseidon8::<Console>::setup("Poseidon8").unwrap();
            assert_snapshot("test_hash", format!("rate_8_test_{index}"), poseidon8.hash(&input).unwrap());
        }
        test_case_hash8(0, vec![]);
        test_case_hash8(1, vec![Field::<Console>::from_u8(0)]);
        test_case_hash8(2, vec![Field::<Console>::from_u8(1)]);
        test_case_hash8(3, vec![Field::<Console>::from_u8(0), Field::<Console>::from_u8(1)]);
        test_case_hash8(4, vec![Field::<Console>::from_u8(7), Field::<Console>::from_u8(6)]);
        test_case_hash8(5, vec![
            Field::<Console>::from_str(
                "3801852864665033841774715284518384682376829752661853198612247855579120198106field",
            )
            .unwrap(),
            Field::<Console>::from_str(
                "8354898322875240371401674517397790035008442020361740574117886421279083828480field",
            )
            .unwrap(),
            Field::<Console>::from_str(
                "4810388512520169167962815122521832339992376865086300759308552937986944510606field",
            )
            .unwrap(),
        ]);
        test_case_hash8(6, vec![
            Field::<Console>::from_str(
                "3801852864665033841774715284518384682376829752661853198612247855579120198106field",
            )
            .unwrap(),
            Field::<Console>::from_str(
                "8354898322875240371401674517397790035008442020361740574117886421279083828480field",
            )
            .unwrap(),
            Field::<Console>::from_str(
                "4810388512520169167962815122521832339992376865086300759308552937986944510606field",
            )
            .unwrap(),
            Field::<Console>::from_str(
                "1806278863067630397941269234951941896370617486625414347832536440203404317871field",
            )
            .unwrap(),
        ]);
        test_case_hash8(7, vec![
            Field::<Console>::from_str(
                "3801852864665033841774715284518384682376829752661853198612247855579120198106field",
            )
            .unwrap(),
            Field::<Console>::from_str(
                "8354898322875240371401674517397790035008442020361740574117886421279083828480field",
            )
            .unwrap(),
            Field::<Console>::from_str(
                "4810388512520169167962815122521832339992376865086300759308552937986944510606field",
            )
            .unwrap(),
            Field::<Console>::from_str(
                "1806278863067630397941269234951941896370617486625414347832536440203404317871field",
            )
            .unwrap(),
            Field::<Console>::from_str(
                "4017177598231920767921734423139954103557056461408532722673217828464276314809field",
            )
            .unwrap(),
        ]);
        test_case_hash8(8, vec![
            Field::<Console>::from_str(
                "2241061724039470158487229089505123379386376040366677537043719491567584322339field",
            )
            .unwrap(),
            Field::<Console>::from_str(
                "4450395467941419565906844040025562669400620759737863109185235386261110553073field",
            )
            .unwrap(),
            Field::<Console>::from_str(
                "3763549180544198711495347718218896634621699987767108409942867882747700142403field",
            )
            .unwrap(),
            Field::<Console>::from_str(
                "1834649076610684411560795826346579299134200286711220272747136514724202486145field",
            )
            .unwrap(),
            Field::<Console>::from_str(
                "3330794675297759513930533281299019673013197332462213086257974185952740704073field",
            )
            .unwrap(),
            Field::<Console>::from_str(
                "5929621997900969559642343088519370677943323262633114245367700983937202243619field",
            )
            .unwrap(),
            Field::<Console>::from_str(
                "8211311402459203356251863974142333868284569297703150729090604853345946857386field",
            )
            .unwrap(),
        ]);
        test_case_hash8(9, vec![
            Field::<Console>::from_str(
                "160895951580389706659907027483151875213333010019551276998320919296228647317field",
            )
            .unwrap(),
            Field::<Console>::from_str(
                "8334099740396373026754940038411748941117628023990297711605274995172393663866field",
            )
            .unwrap(),
            Field::<Console>::from_str(
                "6508516067551208838086421306235504440162527555399726948591414865066786644888field",
            )
            .unwrap(),
            Field::<Console>::from_str(
                "5260580011132523115913756761919139190330166964648541423363604516046903841683field",
            )
            .unwrap(),
            Field::<Console>::from_str(
                "1066299182733912299977577599302716102002738653010828827086884529157392046228field",
            )
            .unwrap(),
            Field::<Console>::from_str(
                "1977519953625589014039847898215240724041194773120013187722954068145627219929field",
            )
            .unwrap(),
            Field::<Console>::from_str(
                "1618348632868002512910764605250139381231860094469042556990470848701700964713field",
            )
            .unwrap(),
            Field::<Console>::from_str(
                "1157459381876765943377450451674060447297483544491073402235960067133285590974field",
            )
            .unwrap(),
        ]);
        test_case_hash8(10, vec![
            Field::<Console>::from_str(
                "3912308888616251672812272013988802988420414245857866136212784631403027079860field",
            )
            .unwrap(),
            Field::<Console>::from_str(
                "4100923705771018951561873336835055979905965765839649442185404560120892958216field",
            )
            .unwrap(),
            Field::<Console>::from_str(
                "5701101373789959818781445339314572139971317958997296225671698446757742149719field",
            )
            .unwrap(),
            Field::<Console>::from_str(
                "5785597627944719799683455467917641287692417422465938462034769734951914291948field",
            )
            .unwrap(),
            Field::<Console>::from_str(
                "214818498460401597228033958287537426429167258531438668351703993840760770582field",
            )
            .unwrap(),
            Field::<Console>::from_str(
                "4497884203527978976088488455523871581608892729212445595385399904032800522087field",
            )
            .unwrap(),
            Field::<Console>::from_str(
                "4010331535874074900042223641934450423780782982190514529696596753456937384201field",
            )
            .unwrap(),
            Field::<Console>::from_str(
                "6067637133445382691713836557146174628934072680692724940823629181144890569742field",
            )
            .unwrap(),
            Field::<Console>::from_str(
                "5966421531117752671625849775894572561179958822813329961720805067254995723444field",
            )
            .unwrap(),
        ]);
    }
}
