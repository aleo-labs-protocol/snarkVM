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

use circuit::{environment::compare_constraints, prelude::count_is};
use console::{
    program::{InputID, Plaintext, ProgramID, Record, ToFields, Value},
    types::{Address, Field, U16},
};

use crate::{
    TranslationAssignment,
    compute_console_dynamic_or_external_record_id,
    tests::test_utils::{CurrentAleo, CurrentNetwork},
};

use super::*;

use std::str::FromStr;

fn translation_assignment_from_record_str(
    record_str: &str,
    is_to_static: bool,
    is_external_record: bool,
    function_id_opt: Option<Field<CurrentNetwork>>,
    rng: &mut TestRng,
) -> (TranslationAssignment<CurrentNetwork>, u16) {
    // Independent fields.
    let record_static = Record::<CurrentNetwork, Plaintext<CurrentNetwork>>::from_str(record_str).unwrap();
    let program_id = ProgramID::<CurrentNetwork>::from_str("space_fighters.aleo").unwrap();
    let function_id = function_id_opt.unwrap_or(Field::<CurrentNetwork>::from_u64(Uniform::rand(rng)));
    let record_name = Identifier::<CurrentNetwork>::from_str("spacecraft").unwrap();
    let translation_index: u16 = Uniform::rand(rng);
    let tvk = Uniform::rand(rng);
    let record_register_index = Uniform::rand(rng);
    let record_view_key = Uniform::rand(rng);
    let gamma = Uniform::rand(rng);

    // Dependent fields.
    let record_dynamic = DynamicRecord::<CurrentNetwork>::from_record(&record_static).unwrap();

    let id_dynamic = compute_console_dynamic_or_external_record_id(
        function_id,
        record_dynamic.to_fields().unwrap(),
        tvk,
        U16::new(record_register_index),
    )
    .unwrap();

    let commitment = record_static.to_commitment(&program_id, &record_name, &record_view_key).unwrap();
    let id_static = if is_to_static {
        Record::<CurrentNetwork, Plaintext<CurrentNetwork>>::serial_number_from_gamma(&gamma, commitment).unwrap()
    } else {
        commitment
    };

    (
        TranslationAssignment::<CurrentNetwork>::new(
            record_static,
            record_dynamic,
            program_id,
            function_id,
            record_name,
            is_to_static,
            is_external_record,
            tvk,
            Some(record_view_key),
            Some(gamma),
            record_register_index,
            id_dynamic,
            id_static,
        ),
        translation_index,
    )
}

fn print_r1cs_data(name: &str) {
    println!("Translation R1CS for {name}:");
    println!("   num_public: {}", <CurrentAleo as circuit::Environment>::num_public());
    println!("   num_private: {}", <CurrentAleo as circuit::Environment>::num_private());
    println!("   num_constraints: {}", <CurrentAleo as circuit::Environment>::num_constraints());
    println!("   num_nonzeros: {:?}", <CurrentAleo as circuit::Environment>::num_nonzeros());
}

#[test]
fn test_translation_simple() {
    let mut rng = TestRng::default();

    let record_static_str = r#"{
        owner: aleo1d5hg2z3ma00382pngntdp68e74zv54jdxy249qhaujhks9c72yrs33ddah.private,
        location_x: 100field.public,
        location_y: 243field.public,
        target_coords: [
            92u8.private,
            3u8.private,
            100u8.private
        ],
        has_allies: false.public,
        codename: 1989u64.public,
        interstellar_signing_key: 2group.private,
        _nonce: 0group.public,
        _version: 1u8.public
    }"#;

    let (translation_assignment, translation_index) =
        translation_assignment_from_record_str(record_static_str, false, false, None, &mut rng);
    translation_assignment.to_circuit_assignment_internal::<CurrentAleo>(translation_index, None, None, None).unwrap();
    print_r1cs_data("simple");
    assert!(<CurrentAleo as circuit::Environment>::is_satisfied());
    let counts = count_is!(<=36085, 8, 24131, 24156);
    counts.assert_matches(
        <CurrentAleo as circuit::Environment>::num_constants(),
        <CurrentAleo as circuit::Environment>::num_public(),
        <CurrentAleo as circuit::Environment>::num_private(),
        <CurrentAleo as circuit::Environment>::num_constraints(),
    );

    // is_to_static = true
    <CurrentAleo as circuit::Environment>::reset();
    let (translation_assignment, translation_index) =
        translation_assignment_from_record_str(record_static_str, true, false, None, &mut rng);
    translation_assignment.to_circuit_assignment_internal::<CurrentAleo>(translation_index, None, None, None).unwrap();
    assert!(<CurrentAleo as circuit::Environment>::is_satisfied());
    let counts = count_is!(<=6160, 8, 24131, 24156);
    counts.assert_matches(
        <CurrentAleo as circuit::Environment>::num_constants(),
        <CurrentAleo as circuit::Environment>::num_public(),
        <CurrentAleo as circuit::Environment>::num_private(),
        <CurrentAleo as circuit::Environment>::num_constraints(),
    );
}

#[test]
fn test_varuna_v3_translation_key_reuse() -> Result<()> {
    use circuit::Environment;
    use snarkvm_algorithms::snark::varuna::VarunaVersion;
    use snarkvm_synthesizer_snark::UniversalSRS;

    let rng = &mut TestRng::fixed(3106);
    let record = r"{
        owner: aleo1d5hg2z3ma00382pngntdp68e74zv54jdxy249qhaujhks9c72yrs33ddah.private,
        _nonce: 0group.public,
        _version: 1u8.public
    }";
    let srs = UniversalSRS::<CurrentNetwork>::load()?;
    let mut expected_key = None;
    for is_to_static in [false, true] {
        for is_external in [false, true] {
            CurrentAleo::reset();
            let (mut translation, index) =
                translation_assignment_from_record_str(record, is_to_static, is_external, None, rng);
            if is_external {
                translation.id_static = compute_console_dynamic_or_external_record_id(
                    translation.function_id,
                    translation.record_static.to_fields()?,
                    translation.tvk,
                    U16::new(translation.record_register_index),
                )?;
            }
            let assignment = translation.to_circuit_assignment::<CurrentAleo>(index, None, None, None)?;
            let (pk, vk) = srs.to_circuit_key("translation", &assignment)?;
            if let Some(expected_key) = &expected_key {
                assert!(expected_key == &vk);
            } else {
                expected_key = Some(vk.clone());
            }
            let inputs = assignment.public_inputs().iter().map(|variable| variable.value()).collect::<Vec<_>>();
            for version in [VarunaVersion::V2, VarunaVersion::V3] {
                let proof = pk.prove("translation", version, &assignment, rng)?;
                assert!(vk.verify("translation", version, &inputs, &proof));
            }
        }
    }
    Ok(())
}

#[test]
fn test_translation_recursive() {
    let mut rng = TestRng::default();

    let record_static_str = r#"{
        owner: aleo1d5hg2z3ma00382pngntdp68e74zv54jdxy249qhaujhks9c72yrs33ddah.private,
        location_x: 100field.public,
        location_y: 243field.public,
        has_allies: false.public,
        codename: 1989u64.public,
        num_crew: 9u64.public,
        stealth_mode: false.private,
        resources: {
            food: 90u32.private,
            spice: 23918u32.private
        },
        targets: {
            main: {
                name: 10_992u128.private,
                star: true.private,
                interconnected: true.private,
                coords: [
                    12u8.private,
                    9u8.private,
                    72u8.private
                ]
            },
            secondary: {
                name: 33_147u128.private,
                star: false.private,
                interconnected: false.private,
                coords: [
                    85u8.private,
                    90u8.private,
                    8u8.private
                ]
            }
        },
        interstellar_signing_key: 2group.private,
        _nonce: 0group.public,
        _version: 1u8.public
    }"#;

    // is_to_static = false
    let (translation_assignment, translation_index) =
        translation_assignment_from_record_str(record_static_str, false, false, None, &mut rng);
    translation_assignment.to_circuit_assignment_internal::<CurrentAleo>(translation_index, None, None, None).unwrap();
    print_r1cs_data("recursive");
    assert!(<CurrentAleo as circuit::Environment>::is_satisfied());
    let counts = count_is!(<=38785, 8, 32721, 32750);
    counts.assert_matches(
        <CurrentAleo as circuit::Environment>::num_constants(),
        <CurrentAleo as circuit::Environment>::num_public(),
        <CurrentAleo as circuit::Environment>::num_private(),
        <CurrentAleo as circuit::Environment>::num_constraints(),
    );

    // is_to_static = true
    <CurrentAleo as circuit::Environment>::reset();
    let (translation_assignment, translation_index) =
        translation_assignment_from_record_str(record_static_str, true, false, None, &mut rng);
    translation_assignment.to_circuit_assignment_internal::<CurrentAleo>(translation_index, None, None, None).unwrap();
    assert!(<CurrentAleo as circuit::Environment>::is_satisfied());

    let counts = count_is!(<=8860, 8, 32721, 32750);
    counts.assert_matches(
        <CurrentAleo as circuit::Environment>::num_constants(),
        <CurrentAleo as circuit::Environment>::num_public(),
        <CurrentAleo as circuit::Environment>::num_private(),
        <CurrentAleo as circuit::Environment>::num_constraints(),
    );
}

#[test]
fn test_translation_complex() {
    let mut rng = TestRng::default();

    let record_static_str = r#"{
        owner: aleo1d5hg2z3ma00382pngntdp68e74zv54jdxy249qhaujhks9c72yrs33ddah.private,
        entry1: 100field.public,
        entry2: 243field.public,
        entry3: false.public,
        entry4: 1989u64.public,
        entry5: 9u64.public,
        entry6: false.private,
        entry7: {
            food: 90u32.private,
            spice: 23918u32.private
        },
        entry8: {
            main: {
                name: 10_992u128.private,
                star: true.private,
                interconnected: true.private
            },
            secondary: {
                name: 33_147u128.private,
                star: false.private,
                interconnected: false.private
            }
        },
        entry9: 2group.private,
        entry10: 99u8.public,
        entry11: [true.public, false.public, true.public, true.public, false.public],
        entry12: false.private,
        entry13: 100field.public,
        entry14: 0group.private,
        entry15: {
            maybe: true.private,
            maybe_not: false.private
        },
        entry16: 4u8.public,
        entry17: 17u8.public,
        entry18: 18u16.public,
        entry19: 19u32.public,
        entry20: 20u64.public,
        entry21: 21field.public,
        entry22: 22u128.public,
        entry23: [0group.public, 2group.public],
        entry24: 24field.public,
        entry25: 25field.public,
        entry26: 26field.public,
        entry27: 000_404u64.private,
        entry28: 28u16.public,
        entry29: 29u16.public,
        entry30: true.public,
        entry31: false.private,
        entry32: 30field.public,
        _nonce: 0group.public,
        _version: 1u8.public
    }"#;

    // is_to_static = false
    let (translation_assignment, translation_index) =
        translation_assignment_from_record_str(record_static_str, false, false, None, &mut rng);
    translation_assignment.to_circuit_assignment_internal::<CurrentAleo>(translation_index, None, None, None).unwrap();
    print_r1cs_data("complex");
    assert!(<CurrentAleo as circuit::Environment>::is_satisfied());
    let counts = count_is!(<=41330, 8, 68798, 68844);
    counts.assert_matches(
        <CurrentAleo as circuit::Environment>::num_constants(),
        <CurrentAleo as circuit::Environment>::num_public(),
        <CurrentAleo as circuit::Environment>::num_private(),
        <CurrentAleo as circuit::Environment>::num_constraints(),
    );

    // is_to_static = true
    <CurrentAleo as circuit::Environment>::reset();
    let (translation_assignment, translation_index) =
        translation_assignment_from_record_str(record_static_str, true, false, None, &mut rng);
    translation_assignment.to_circuit_assignment_internal::<CurrentAleo>(translation_index, None, None, None).unwrap();
    assert!(<CurrentAleo as circuit::Environment>::is_satisfied());
    let counts = count_is!(<=11405, 8, 68798, 68844);
    counts.assert_matches(
        <CurrentAleo as circuit::Environment>::num_constants(),
        <CurrentAleo as circuit::Environment>::num_public(),
        <CurrentAleo as circuit::Environment>::num_private(),
        <CurrentAleo as circuit::Environment>::num_constraints(),
    );
}

// Checks the translation circuit is characterised only by the structure of the
// record definition (and other auxiliary data, such as the program ID) and not
// by e.g. the data in the record's entries.
#[test]
fn test_definition_invariance() {
    let mut rng = TestRng::default();

    let record_strings = [
        // Original record
        r#"{
            owner: aleo1d5hg2z3ma00382pngntdp68e74zv54jdxy249qhaujhks9c72yrs33ddah.private,
            location_x: 100field.public,
            location_y: 243field.public,
            has_allies: false.public,
            codename: 1989u64.public,
            num_crew: 9u64.public,
            stealth_mode: false.private,
            resources: {
                food: 90u32.private,
                spice: 23918u32.private
            },
            targets: {
                main: {
                    name: 10_992u128.private,
                    star: true.private,
                    interconnected: true.private
                },
                secondary: {
                    name: 33_147u128.private,
                    star: false.private,
                    interconnected: false.private
                }
            },
            interstellar_signing_key: 2group.private,
            _nonce: 0group.public,
            _version: 1u8.public
        }"#,
        // Modifying all fields from owner up to resources
        r#"{
            owner: aleo14tlamssdmg3d0p5zmljma573jghe2q9n6wz29qf36re2glcedcpqfg4add.private,
            location_x: 7field.public,
            location_y: 23field.public,
            has_allies: true.public,
            codename: 777u64.public,
            num_crew: 2000u64.public,
            stealth_mode: true.private,
            resources: {
                food: 2000u32.private,
                spice: 233918u32.private
            },
            targets: {
                main: {
                    name: 10_992u128.private,
                    star: true.private,
                    interconnected: true.private
                },
                secondary: {
                    name: 33_147u128.private,
                    star: false.private,
                    interconnected: false.private
                }
            },
            interstellar_signing_key: 2group.private,
            _nonce: 0group.public,
            _version: 1u8.public
        }"#,
        // Modifying all fields
        r#"{
            owner: aleo14tlamssdmg3d0p5zmljma573jghe2q9n6wz29qf36re2glcedcpqfg4add.private,
            location_x: 7field.public,
            location_y: 23field.public,
            has_allies: true.public,
            codename: 777u64.public,
            num_crew: 2000u64.public,
            stealth_mode: true.private,
            resources: {
                food: 2000u32.private,
                spice: 233918u32.private
            },
            targets: {
                main: {
                    name: 9_992u128.private,
                    star: false.private,
                    interconnected: false.private
                },
                secondary: {
                    name: 6_637u128.private,
                    star: true.private,
                    interconnected: true.private
                }
            },
            interstellar_signing_key: 0group.private,
            _nonce: 2group.public,
            _version: 1u8.public
        }"#,
    ];

    // We need to ensure the function ID is the same
    let function_id = Some(Field::<CurrentNetwork>::from_u64(Uniform::rand(&mut rng)));

    // Other fields which the circuit should be independent of are generated
    // randomly inside translation_assignment_from_record_str

    // We also play around with the flag is_to_static, which should not affect the circuit
    let translation_assignments = [
        translation_assignment_from_record_str(record_strings[0], false, false, function_id, &mut rng),
        translation_assignment_from_record_str(record_strings[1], false, false, function_id, &mut rng),
        translation_assignment_from_record_str(record_strings[1], true, false, function_id, &mut rng),
        translation_assignment_from_record_str(record_strings[2], false, false, function_id, &mut rng),
        translation_assignment_from_record_str(record_strings[2], true, false, function_id, &mut rng),
    ];

    // Checking parameters of the first translation separately
    translation_assignments[0]
        .0
        .to_circuit_assignment_internal::<CurrentAleo>(translation_assignments[0].1, None, None, None)
        .unwrap();
    let counts = count_is!(<=37800, 8, 31043, 31070);
    counts.assert_matches(
        <CurrentAleo as circuit::Environment>::num_constants(),
        <CurrentAleo as circuit::Environment>::num_public(),
        <CurrentAleo as circuit::Environment>::num_private(),
        <CurrentAleo as circuit::Environment>::num_constraints(),
    );

    // Testing circuit invariance across all translations
    <CurrentAleo as circuit::Environment>::reset();
    let circuit_assignments = translation_assignments
        .iter()
        .map(|(assignment, index)| assignment.to_circuit_assignment::<CurrentAleo>(*index, None, None, None).unwrap())
        .collect_vec();

    for circuit_assignment in circuit_assignments.iter().skip(1) {
        compare_constraints(&circuit_assignments[0], circuit_assignment).unwrap();
    }
}

// Checks the translation circuit changes in various scenarios (e.g. when
// the program ID or the identifier of a record's entry change
#[test]
fn test_definition_variance() {
    let mut rng = TestRng::default();

    let record_strings = [
        // Original record
        r#"{
            owner: aleo1d5hg2z3ma00382pngntdp68e74zv54jdxy249qhaujhks9c72yrs33ddah.private,
            location_x: 100field.public,
            location_y: 243field.public,
            has_allies: false.public,
            codename: 1989u64.public,
            interstellar_signing_key: 2group.private,
            ponderings: [true.public, false.public, true.public],
            _nonce: 0group.public,
            _version: 1u8.public
        }"#,
        // Adding an entry "location_z"
        r#"{
            owner: aleo1d5hg2z3ma00382pngntdp68e74zv54jdxy249qhaujhks9c72yrs33ddah.private,
            location_x: 100field.public,
            location_y: 243field.public,
            location_z: 300field.public,
            has_allies: false.public,
            codename: 1989u64.public,
            interstellar_signing_key: 2group.private,
            ponderings: [true.public, false.public, true.public],
            _nonce: 0group.public,
            _version: 1u8.public
        }"#,
        // Changing the type of the field "location_x"
        r#"{
            owner: aleo1d5hg2z3ma00382pngntdp68e74zv54jdxy249qhaujhks9c72yrs33ddah.private,
            location_x: 100u32.public,
            location_y: 243field.public,
            has_allies: false.public,
            codename: 1989u64.public,
            interstellar_signing_key: 2group.private,
            ponderings: [true.public, false.public, true.public],
            _nonce: 0group.public,
            _version: 1u8.public
        }"#,
        // Changing the visibility of the field "interstellar_signing_key"
        r#"{
            owner: aleo1d5hg2z3ma00382pngntdp68e74zv54jdxy249qhaujhks9c72yrs33ddah.private,
            location_x: 100field.public,
            location_y: 243field.public,
            has_allies: false.public,
            codename: 1989u64.public,
            interstellar_signing_key: 2group.public,
            ponderings: [true.public, false.public, true.public],
            _nonce: 0group.public,
            _version: 1u8.public
        }"#,
        // Changing the number of elements in the array `ponderings`
        r#"{
            owner: aleo1d5hg2z3ma00382pngntdp68e74zv54jdxy249qhaujhks9c72yrs33ddah.private,
            location_x: 100field.public,
            location_y: 243field.public,
            has_allies: false.public,
            codename: 1989u64.public,
            interstellar_signing_key: 2group.private,
            ponderings: [true.public, false.public, true.public, true.public],
            _nonce: 0group.public,
            _version: 1u8.public
        }"#,
    ];

    // We need to ensure the function ID is the same in some of the test cases
    let function_id = Some(Field::<CurrentNetwork>::from_u64(Uniform::rand(&mut rng)));

    let mut translation_assignments = record_strings
        .iter()
        .map(|record_str| translation_assignment_from_record_str(record_str, false, false, function_id, &mut rng))
        .collect_vec();

    // Modifying the program ID
    let mut assignment_modified_program_id = translation_assignments[0].clone();
    assignment_modified_program_id.0.program_id = ProgramID::<CurrentNetwork>::from_str("space_invaders.aleo").unwrap();
    translation_assignments.push(assignment_modified_program_id);

    // Modifying the record name
    let mut assignment_modified_record_name = translation_assignments[0].clone();
    assignment_modified_record_name.0.record_name = Identifier::<CurrentNetwork>::from_str("spacemotorbike").unwrap();
    translation_assignments.push(assignment_modified_record_name);

    let circuit_assignments = translation_assignments
        .iter()
        .map(|(assignment, index)| assignment.to_circuit_assignment::<CurrentAleo>(*index, None, None, None).unwrap())
        .collect_vec();

    for circuit_assignment in circuit_assignments.iter().skip(1) {
        assert!(compare_constraints(&circuit_assignments[0], circuit_assignment).is_err());
    }
}

#[test]
fn test_external_translation() {
    // Tests whether the InputID and OutputID of an external record are the
    // same. If this ceases to be the case, the TranslationAssigment circuit
    // will need to be modified to account for the two scenarios.

    let mut rng = TestRng::default();

    let record_static_str = format!(
        "
        {{
            owner: {}.private,
            location_x: {}.public,
            location_y: {}.public,
            has_allies: {}.public,
            codename: {}u64.public,
            num_crew: {}u64.public,
            stealth_mode: {}.private,
            resources: {{
                food: {}u32.private,
                spice: {}u32.private
            }},
            targets: {{
                main: {{
                    name: {}u128.private,
                    star: {}.private,
                    interconnected: {}.private,
                    coords: [
                        {}u8.private,
                        {}u8.private,
                        {}u8.private
                    ]
                }},
                secondary: {{
                    name: {}u128.private,
                    star: {}.private,
                    interconnected: {}.private,
                    coords: [
                        {}u8.private,
                        {}u8.private,
                        {}u8.private
                    ]
                }}
            }},
            interstellar_signing_key: {}.private,
            _nonce: {}.public,
            _version: 1u8.public
        }}",
        Address::<CurrentNetwork>::rand(&mut rng),
        Field::<CurrentNetwork>::rand(&mut rng),
        Field::<CurrentNetwork>::rand(&mut rng),
        bool::rand(&mut rng),
        u64::rand(&mut rng),
        u64::rand(&mut rng),
        bool::rand(&mut rng),
        u32::rand(&mut rng),
        u32::rand(&mut rng),
        u128::rand(&mut rng),
        bool::rand(&mut rng),
        bool::rand(&mut rng),
        u8::rand(&mut rng),
        u8::rand(&mut rng),
        u8::rand(&mut rng),
        u128::rand(&mut rng),
        bool::rand(&mut rng),
        bool::rand(&mut rng),
        u8::rand(&mut rng),
        u8::rand(&mut rng),
        u8::rand(&mut rng),
        Group::<CurrentNetwork>::rand(&mut rng),
        Group::<CurrentNetwork>::rand(&mut rng),
    );

    let record_static = Record::<CurrentNetwork, Plaintext<CurrentNetwork>>::from_str(&record_static_str).unwrap();
    let record_static_value = Value::Record(record_static.clone());

    let function_id = Field::<CurrentNetwork>::from_u64(Uniform::rand(&mut rng));
    let tvk = Uniform::rand(&mut rng);
    let record_register_index = Uniform::rand(&mut rng);

    let external_record_input_id =
        InputID::<CurrentNetwork>::external_record(function_id, &record_static_value, tvk, record_register_index)
            .unwrap();
    let external_record_output_id = {
        let mut preimage = Vec::new();
        preimage.push(function_id);
        preimage.extend(record_static.to_fields().unwrap());
        preimage.push(tvk);
        preimage.push(Field::<CurrentNetwork>::from_u64(record_register_index as u64));
        CurrentNetwork::hash_psd8(&preimage).unwrap()
    };

    assert_eq!(*external_record_input_id.id(), external_record_output_id);

    // TranslationAssignment data
    let record_dynamic = DynamicRecord::<CurrentNetwork>::from_record(&record_static).unwrap();
    let program_id = ProgramID::<CurrentNetwork>::from_str("logistics.aleo").unwrap();
    let record_name = Identifier::<CurrentNetwork>::from_str("vehicle").unwrap();
    let is_to_static = bool::rand(&mut rng);
    // We specifically set the external-record flag to true.
    let is_external_record = true;
    let translation_index = Uniform::rand(&mut rng);
    let id_dynamic = compute_console_dynamic_or_external_record_id(
        function_id,
        record_dynamic.to_fields().unwrap(),
        tvk,
        U16::new(record_register_index),
    )
    .unwrap();
    let id_static = external_record_output_id;
    let record_view_key = UniformExt::rand_option(&mut rng);
    let gamma = UniformExt::rand_option(&mut rng);

    let translation_assignment = TranslationAssignment::<CurrentNetwork>::new(
        record_static,
        record_dynamic,
        program_id,
        function_id,
        record_name,
        is_to_static,
        is_external_record,
        tvk,
        record_view_key,
        gamma,
        record_register_index,
        id_dynamic,
        id_static,
    );

    translation_assignment.to_circuit_assignment_internal::<CurrentAleo>(translation_index, None, None, None).unwrap();
    assert!(<CurrentAleo as circuit::Environment>::is_satisfied());

    let counts = count_is!(<=38800, 8, 32562, 32591);
    counts.assert_matches(
        <CurrentAleo as circuit::Environment>::num_constants(),
        <CurrentAleo as circuit::Environment>::num_public(),
        <CurrentAleo as circuit::Environment>::num_private(),
        <CurrentAleo as circuit::Environment>::num_constraints(),
    );
}

#[test]
fn test_translation_negative_corrupt_id_dynamic() {
    let mut rng = TestRng::default();

    let record_str = r#"{
        owner: aleo1d5hg2z3ma00382pngntdp68e74zv54jdxy249qhaujhks9c72yrs33ddah.private,
        location_x: 100field.public,
        location_y: 243field.public,
        _nonce: 0group.public,
        _version: 1u8.public
    }"#;

    let (mut assignment, translation_index) =
        translation_assignment_from_record_str(record_str, false, false, None, &mut rng);

    // Corrupt the dynamic ID — any field != the correct one should fail.
    assignment.id_dynamic = Field::<CurrentNetwork>::one();

    assignment.to_circuit_assignment_internal::<CurrentAleo>(translation_index, None, None, None).unwrap();
    assert!(
        !<CurrentAleo as circuit::Environment>::is_satisfied(),
        "Circuit should be unsatisfied with a corrupted id_dynamic"
    );
}

#[test]
fn test_translation_negative_corrupt_id_static() {
    let mut rng = TestRng::default();

    let record_str = r#"{
        owner: aleo1d5hg2z3ma00382pngntdp68e74zv54jdxy249qhaujhks9c72yrs33ddah.private,
        location_x: 100field.public,
        location_y: 243field.public,
        _nonce: 0group.public,
        _version: 1u8.public
    }"#;

    <CurrentAleo as circuit::Environment>::reset();
    let (mut assignment, translation_index) =
        translation_assignment_from_record_str(record_str, false, false, None, &mut rng);

    // Corrupt the static ID — should fail because the circuit verifies the commitment.
    assignment.id_static = Field::<CurrentNetwork>::one();

    assignment.to_circuit_assignment_internal::<CurrentAleo>(translation_index, None, None, None).unwrap();
    assert!(
        !<CurrentAleo as circuit::Environment>::is_satisfied(),
        "Circuit should be unsatisfied with a corrupted id_static"
    );
}

#[test]
fn test_psd8_console_circuit_id_equivalence() {
    // This test explicitly documents and verifies that compute_console_dynamic_or_external_record_id
    // (PSD8 hash) produces the same result as the circuit's internal computation for the same inputs.
    // If the circuit and console diverge, all translation proofs would fail.
    let mut rng = TestRng::default();

    let record_str = r#"{
        owner: aleo1d5hg2z3ma00382pngntdp68e74zv54jdxy249qhaujhks9c72yrs33ddah.private,
        location_x: 100field.public,
        location_y: 243field.public,
        _nonce: 0group.public,
        _version: 1u8.public
    }"#;

    <CurrentAleo as circuit::Environment>::reset();

    // Build a valid assignment; the constructor uses compute_console_dynamic_or_external_record_id
    // to compute id_dynamic. The circuit independently recomputes the same hash.
    // If they differ, the circuit will not be satisfied.
    let (assignment, translation_index) =
        translation_assignment_from_record_str(record_str, false, false, None, &mut rng);

    // Run the circuit.
    assignment.to_circuit_assignment_internal::<CurrentAleo>(translation_index, None, None, None).unwrap();

    // If satisfied, the circuit agreed with the console computation.
    assert!(
        <CurrentAleo as circuit::Environment>::is_satisfied(),
        "Console and circuit PSD8 ID computations must agree"
    );
}
