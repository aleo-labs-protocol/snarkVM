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

#[cfg(any(test, feature = "test"))]
mod varuna {
    use crate::{
        snark::varuna::{
            AHPForR1CS,
            CircuitVerifyingKey,
            VarunaHidingMode,
            VarunaNonHidingMode,
            VarunaSNARK,
            VarunaVersion,
            mode::SNARKMode,
            proof::proof_size,
            test_circuit::TestCircuit,
        },
        traits::{AlgebraicSponge, SNARK},
    };

    use std::collections::BTreeMap;

    use snarkvm_curves::bls12_377::{Bls12_377, Fq, Fr};
    use snarkvm_utilities::{
        CanonicalSerialize,
        ToBytes,
        rand::{TestRng, Uniform},
    };

    type FS = crate::crypto_hash::PoseidonSponge<Fq, 2, 1>;

    type VarunaSonicInst = VarunaSNARK<Bls12_377, FS, VarunaHidingMode>;
    type VarunaSonicPoSWInst = VarunaSNARK<Bls12_377, FS, VarunaNonHidingMode>;

    #[test]
    fn test_varuna_v3_version_encoding() {
        use snarkvm_utilities::FromBytes;

        let version = VarunaVersion::from_bytes_le(&[3]).expect("V3 must have a stable version encoding");
        assert_eq!(version.to_bytes_le().expect("valid test fixture"), [3]);
        assert!(VarunaVersion::from_bytes_le(&[0]).is_err());
        assert!(VarunaVersion::from_bytes_le(&[4]).is_err());
    }

    #[test]
    fn test_varuna_legacy_bytes() {
        use blake2::{Blake2s256, Digest};

        fn snapshot<SM: SNARKMode>() -> String {
            type Inst<SM> = VarunaSNARK<Bls12_377, FS, SM>;
            let rng = &mut TestRng::fixed(20261002);
            let srs = Inst::<SM>::universal_setup(512).expect("valid test fixture");
            let prover = srs.to_universal_prover().expect("valid test fixture");
            let verifier = srs.to_universal_verifier().expect("valid test fixture");
            let parameters = FS::sample_parameters();
            let (circuit, inputs) = TestCircuit::gen_rand(2, 32, 25, rng);
            let (pk, vk) = Inst::<SM>::circuit_setup(&srs, &circuit).expect("valid test fixture");
            let certificate = Inst::<SM>::prove_vk(&prover, &parameters, &vk, &pk).expect("valid test fixture");
            assert!(
                Inst::<SM>::verify_vk(&verifier, &parameters, &circuit, &vk, &certificate).expect("valid test fixture")
            );
            let mut snapshot = format!(
                "hiding={}\npk={}\nvk={}\ncertificate={}\n",
                SM::ZK,
                hex::encode(Blake2s256::digest(pk.to_bytes_le().expect("valid test fixture"))),
                hex::encode(Blake2s256::digest(vk.to_bytes_le().expect("valid test fixture"))),
                hex::encode(Blake2s256::digest(certificate.to_bytes_le().expect("valid test fixture"))),
            );
            for version in [VarunaVersion::V1, VarunaVersion::V2] {
                let proof =
                    Inst::<SM>::prove(&prover, &parameters, &pk, version, &circuit, rng).expect("valid test fixture");
                assert!(
                    Inst::<SM>::verify(&verifier, &parameters, &vk, version, inputs.clone(), &proof)
                        .expect("valid test fixture")
                );
                snapshot.push_str(&format!(
                    "{version:?}={}\n",
                    hex::encode(Blake2s256::digest(proof.to_bytes_le().expect("valid test fixture")))
                ));
            }
            snapshot
        }

        let snapshot = snapshot::<VarunaHidingMode>() + &snapshot::<VarunaNonHidingMode>();
        expect_test::expect![[r#"
            hiding=true
            pk=7fcc38672b1e917dce88a89a395b7c57c38b2495e57d2663e92cbb61950432ca
            vk=9c512f09efda8fd00f12a31bffd8c2113697520b169bcb7e90c2d58bfd16b8a6
            certificate=e07d784b185e6e8f531c6aa309618c925547aa71eeabb85ff4221402fb5ccf5c
            V1=0f5a5f11c5f2b73456397aed824abac7abf1394a568f233bf2b86f2143a92373
            V2=2d54731312c5d437956cf67e4214e94d0e575288c7e71fc6a6ce9351ac32a8ea
            hiding=false
            pk=2579ba64e582504a7c0acd8295e5ac2993979a68d8557a986517ce02ec659fcf
            vk=af8c804c9facd4228705e5e16753828539bf4607391dc81a275adabddfe3e228
            certificate=482f7900b7bab21e15a4b8046a25c63e2d65b32773fa6598c7e4e84ca7eb2bb9
            V1=0774142771cd425d4a2fc9e6ded83764c9bf3c945f43b4bd8793f0febbffada4
            V2=e33baf54ecb31b243c94c4bcee0660f08de77926a5fd539d45c18d87901c7dc6
        "#]]
        .assert_eq(&snapshot);
    }

    #[test]
    fn test_varuna_v3_key_reuse_and_batch() {
        use blake2::{Blake2s256, Digest};
        use snarkvm_utilities::FromBytes;

        fn check<SM: SNARKMode>() -> String {
            type Inst<SM> = VarunaSNARK<Bls12_377, FS, SM>;
            let rng = &mut TestRng::fixed(3102);
            let srs = Inst::<SM>::universal_setup(2048).expect("valid test fixture");
            let prover = srs.to_universal_prover().expect("valid test fixture");
            let verifier = srs.to_universal_verifier().expect("valid test fixture");
            let parameters = FS::sample_parameters();
            let (circuits, inputs): (Vec<_>, Vec<_>) = [(2, 32, 25), (3, 73, 41)]
                .into_iter()
                .map(|(depth, rows, variables)| {
                    (0..2).map(|_| TestCircuit::gen_rand(depth, rows, variables, rng)).unzip::<_, _, Vec<_>, Vec<_>>()
                })
                .unzip();
            let unique = circuits.iter().map(|instances| &instances[0]).collect::<Vec<_>>();
            let keys = Inst::<SM>::batch_circuit_setup(&srs, &unique).expect("valid test fixture");
            let mut prover_inputs = BTreeMap::new();
            let mut verifier_inputs = BTreeMap::new();
            for (((pk, vk), circuits), inputs) in keys.iter().zip(&circuits).zip(&inputs) {
                let certificate = Inst::<SM>::prove_vk(&prover, &parameters, vk, pk).expect("valid test fixture");
                assert!(
                    Inst::<SM>::verify_vk(&verifier, &parameters, &circuits[0], vk, &certificate)
                        .expect("valid test fixture")
                );
                prover_inputs.insert(pk, circuits.as_slice());
                verifier_inputs.insert(vk, inputs.as_slice());
            }

            let mut proof_sizes = Vec::new();
            let mut snapshot = String::new();
            for version in [VarunaVersion::V2, VarunaVersion::V3] {
                let proof = Inst::<SM>::prove_batch(&prover, &parameters, version, &prover_inputs, rng)
                    .expect("valid test fixture");
                let bytes = proof.to_bytes_le().expect("valid test fixture");
                snapshot.push_str(&format!(
                    "hiding={} {version:?}={}\n",
                    SM::ZK,
                    hex::encode(Blake2s256::digest(&bytes))
                ));
                let proof =
                    crate::snark::varuna::Proof::<Bls12_377>::from_bytes_le(&bytes).expect("valid test fixture");
                assert!(
                    Inst::<SM>::verify_batch(&verifier, &parameters, version, &verifier_inputs, &proof)
                        .expect("valid test fixture")
                );
                let mut changed_claim = proof.clone();
                changed_claim.third_msg.sums[0][0].sum_a += Fr::from(1u64);
                assert!(
                    !Inst::<SM>::verify_batch(&verifier, &parameters, version, &verifier_inputs, &changed_claim)
                        .unwrap_or(false)
                );
                assert_eq!(
                    bytes.len(),
                    proof_size::<Bls12_377>(proof.batch_sizes(), version, SM::ZK).expect("valid test fixture")
                );
                proof_sizes.push(bytes.len());
                let other_version = if version == VarunaVersion::V2 { VarunaVersion::V3 } else { VarunaVersion::V2 };
                assert!(
                    !Inst::<SM>::verify_batch(&verifier, &parameters, other_version, &verifier_inputs, &proof)
                        .unwrap_or(false)
                );

                let mut wrong_inputs = inputs.clone();
                wrong_inputs[0][0][1] += Fr::from(1u64);
                let wrong_verifier_inputs =
                    keys.iter().zip(&wrong_inputs).map(|((_, vk), inputs)| (vk, inputs.as_slice())).collect();
                assert!(
                    !Inst::<SM>::verify_batch(&verifier, &parameters, version, &wrong_verifier_inputs, &proof)
                        .unwrap_or(false)
                );
            }
            assert_eq!(proof_sizes[0], proof_sizes[1]);
            snapshot
        }

        let snapshot = check::<VarunaHidingMode>() + &check::<VarunaNonHidingMode>();
        expect_test::expect![[r#"
            hiding=true V2=03673be9a6b1aa62629164620492ffc9f30b677c80dd0f8b05a8f8c63a6cc965
            hiding=true V3=f6a95d87ce3026bc71199b3e419d0cf93d065ffe06ad88600e08b90806fd6666
            hiding=false V2=1247d0fc9643ed261fb7633b39e06fde7d287708eab5861ead4970e3f2521a86
            hiding=false V3=514f2f98043b5945abd3115fd305056ed28162e4e5135c4818333d8113b994ca
        "#]]
        .assert_eq(&snapshot);
    }

    #[test]
    fn test_varuna_v3_lineval_identity() {
        use crate::snark::varuna::ahp::verifier::{BatchCombiners, FirstMessage, PrepareThirdMessage, SecondMessage};
        use snarkvm_fields::{One, Zero};

        let rng = &mut TestRng::fixed(3103);
        let (circuit, _) = TestCircuit::<Fr>::gen_rand(2, 32, 25, rng);
        let circuit_index = AHPForR1CS::<Fr, VarunaHidingMode>::index(&circuit).expect("valid test fixture");
        let instances = BTreeMap::from([(&circuit_index, std::slice::from_ref(&circuit))]);
        let combiners = BTreeMap::from([(circuit_index.id, BatchCombiners {
            circuit_combiner: Fr::one(),
            instance_combiners: vec![Fr::one()],
        })]);
        let first_message = FirstMessage { first_round_batch_combiners: combiners.clone() };
        let second_message = SecondMessage { alpha: Fr::from(17u64), eta_b: None, eta_c: None };

        for weights in [[0u64, 0, 0], [1, 0, 0], [2, 3, 5], [0, 3, 5]] {
            let [eta_a, eta_b, eta_c] = weights.map(Fr::from);
            let state = AHPForR1CS::<_, VarunaHidingMode>::init_prover(&instances, rng).expect("valid test fixture");
            let state = AHPForR1CS::<_, VarunaHidingMode>::prover_first_round(state, rng).expect("valid test fixture");
            let (_, state) = AHPForR1CS::<_, VarunaHidingMode>::prover_second_round(&first_message, state, rng)
                .expect("valid test fixture");
            let (claims, state) = AHPForR1CS::<_, VarunaHidingMode>::prover_prepare_third_round(
                &first_message,
                &second_message,
                state,
                rng,
            )
            .expect("valid test fixture");
            let domain = state.max_variable_domain;
            let mask = state
                .first_round_oracles
                .as_ref()
                .expect("valid test fixture")
                .mask_poly
                .as_ref()
                .expect("valid test fixture")
                .clone();
            let raw =
                state.circuit_specific_states[&circuit_index].z_m_at_alpha_polys.as_ref().expect("valid test fixture")
                    [0]
                .clone();
            let expected = |point| {
                mask.evaluate(point)
                    + eta_a * raw[0].evaluate(point)
                    + eta_b * raw[1].evaluate(point)
                    + eta_c * raw[2].evaluate(point)
            };
            let average = domain.elements().map(expected).sum::<Fr>() * domain.size_inv;
            assert_eq!(average, claims.sum(&combiners, eta_a, eta_b, eta_c) * domain.size_inv);
            let challenges =
                PrepareThirdMessage { third_round_batch_combiners: combiners.clone(), eta_a, eta_b, eta_c };
            let (_, oracles, _) = AHPForR1CS::<_, VarunaHidingMode>::prover_third_round(
                &first_message,
                &second_message,
                &Some(challenges),
                state,
                rng,
                VarunaVersion::V3,
            )
            .expect("valid test fixture");
            for beta in [Fr::zero(), Fr::one(), Fr::from(19u64), Fr::rand(rng)] {
                let actual = domain.evaluate_vanishing_polynomial(beta) * oracles.h_1.evaluate(beta)
                    + beta * oracles.g_1.evaluate(beta)
                    + average;
                assert_eq!(actual, expected(beta), "weights={weights:?}, beta={beta}");
            }
        }
    }

    macro_rules! impl_varuna_test {
        ($test_struct: ident, $snark_inst: tt, $snark_mode: tt) => {
            struct $test_struct {}
            impl $test_struct {
                pub(crate) fn test_circuit(num_constraints: usize, num_variables: usize, pk_size_expectation: usize, varuna_version: VarunaVersion, rng: &mut snarkvm_utilities::rand::TestRng) {
                    let random = Fr::rand(rng);

                    let max_degree = AHPForR1CS::<Fr, $snark_mode>::max_degree(100, 25, 300).unwrap();
                    let universal_srs = $snark_inst::universal_setup(max_degree).unwrap();
                    let universal_prover = &universal_srs.to_universal_prover().unwrap();
                    let universal_verifier = &universal_srs.to_universal_verifier().unwrap();
                    let fs_parameters = FS::sample_parameters();

                    let wrong_varuna_version = match varuna_version {
                        VarunaVersion::V1 => VarunaVersion::V2,
                        VarunaVersion::V2 => VarunaVersion::V1,
                        VarunaVersion::V3 => VarunaVersion::V2,
                    };

                    for i in 0..5 {
                        let mul_depth = 1;
                        println!("running test with SM::ZK: {}, mul_depth: {}, num_constraints: {}, num_variables: {}, varuna_version: {:?}", $snark_mode::ZK, mul_depth + i, num_constraints + i, num_variables + i, varuna_version);
                        let (circ, public_inputs) = TestCircuit::gen_rand(mul_depth + i, num_constraints + i, num_variables + i, rng);
                        let mut fake_inputs = public_inputs.clone();
                        fake_inputs[public_inputs.len() - 1] = random;

                        let (index_pk, index_vk) = $snark_inst::circuit_setup(&universal_srs, &circ).unwrap();
                        println!("Called circuit setup");

                        let certificate = $snark_inst::prove_vk(universal_prover, &fs_parameters, &index_vk, &index_pk).unwrap();
                        assert!($snark_inst::verify_vk(universal_verifier, &fs_parameters, &circ, &index_vk, &certificate).unwrap());
                        println!("verified vk");

                        if i == 0 {
                            assert_eq!(pk_size_expectation, index_pk.to_bytes_le().unwrap().len(), "Update me if serialization has changed");
                        }
                        assert_eq!(664, index_vk.to_bytes_le().unwrap().len(), "Update me if serialization has changed");

                        let proof = $snark_inst::prove(universal_prover, &fs_parameters, &index_pk, varuna_version, &circ, rng).unwrap();
                        println!("Called prover");

                        assert!($snark_inst::verify(universal_verifier, &fs_parameters, &index_vk, varuna_version, public_inputs.clone(), &proof).unwrap());
                        println!("Called verifier");
                        eprintln!("\nShould not verify with fake inputs (i.e. verifier messages should print below):");
                        assert!(!$snark_inst::verify(universal_verifier, &fs_parameters, &index_vk, varuna_version, fake_inputs, &proof).unwrap());
                        eprintln!("\nShould not verify with wrong varuna version (i.e. verifier messages should print below):");
                        assert!(!$snark_inst::verify(universal_verifier, &fs_parameters, &index_vk, wrong_varuna_version, public_inputs, &proof).unwrap());
                    }

                    for circuit_batch_size in (0..4).map(|i| 2usize.pow(i)) {
                        for instance_batch_size in (0..4).map(|i| 2usize.pow(i)) {
                            println!("running test with circuit_batch_size: {circuit_batch_size} and instance_batch_size: {instance_batch_size}");
                            let mut constraints = BTreeMap::new();
                            let mut inputs = BTreeMap::new();

                            for i in 0..circuit_batch_size {
                                let (circuit_batch, input_batch): (Vec<_>, Vec<_>) = (0..instance_batch_size)
                                .map(|_| {
                                    let mul_depth = 2 + i;
                                    let (circ, inputs) = TestCircuit::gen_rand(mul_depth, num_constraints + 100*i, num_variables, rng);
                                    (circ, inputs)
                                })
                                .unzip();
                                let circuit_id = AHPForR1CS::<Fr, $snark_mode>::index(&circuit_batch[0]).unwrap().id;
                                constraints.insert(circuit_id, circuit_batch);
                                inputs.insert(circuit_id, input_batch);
                            }
                            let unique_instances = constraints.values().map(|instances| &instances[0]).collect::<Vec<_>>();

                            let index_keys =
                                $snark_inst::batch_circuit_setup(&universal_srs, unique_instances.as_slice()).unwrap();
                            println!("Called circuit setup");

                            let mut pks_to_constraints = BTreeMap::new();
                            let mut vks_to_inputs = BTreeMap::new();

                            for (index_pk, index_vk) in index_keys.iter() {
                                let certificate = $snark_inst::prove_vk(universal_prover, &fs_parameters, &index_vk, &index_pk).unwrap();
                                let circuits = constraints[&index_pk.circuit.id].as_slice();
                                assert!($snark_inst::verify_vk(universal_verifier, &fs_parameters, &circuits[0], &index_vk, &certificate).unwrap());
                                pks_to_constraints.insert(index_pk, circuits);
                                vks_to_inputs.insert(index_vk, inputs[&index_pk.circuit.id].as_slice());
                            }
                            println!("verified vks");

                            let proof =
                                $snark_inst::prove_batch(universal_prover, &fs_parameters, varuna_version, &pks_to_constraints, rng).unwrap();
                            println!("Called prover");

                            if varuna_version == VarunaVersion::V2 {
                                let batch_sizes = proof.batch_sizes();
                                let mut proof_bytes = vec![];
                                proof.serialize_compressed(&mut proof_bytes).unwrap();
                                let actual_size = proof_size::<Bls12_377>(&batch_sizes, VarunaVersion::V2, $snark_mode::ZK).unwrap();
                                assert_eq!(proof_bytes.len(), actual_size);
                                println!("Compressed size is as expected ({actual_size} B)");
                            }

                            assert!(
                                $snark_inst::verify_batch(universal_verifier, &fs_parameters, varuna_version, &vks_to_inputs, &proof).unwrap(),
                                "Batch verification failed with {instance_batch_size} instances and {circuit_batch_size} circuits for circuits: {constraints:?}"
                            );
                            println!("Called verifier");
                            eprintln!("\nShould not verify with wrong inputs (i.e. verifier messages should print below):");
                            let mut fake_instance_inputs = Vec::with_capacity(vks_to_inputs.len());
                            for instance_input in vks_to_inputs.values() {
                                let mut fake_instance_input = Vec::with_capacity(instance_input.len());
                                for input in instance_input.iter() {
                                    let mut fake_input = input.clone();
                                    fake_input[input.len() - 1] = Fr::rand(rng);
                                    fake_instance_input.push(fake_input);
                                }
                                fake_instance_inputs.push(fake_instance_input);
                            }
                            let mut vks_to_fake_inputs = BTreeMap::new();
                            for (i, vk) in vks_to_inputs.keys().enumerate() {
                                vks_to_fake_inputs.insert(*vk, fake_instance_inputs[i].as_slice());
                            }
                            assert!(
                                !$snark_inst::verify_batch(
                                    universal_verifier,
                                    &fs_parameters,
                                    varuna_version,
                                    &vks_to_fake_inputs,
                                    &proof,
                                )
                                .unwrap()
                            );
                            eprintln!("\nShould not verify with wrong varuna version (i.e. verifier messages should print below):");
                            assert!(
                                !$snark_inst::verify_batch(
                                    universal_verifier,
                                    &fs_parameters,
                                    wrong_varuna_version,
                                    &vks_to_inputs,
                                    &proof,
                                )
                                .unwrap()
                            );
                        }
                    }
                }

                pub(crate) fn test_serde_json(num_constraints: usize, num_variables: usize, rng: &mut TestRng) {
                    use std::str::FromStr;

                    let max_degree = AHPForR1CS::<Fr, $snark_mode>::max_degree(100, 25, 300).unwrap();
                    let universal_srs = $snark_inst::universal_setup(max_degree).unwrap();

                    let mul_depth = 1;
                    let (circ, _) = TestCircuit::gen_rand(mul_depth, num_constraints, num_variables, rng);

                    let (_index_pk, index_vk) = $snark_inst::circuit_setup(&universal_srs, &circ).unwrap();
                    println!("Called circuit setup");

                    // Serialize
                    let expected_string = index_vk.to_string();
                    let candidate_string = serde_json::to_string(&index_vk).unwrap();
                    assert_eq!(
                        expected_string,
                        serde_json::Value::from_str(&candidate_string).unwrap().as_str().unwrap()
                    );

                    // Deserialize
                    assert_eq!(index_vk, CircuitVerifyingKey::from_str(&expected_string).unwrap());
                    assert_eq!(index_vk, serde_json::from_str(&candidate_string).unwrap());
                }

                pub(crate) fn test_bincode(num_constraints: usize, num_variables: usize, rng: &mut TestRng) {
                    use snarkvm_utilities::{FromBytes, ToBytes};

                    let max_degree = AHPForR1CS::<Fr, $snark_mode>::max_degree(100, 25, 300).unwrap();
                    let universal_srs = $snark_inst::universal_setup(max_degree).unwrap();

                    let mul_depth = 1;
                    let (circ, _) = TestCircuit::gen_rand(mul_depth, num_constraints, num_variables, rng);

                    let (_index_pk, index_vk) = $snark_inst::circuit_setup(&universal_srs, &circ).unwrap();
                    println!("Called circuit setup");

                    // Serialize
                    let expected_bytes = index_vk.to_bytes_le().unwrap();
                    let candidate_bytes = bincode::serialize(&index_vk).unwrap();
                    // TODO (howardwu): Serialization - Handle the inconsistency between ToBytes and Serialize (off by a length encoding).
                    assert_eq!(&expected_bytes[..], &candidate_bytes[8..]);

                    // Deserialize
                    assert_eq!(index_vk, CircuitVerifyingKey::read_le(&expected_bytes[..]).unwrap());
                    assert_eq!(index_vk, bincode::deserialize(&candidate_bytes[..]).unwrap());
                }
            }
        };
    }

    impl_varuna_test!(SonicPCTest, VarunaSonicInst, VarunaHidingMode);
    impl_varuna_test!(SonicPCPoswTest, VarunaSonicPoSWInst, VarunaNonHidingMode);

    #[test]
    fn prove_and_verify_with_tall_matrix_big() {
        let num_constraints = 100;
        let num_variables = 25;
        let pk_size_zk = 91971;
        let pk_size_posw = 91633;
        let mut rng = TestRng::default();

        SonicPCTest::test_circuit(num_constraints, num_variables, pk_size_zk, VarunaVersion::V1, &mut rng);
        SonicPCPoswTest::test_circuit(num_constraints, num_variables, pk_size_posw, VarunaVersion::V1, &mut rng);

        SonicPCTest::test_circuit(num_constraints, num_variables, pk_size_zk, VarunaVersion::V2, &mut rng);
        SonicPCPoswTest::test_circuit(num_constraints, num_variables, pk_size_posw, VarunaVersion::V2, &mut rng);

        SonicPCTest::test_serde_json(num_constraints, num_variables, &mut rng);
        SonicPCPoswTest::test_serde_json(num_constraints, num_variables, &mut rng);

        SonicPCTest::test_bincode(num_constraints, num_variables, &mut rng);
        SonicPCPoswTest::test_bincode(num_constraints, num_variables, &mut rng);
    }

    #[test]
    fn prove_and_verify_with_tall_matrix_small() {
        let num_constraints = 26;
        let num_variables = 25;
        let pk_size_zk = 25428;
        let pk_size_posw = 25090;
        let mut rng = TestRng::default();

        SonicPCTest::test_circuit(num_constraints, num_variables, pk_size_zk, VarunaVersion::V1, &mut rng);
        SonicPCPoswTest::test_circuit(num_constraints, num_variables, pk_size_posw, VarunaVersion::V1, &mut rng);

        SonicPCTest::test_circuit(num_constraints, num_variables, pk_size_zk, VarunaVersion::V2, &mut rng);
        SonicPCPoswTest::test_circuit(num_constraints, num_variables, pk_size_posw, VarunaVersion::V2, &mut rng);

        SonicPCTest::test_serde_json(num_constraints, num_variables, &mut rng);
        SonicPCPoswTest::test_serde_json(num_constraints, num_variables, &mut rng);

        SonicPCTest::test_bincode(num_constraints, num_variables, &mut rng);
        SonicPCPoswTest::test_bincode(num_constraints, num_variables, &mut rng);
    }

    #[test]
    fn prove_and_verify_with_squat_matrix_big() {
        let num_constraints = 25;
        let num_variables = 100;
        let pk_size_zk = 53523;
        let pk_size_posw = 53185;
        let mut rng = TestRng::default();

        SonicPCTest::test_circuit(num_constraints, num_variables, pk_size_zk, VarunaVersion::V1, &mut rng);
        SonicPCPoswTest::test_circuit(num_constraints, num_variables, pk_size_posw, VarunaVersion::V1, &mut rng);

        SonicPCTest::test_circuit(num_constraints, num_variables, pk_size_zk, VarunaVersion::V2, &mut rng);
        SonicPCPoswTest::test_circuit(num_constraints, num_variables, pk_size_posw, VarunaVersion::V2, &mut rng);

        SonicPCTest::test_serde_json(num_constraints, num_variables, &mut rng);
        SonicPCPoswTest::test_serde_json(num_constraints, num_variables, &mut rng);

        SonicPCTest::test_bincode(num_constraints, num_variables, &mut rng);
        SonicPCPoswTest::test_bincode(num_constraints, num_variables, &mut rng);
    }

    #[test]
    fn prove_and_verify_with_squat_matrix_small() {
        let num_constraints = 25;
        let num_variables = 26;
        let pk_size_zk = 25284;
        let pk_size_posw = 24946;
        let mut rng = TestRng::default();

        SonicPCTest::test_circuit(num_constraints, num_variables, pk_size_zk, VarunaVersion::V1, &mut rng);
        SonicPCPoswTest::test_circuit(num_constraints, num_variables, pk_size_posw, VarunaVersion::V1, &mut rng);

        SonicPCTest::test_circuit(num_constraints, num_variables, pk_size_zk, VarunaVersion::V2, &mut rng);
        SonicPCPoswTest::test_circuit(num_constraints, num_variables, pk_size_posw, VarunaVersion::V2, &mut rng);

        SonicPCTest::test_serde_json(num_constraints, num_variables, &mut rng);
        SonicPCPoswTest::test_serde_json(num_constraints, num_variables, &mut rng);

        SonicPCTest::test_bincode(num_constraints, num_variables, &mut rng);
        SonicPCPoswTest::test_bincode(num_constraints, num_variables, &mut rng);
    }

    #[test]
    fn prove_and_verify_with_square_matrix() {
        let num_constraints = 25;
        let num_variables = 25;
        let pk_size_zk = 25284;
        let pk_size_posw = 24946;
        let mut rng = TestRng::default();

        SonicPCTest::test_circuit(num_constraints, num_variables, pk_size_zk, VarunaVersion::V1, &mut rng);
        SonicPCPoswTest::test_circuit(num_constraints, num_variables, pk_size_posw, VarunaVersion::V1, &mut rng);

        SonicPCTest::test_circuit(num_constraints, num_variables, pk_size_zk, VarunaVersion::V2, &mut rng);
        SonicPCPoswTest::test_circuit(num_constraints, num_variables, pk_size_posw, VarunaVersion::V2, &mut rng);

        SonicPCTest::test_serde_json(num_constraints, num_variables, &mut rng);
        SonicPCPoswTest::test_serde_json(num_constraints, num_variables, &mut rng);

        SonicPCTest::test_bincode(num_constraints, num_variables, &mut rng);
        SonicPCPoswTest::test_bincode(num_constraints, num_variables, &mut rng);
    }
}

#[cfg(any(test, feature = "test"))]
mod varuna_hiding {
    use crate::{
        crypto_hash::PoseidonSponge,
        snark::varuna::{
            CircuitVerifyingKey,
            VarunaHidingMode,
            VarunaSNARK,
            VarunaVersion,
            ahp::AHPForR1CS,
            test_circuit::TestCircuit,
        },
        traits::{AlgebraicSponge, SNARK},
    };
    use snarkvm_curves::bls12_377::{Bls12_377, Fq, Fr};
    #[cfg(not(feature = "filesystem"))]
    use snarkvm_parameters::mainnet::MissingPowers;
    use snarkvm_utilities::{
        FromBytes,
        ToBytes,
        rand::{TestRng, Uniform},
    };

    use std::str::FromStr;

    type VarunaInst = VarunaSNARK<Bls12_377, FS, VarunaHidingMode>;
    type FS = PoseidonSponge<Fq, 2, 1>;

    fn test_circuit_n_times(
        num_constraints: usize,
        num_variables: usize,
        num_times: usize,
        varuna_version: VarunaVersion,
        rng: &mut TestRng,
    ) {
        let max_degree = AHPForR1CS::<Fr, VarunaHidingMode>::max_degree(100, 25, 300).unwrap();
        let universal_srs = VarunaInst::universal_setup(max_degree).unwrap();
        let universal_prover = &universal_srs.to_universal_prover().unwrap();
        let universal_verifier = &universal_srs.to_universal_verifier().unwrap();
        let fs_parameters = FS::sample_parameters();

        let wrong_varuna_version = match varuna_version {
            VarunaVersion::V1 => VarunaVersion::V2,
            VarunaVersion::V2 => VarunaVersion::V1,
            VarunaVersion::V3 => VarunaVersion::V2,
        };

        for _ in 0..num_times {
            let mul_depth = 2;
            let (circuit, public_inputs) = TestCircuit::gen_rand(mul_depth, num_constraints, num_variables, rng);
            let mut fake_inputs = public_inputs.clone();
            fake_inputs[public_inputs.len() - 1] = Fr::rand(rng);

            let (index_pk, index_vk) = VarunaInst::circuit_setup(&universal_srs, &circuit).unwrap();
            println!("Called circuit setup");

            let proof =
                VarunaInst::prove(universal_prover, &fs_parameters, &index_pk, varuna_version, &circuit, rng).unwrap();
            println!("Called prover");

            assert!(
                VarunaInst::verify(
                    universal_verifier,
                    &fs_parameters,
                    &index_vk,
                    varuna_version,
                    public_inputs.clone(),
                    &proof,
                )
                .unwrap()
            );
            println!("Called verifier");
            eprintln!("\nShould not verify with fake inputs (i.e. verifier messages should print below):");
            assert!(
                !VarunaInst::verify(
                    universal_verifier,
                    &fs_parameters,
                    &index_vk,
                    varuna_version,
                    fake_inputs.clone(),
                    &proof
                )
                .unwrap()
            );
            eprintln!("\nShould not verify with wrong varuna version (i.e. verifier messages should print below):");
            assert!(
                !VarunaInst::verify(
                    universal_verifier,
                    &fs_parameters,
                    &index_vk,
                    wrong_varuna_version,
                    public_inputs.clone(),
                    &proof,
                )
                .unwrap()
            );
        }
    }

    fn test_circuit(num_constraints: usize, num_variables: usize, varuna_version: VarunaVersion, rng: &mut TestRng) {
        test_circuit_n_times(num_constraints, num_variables, 100, varuna_version, rng)
    }

    fn test_serde_json(num_constraints: usize, num_variables: usize, rng: &mut TestRng) {
        let max_degree = AHPForR1CS::<Fr, VarunaHidingMode>::max_degree(100, 25, 300).unwrap();
        let universal_srs = VarunaInst::universal_setup(max_degree).unwrap();

        let mul_depth = 1;
        let (circuit, _) = TestCircuit::gen_rand(mul_depth, num_constraints, num_variables, rng);

        let (_index_pk, index_vk) = VarunaInst::circuit_setup(&universal_srs, &circuit).unwrap();
        println!("Called circuit setup");

        // Serialize
        let expected_string = index_vk.to_string();
        let candidate_string = serde_json::to_string(&index_vk).unwrap();
        assert_eq!(expected_string, serde_json::Value::from_str(&candidate_string).unwrap().as_str().unwrap());

        // Deserialize
        assert_eq!(index_vk, CircuitVerifyingKey::from_str(&expected_string).unwrap());
        assert_eq!(index_vk, serde_json::from_str(&candidate_string).unwrap());
    }

    fn test_bincode(num_constraints: usize, num_variables: usize, rng: &mut TestRng) {
        let max_degree = AHPForR1CS::<Fr, VarunaHidingMode>::max_degree(100, 25, 300).unwrap();
        let universal_srs = VarunaInst::universal_setup(max_degree).unwrap();

        let mul_depth = 1;
        let (circuit, _) = TestCircuit::gen_rand(mul_depth, num_constraints, num_variables, rng);

        let (_index_pk, index_vk) = VarunaInst::circuit_setup(&universal_srs, &circuit).unwrap();
        println!("Called circuit setup");

        // Serialize
        let expected_bytes = index_vk.to_bytes_le().unwrap();
        let candidate_bytes = bincode::serialize(&index_vk).unwrap();
        // TODO (howardwu): Serialization - Handle the inconsistency between ToBytes and
        // Serialize (off by a length encoding).
        assert_eq!(&expected_bytes[..], &candidate_bytes[8..]);

        // Deserialize
        assert_eq!(index_vk, CircuitVerifyingKey::read_le(&expected_bytes[..]).unwrap());
        assert_eq!(index_vk, bincode::deserialize(&candidate_bytes[..]).unwrap());
    }

    #[test]
    fn prove_and_verify_with_tall_matrix_big() {
        let num_constraints = 100;
        let num_variables = 25;
        let mut rng = TestRng::default();

        test_circuit(num_constraints, num_variables, VarunaVersion::V1, &mut rng);
        test_circuit(num_constraints, num_variables, VarunaVersion::V2, &mut rng);
        test_serde_json(num_constraints, num_variables, &mut rng);
        test_bincode(num_constraints, num_variables, &mut rng);
    }

    #[test]
    fn prove_and_verify_with_tall_matrix_small() {
        let num_constraints = 26;
        let num_variables = 25;
        let mut rng = TestRng::default();

        test_circuit(num_constraints, num_variables, VarunaVersion::V1, &mut rng);
        test_circuit(num_constraints, num_variables, VarunaVersion::V2, &mut rng);
        test_serde_json(num_constraints, num_variables, &mut rng);
        test_bincode(num_constraints, num_variables, &mut rng);
    }

    #[test]
    fn prove_and_verify_with_squat_matrix_big() {
        let num_constraints = 25;
        let num_variables = 100;
        let mut rng = TestRng::default();

        test_circuit(num_constraints, num_variables, VarunaVersion::V1, &mut rng);
        test_circuit(num_constraints, num_variables, VarunaVersion::V2, &mut rng);
        test_serde_json(num_constraints, num_variables, &mut rng);
        test_bincode(num_constraints, num_variables, &mut rng);
    }

    #[test]
    fn prove_and_verify_with_squat_matrix_small() {
        let num_constraints = 25;
        let num_variables = 26;
        let mut rng = TestRng::default();

        test_circuit(num_constraints, num_variables, VarunaVersion::V1, &mut rng);
        test_circuit(num_constraints, num_variables, VarunaVersion::V2, &mut rng);
        test_serde_json(num_constraints, num_variables, &mut rng);
        test_bincode(num_constraints, num_variables, &mut rng);
    }

    #[test]
    fn prove_and_verify_with_square_matrix() {
        let num_constraints = 25;
        let num_variables = 25;
        let mut rng = TestRng::default();

        test_circuit(num_constraints, num_variables, VarunaVersion::V1, &mut rng);
        test_circuit(num_constraints, num_variables, VarunaVersion::V2, &mut rng);
        test_serde_json(num_constraints, num_variables, &mut rng);
        test_bincode(num_constraints, num_variables, &mut rng);
    }

    #[cfg(feature = "filesystem")]
    #[test]
    fn prove_and_verify_with_large_matrix() {
        let num_constraints = 1 << 16;
        let num_variables = 1 << 16;
        let mut rng = TestRng::default();

        test_circuit_n_times(num_constraints, num_variables, 1, VarunaVersion::V1, &mut rng);
        test_circuit_n_times(num_constraints, num_variables, 1, VarunaVersion::V2, &mut rng);
    }

    #[cfg(feature = "filesystem")]
    #[test]
    fn check_indexing() {
        let rng = &mut TestRng::default();
        let mul_depth = 2;
        let num_constraints = 1 << 13;
        let num_variables = 1 << 13;
        let (circuit, public_inputs) = TestCircuit::gen_rand(mul_depth, num_constraints, num_variables, rng);

        let max_degree = AHPForR1CS::<Fr, VarunaHidingMode>::max_degree(100, 25, 300).unwrap();
        let universal_srs = VarunaInst::universal_setup(max_degree).unwrap();
        let universal_prover = &universal_srs.to_universal_prover().unwrap();
        let universal_verifier = &universal_srs.to_universal_verifier().unwrap();
        let fs_parameters = FS::sample_parameters();
        for varuna_version in [VarunaVersion::V1, VarunaVersion::V2] {
            let wrong_varuna_version = match varuna_version {
                VarunaVersion::V1 => VarunaVersion::V2,
                VarunaVersion::V2 => VarunaVersion::V1,
                VarunaVersion::V3 => VarunaVersion::V2,
            };
            let (index_pk, index_vk) = VarunaInst::circuit_setup(&universal_srs, &circuit).unwrap();
            println!("Called circuit setup");

            let proof =
                VarunaInst::prove(universal_prover, &fs_parameters, &index_pk, varuna_version, &circuit, rng).unwrap();
            println!("Called prover");

            universal_srs.download_powers_for(0..2usize.pow(18)).unwrap();
            let (new_pk, new_vk) = VarunaInst::circuit_setup(&universal_srs, &circuit).unwrap();
            assert_eq!(index_pk, new_pk);
            assert_eq!(index_vk, new_vk);
            assert!(
                VarunaInst::verify(
                    universal_verifier,
                    &fs_parameters,
                    &index_vk,
                    varuna_version,
                    public_inputs.clone(),
                    &proof,
                )
                .unwrap()
            );
            assert!(
                VarunaInst::verify(
                    universal_verifier,
                    &fs_parameters,
                    &new_vk,
                    varuna_version,
                    public_inputs.clone(),
                    &proof
                )
                .unwrap()
            );
            assert!(
                !VarunaInst::verify(
                    universal_verifier,
                    &fs_parameters,
                    &index_vk,
                    wrong_varuna_version,
                    public_inputs.clone(),
                    &proof,
                )
                .unwrap()
            );
        }
    }

    #[cfg(feature = "filesystem")]
    #[test]
    fn test_srs_downloads() {
        let rng = &mut TestRng::default();

        let max_degree = AHPForR1CS::<Fr, VarunaHidingMode>::max_degree(100, 25, 300).unwrap();
        let universal_srs = VarunaInst::universal_setup(max_degree).unwrap();
        let universal_prover = &universal_srs.to_universal_prover().unwrap();
        let universal_verifier = &universal_srs.to_universal_verifier().unwrap();
        let fs_parameters = FS::sample_parameters();
        let varuna_version = VarunaVersion::V2;

        // Indexing, proving, and verifying for a circuit with 1 << 15 constraints and 1
        // << 15 variables.
        let mul_depth = 2;
        let num_constraints = 2usize.pow(15) - 10;
        let num_variables = 2usize.pow(15) - 10;
        let (circuit1, public_inputs1) = TestCircuit::gen_rand(mul_depth, num_constraints, num_variables, rng);
        let (pk1, vk1) = VarunaInst::circuit_setup(&universal_srs, &circuit1).unwrap();
        println!("Called circuit setup");

        let proof1 = VarunaInst::prove(universal_prover, &fs_parameters, &pk1, varuna_version, &circuit1, rng).unwrap();
        println!("Called prover");
        assert!(
            VarunaInst::verify(
                universal_verifier,
                &fs_parameters,
                &vk1,
                varuna_version,
                public_inputs1.clone(),
                &proof1
            )
            .unwrap()
        );

        /***************************************************************************
         * * */

        // Indexing, proving, and verifying for a circuit with 1 << 19 constraints and 1
        // << 19 variables.
        let mul_depth = 2;
        let num_constraints = 2usize.pow(19) - 10;
        let num_variables = 2usize.pow(19) - 10;
        let (circuit2, public_inputs2) = TestCircuit::gen_rand(mul_depth, num_constraints, num_variables, rng);
        let (pk2, vk2) = VarunaInst::circuit_setup(&universal_srs, &circuit2).unwrap();
        println!("Called circuit setup");

        let proof2 = VarunaInst::prove(universal_prover, &fs_parameters, &pk2, varuna_version, &circuit2, rng).unwrap();
        println!("Called prover");
        assert!(
            VarunaInst::verify(universal_verifier, &fs_parameters, &vk2, varuna_version, public_inputs2, &proof2)
                .unwrap()
        );
        /***************************************************************************
         * * */
        assert!(
            VarunaInst::verify(universal_verifier, &fs_parameters, &vk1, varuna_version, public_inputs1, &proof1)
                .unwrap()
        );
    }

    /// Without `filesystem`, `circuit_setup` names every file it needs in one
    /// error, and sets the circuit up once they are added.
    #[cfg(not(feature = "filesystem"))]
    #[test]
    #[ignore = "reads the powers files that a run with `filesystem` caches"]
    fn circuit_setup_names_every_missing_file_at_once() {
        let rng = &mut TestRng::default();
        let (circuit, _) = TestCircuit::gen_rand(2, (1 << 16) - 10, (1 << 16) - 10, rng);
        let indexed = AHPForR1CS::<Fr, VarunaHidingMode>::index(&circuit).unwrap();
        let max_degree = indexed.max_degree().unwrap();
        assert!(max_degree >= 1 << 16);
        let bounds = AHPForR1CS::<Fr, VarunaHidingMode>::get_degree_bounds(&indexed.index_info).unwrap();
        // `bounds` is an array of four.
        let highest_bound = bounds.into_iter().max().unwrap();

        let universal_srs = crate::snark::varuna::UniversalSRS::<Bls12_377>::load().unwrap();
        let top = universal_srs.max_degree();
        let mut files = universal_srs.missing_files_for(0..max_degree + 1).unwrap();
        files.extend(universal_srs.missing_files_for(top - highest_bound..top + 1).unwrap());
        assert!(!files.is_empty());

        let error = VarunaInst::circuit_setup(&universal_srs, &circuit).unwrap_err();
        assert_eq!(error.downcast_ref::<MissingPowers>().map(|missing| &missing.files), Some(&files));

        for file in &files {
            universal_srs.add_powers_file(file, &*crate::polycommit::test_templates::cached_file_bytes(file)).unwrap();
        }
        VarunaInst::circuit_setup(&universal_srs, &circuit).unwrap();
    }

    #[test]
    fn test_circuit_verifying_key_bounded_deserialization() {
        use snarkvm_utilities::serialize::*;

        let mut rng = TestRng::default();

        // Create a valid circuit and verifying key
        let max_degree = AHPForR1CS::<Fr, VarunaHidingMode>::max_degree(100, 25, 300).unwrap();
        let universal_srs = VarunaInst::universal_setup(max_degree).unwrap();
        let (circ, _public_inputs) = TestCircuit::gen_rand(1, 26, 25, &mut rng);
        let (_index_pk, index_vk) = VarunaInst::circuit_setup(&universal_srs, &circ).unwrap();

        // Test 1: Valid verifying key should deserialize successfully
        let serialized = index_vk.to_bytes_le().unwrap();
        let deserialized: CircuitVerifyingKey<Bls12_377> =
            CircuitVerifyingKey::deserialize_compressed(&serialized[..]).unwrap();
        assert_eq!(index_vk, deserialized);

        // Test 2: Verify the number of circuit commitments is within bounds (should be
        // 12)
        assert!(
            index_vk.circuit_commitments.len() <= 12,
            "Circuit commitments should not exceed 12, got {}",
            index_vk.circuit_commitments.len()
        );

        // Test 3: Attempt to deserialize a verifying key with too many commitments
        // We'll manually craft a malicious serialization with 13 commitments
        let mut malicious_bytes = Vec::new();

        // Serialize circuit_info
        index_vk.circuit_info.serialize_compressed(&mut malicious_bytes).unwrap();

        // Write a length of 13 (exceeds MAX_CIRCUIT_COMMITMENTS = 12)
        let malicious_len: u64 = 13;
        malicious_len.serialize_compressed(&mut malicious_bytes).unwrap();

        // Serialize 13 commitments (repeating commitments as needed)
        for i in 0..13 {
            let commitment_idx = i % index_vk.circuit_commitments.len();
            index_vk.circuit_commitments[commitment_idx].serialize_compressed(&mut malicious_bytes).unwrap();
        }

        // Serialize id
        index_vk.id.serialize_compressed(&mut malicious_bytes).unwrap();

        // Test 4: Deserialization should fail with InvalidData error
        let result: Result<CircuitVerifyingKey<Bls12_377>, SerializationError> =
            CircuitVerifyingKey::deserialize_compressed(&malicious_bytes[..]);

        assert!(result.is_err(), "Deserialization should fail for more than 12 commitments");
        assert!(
            matches!(result.unwrap_err(), SerializationError::InvalidData),
            "Error should be SerializationError::InvalidData"
        );

        // Test 5: Test backwards compatibility - verifying keys with <= 12 commitments
        // should work
        for num_commitments in 1..=12 {
            let mut compatible_bytes = Vec::new();

            // Serialize circuit_info
            index_vk.circuit_info.serialize_compressed(&mut compatible_bytes).unwrap();

            // Write a valid length (use min to handle cases where circuit has fewer
            // commitments)
            let actual_len = num_commitments.min(index_vk.circuit_commitments.len());
            (actual_len as u64).serialize_compressed(&mut compatible_bytes).unwrap();

            // Serialize the commitments (repeat if necessary for testing)
            for i in 0..actual_len {
                let commitment_idx = i % index_vk.circuit_commitments.len();
                index_vk.circuit_commitments[commitment_idx].serialize_compressed(&mut compatible_bytes).unwrap();
            }

            // Serialize id
            index_vk.id.serialize_compressed(&mut compatible_bytes).unwrap();

            // This should succeed
            let result: Result<CircuitVerifyingKey<Bls12_377>, SerializationError> =
                CircuitVerifyingKey::deserialize_compressed(&compatible_bytes[..]);

            assert!(result.is_ok(), "Deserialization should succeed for {num_commitments} commitments",);
        }
    }

    #[test]
    fn a_proving_key_reads_back_with_exact_rows() {
        use crate::snark::varuna::{CircuitProvingKey, ahp::indexer::Circuit};

        fn exact_rows(c: &Circuit<Fr, VarunaHidingMode>) -> bool {
            [&c.a, &c.b, &c.c].into_iter().flatten().all(|r| r.capacity() == r.len())
        }

        let rng = &mut TestRng::default();
        let max_degree = AHPForR1CS::<Fr, VarunaHidingMode>::max_degree(100, 25, 300).expect("a degree");
        let universal_srs = VarunaInst::universal_setup(max_degree).expect("an SRS");
        // Every row has one entry.
        let (circuit, _) = TestCircuit::gen_rand(2, 100, 25, rng);
        let (pk, _) = VarunaInst::circuit_setup(&universal_srs, &circuit).expect("a key");
        let bytes = pk.to_bytes_le().expect("the key writes");
        let read = CircuitProvingKey::<Bls12_377, VarunaHidingMode>::read_le(&bytes[..]).expect("the key reads");

        assert!(exact_rows(&pk.circuit), "synthesis no longer builds exact rows");
        assert!(exact_rows(&read.circuit), "the key read back holds spare row capacity");
        assert!(read.to_bytes_le().expect("the key writes") == bytes, "the key read back writes other bytes");
    }
}

mod varuna_test_vectors {
    use crate::{
        fft::EvaluationDomain,
        snark::varuna::{AHPForR1CS, TestCircuit, VarunaNonHidingMode, VarunaSNARK, VarunaVersion, ahp::verifier},
        traits::snark::SNARK,
    };
    use snarkvm_curves::bls12_377::{Bls12_377, Fq, Fr};
    use snarkvm_fields::One;
    use std::{collections::BTreeMap, fs, ops::Deref, path::PathBuf, str::FromStr, sync::Arc};

    type FS = crate::crypto_hash::PoseidonSponge<Fq, 2, 1>;
    type MM = VarunaNonHidingMode;
    type VarunaSonicInst = VarunaSNARK<Bls12_377, FS, MM>;

    // Create the path for the `resources` folder.
    fn resources_path(create_dir: bool) -> PathBuf {
        let mut path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        path.push("src");
        path.push("snark");
        path.push("varuna");
        path.push("resources");

        // Create the `resources` folder, if it does not exist.
        if !path.exists() {
            if create_dir {
                fs::create_dir(&path).unwrap_or_else(|_| panic!("Failed to create resources folder: {path:?}"));
            } else {
                panic!("Resources folder does not exist: {path:?}");
            }
        }

        path
    }

    // Create the file path.
    fn test_vector_path(folder: &str, file: &str, circuit: &str, create_dir: bool) -> PathBuf {
        let mut path = resources_path(create_dir);

        // Construct the path where the test data lives.
        path.push(circuit);
        path.push(folder);

        // Create the test folder if it does not exist if specified, otherwise panic.
        if !path.exists() {
            if create_dir {
                fs::create_dir(&path).unwrap_or_else(|_| panic!("Failed to create resources folder: {path:?}"));
            } else {
                panic!("Resources folder does not exist: {path:?}");
            }
        }

        // Construct the path for the test file.
        path.push(file);
        path.set_extension("txt");

        path
    }

    // Loads the given `test_folder/test_file` and asserts the given `candidate`
    // matches the expected values.
    #[track_caller]
    fn assert_test_vector_equality(test_folder: &str, test_file: &str, candidate: &str, circuit: &str) {
        // Get the path to the test file.
        let path = test_vector_path(test_folder, test_file, circuit, false);

        // Assert the test file is equal to the expected value.
        expect_test::expect_file![path].assert_eq(candidate);
    }

    // Create a test vector from a trusted revision of Varuna.
    fn create_test_vector(folder: &str, file: &str, data: &str, circuit: &str) {
        // Get the path to the test file.
        let path = test_vector_path(folder, file, circuit, true);

        // Write the test vector to file.
        fs::write(&path, data).unwrap_or_else(|_| panic!("Failed to write to file: {path:?}"));
    }

    // Tests varuna against the test vectors in all circuits in the resources
    // folder.
    fn test_varuna_with_all_circuits(create_test_vectors: bool) {
        let entries = fs::read_dir(resources_path(create_test_vectors)).expect("Failed to read resources folder");
        entries.into_iter().for_each(|entry| {
            let path = entry.unwrap().path();
            if path.is_dir() {
                let circuit = path.file_name().unwrap().to_str().unwrap();
                test_circuit_with_test_vectors(create_test_vectors, circuit);
            }
        });
    }

    // Test Varuna against test vectors for a specific circuit.
    fn test_circuit_with_test_vectors(create_test_vectors: bool, circuit: &str) {
        // Initialize the parts of the witness used in the multiplicative constraints.
        let witness_path = resources_path(false).join(circuit).join("witness.input");
        let instance_file = fs::read_to_string(witness_path).expect("Could not read the file");
        let witness: Vec<u128> = serde_json::from_str(instance_file.lines().next().unwrap()).unwrap();
        let (a, b) = (witness[0], witness[1]);

        // Initialize challenges from file.
        let challenges_path = resources_path(false).join(circuit).join("challenges.input");
        let challenges_file = fs::read_to_string(challenges_path).expect("Could not read the file");
        let mut challenges = Vec::new();
        for line in challenges_file.lines() {
            challenges.push(line)
        }
        let (alpha, _eta_a, eta_b, eta_c, beta, delta_a, delta_b, delta_c, _gamma) = (
            Fr::from_str(challenges[0]).unwrap(),
            Fr::from_str(challenges[1]).unwrap(),
            Fr::from_str(challenges[2]).unwrap(),
            Fr::from_str(challenges[3]).unwrap(),
            Fr::from_str(challenges[4]).unwrap(),
            vec![Fr::from_str(challenges[5]).unwrap()],
            vec![Fr::from_str(challenges[6]).unwrap()],
            vec![Fr::from_str(challenges[7]).unwrap()],
            Fr::from_str(challenges[8]).unwrap(),
        );

        let circuit_combiner = Fr::one();
        let instance_combiners = vec![Fr::one()];

        // Create sample circuit which corresponds to instance.input file.
        let mul_depth = 3;
        let num_constraints = 7;
        let num_variables = 7;

        // Create a fixed seed rng that matches those the test vectors were generated
        // with.
        let rng = &mut snarkvm_utilities::rand::TestRng::fixed(4730);
        let max_degree =
            AHPForR1CS::<Fr, MM>::max_degree(num_constraints, num_variables, num_variables * num_constraints).unwrap();
        let universal_srs = VarunaSonicInst::universal_setup(max_degree).unwrap();
        let (circ, _) =
            TestCircuit::generate_circuit_with_fixed_witness(a, b, mul_depth, num_constraints, num_variables);
        println!("Circuit: {circ:?}");
        let (index_pk, _index_vk) = VarunaSonicInst::circuit_setup(&universal_srs, &circ).unwrap();
        let mut keys_to_constraints = BTreeMap::new();
        keys_to_constraints.insert(index_pk.circuit.deref(), std::slice::from_ref(&circ));

        // Begin the Varuna protocol execution.
        let prover_state = AHPForR1CS::<_, MM>::init_prover(&keys_to_constraints, rng).unwrap();
        let mut prover_state = AHPForR1CS::<_, MM>::prover_first_round(prover_state, rng).unwrap();
        let first_round_oracles = Arc::new(prover_state.first_round_oracles.as_ref().unwrap());

        // Get private witness polynomial coefficients.
        let (_, w_poly) = first_round_oracles.batches.iter().next().unwrap();
        let w_lde = format!("{:?}", w_poly[0].0.coeffs().map(|(_, coeff)| coeff).collect::<Vec<_>>());
        if create_test_vectors {
            create_test_vector("polynomials", "w_lde", &w_lde, circuit);
        }

        // Generate test vectors from assignments.
        let assignments = AHPForR1CS::<_, MM>::calculate_assignments(&mut prover_state).unwrap();

        // Get full witness polynomial coefficients.
        let (_, z_poly) = assignments.iter().next().unwrap();
        let z_lde = format!("{:?}", z_poly[0].coeffs().iter().collect::<Vec<_>>());
        if create_test_vectors {
            create_test_vector("polynomials", "z_lde", &z_lde, circuit);
        }

        let combiners = verifier::BatchCombiners::<Fr> { circuit_combiner, instance_combiners };
        let first_round_batch_combiners = BTreeMap::from_iter([(index_pk.circuit.id, combiners)]);
        let verifier_first_msg = verifier::FirstMessage::<Fr> { first_round_batch_combiners };

        let (second_oracles, prover_state) =
            AHPForR1CS::<_, MM>::prover_second_round::<_>(&verifier_first_msg, prover_state, rng).unwrap();

        // Get round 2 rowcheck polynomial oracle coefficients.
        let h_0 = format!("{:?}", second_oracles.h_0.coeffs().map(|(_, coeff)| coeff).collect::<Vec<_>>());
        if create_test_vectors {
            create_test_vector("polynomials", "h_0", &h_0, circuit);
        }

        let verifier_second_msg = verifier::SecondMessage::<Fr> { alpha, eta_b: Some(eta_b), eta_c: Some(eta_c) };
        let (_prover_third_message, third_oracles, prover_state) = AHPForR1CS::<_, MM>::prover_third_round(
            &verifier_first_msg,
            &verifier_second_msg,
            &None,
            prover_state,
            rng,
            VarunaVersion::V1,
        )
        .unwrap();

        // Get coefficients round 3 univariate rowcheck polynomial oracles.
        let g_1 = format!("{:?}", third_oracles.g_1.coeffs().map(|(_, coeff)| coeff).collect::<Vec<_>>());
        if create_test_vectors {
            create_test_vector("polynomials", "g_1", &g_1, circuit);
        }
        let h_1 = format!("{:?}", third_oracles.h_1.coeffs().map(|(_, coeff)| coeff).collect::<Vec<_>>());
        if create_test_vectors {
            create_test_vector("polynomials", "h_1", &h_1, circuit);
        }

        let verifier_third_msg = verifier::ThirdMessage::<Fr> { beta };
        let (_prover_fourth_message, fourth_oracles, prover_state) =
            AHPForR1CS::<_, MM>::prover_fourth_round(&verifier_second_msg, &verifier_third_msg, prover_state, rng)
                .unwrap();

        // Create round 4 rational sumcheck oracle polynomials.
        let (_, gm_polys) = fourth_oracles.gs.iter().next().unwrap();
        let g_a = format!("{:?}", gm_polys.g_a.coeffs().map(|(_, coeff)| coeff).collect::<Vec<_>>());
        let g_b = format!("{:?}", gm_polys.g_b.coeffs().map(|(_, coeff)| coeff).collect::<Vec<_>>());
        let g_c = format!("{:?}", gm_polys.g_b.coeffs().map(|(_, coeff)| coeff).collect::<Vec<_>>());
        if create_test_vectors {
            create_test_vector("polynomials", "g_a", &g_a, circuit);
            create_test_vector("polynomials", "g_b", &g_b, circuit);
            create_test_vector("polynomials", "g_c", &g_c, circuit);
        }

        // Create the verifier's fourth message.
        let verifier_fourth_msg = verifier::FourthMessage::<Fr> { delta_a, delta_b, delta_c };

        let mut public_inputs = BTreeMap::new();
        let public_input = prover_state.public_inputs(&index_pk.circuit).unwrap();
        public_inputs.insert(index_pk.circuit.id, public_input);
        let non_zero_a_domain = EvaluationDomain::<Fr>::new(index_pk.circuit.index_info.num_non_zero_a).unwrap();
        let non_zero_b_domain = EvaluationDomain::<Fr>::new(index_pk.circuit.index_info.num_non_zero_b).unwrap();
        let non_zero_c_domain = EvaluationDomain::<Fr>::new(index_pk.circuit.index_info.num_non_zero_c).unwrap();
        let variable_domain =
            EvaluationDomain::<Fr>::new(index_pk.circuit.index_info.num_public_and_private_variables).unwrap();
        let constraint_domain = EvaluationDomain::<Fr>::new(index_pk.circuit.index_info.num_constraints).unwrap();
        let input_domain = EvaluationDomain::<Fr>::new(index_pk.circuit.index_info.num_public_inputs).unwrap();

        // Get constraint domain elements.
        let mut constraint_domain_elements = Vec::with_capacity(constraint_domain.size());
        for el in constraint_domain.elements() {
            constraint_domain_elements.push(el);
        }
        if create_test_vectors {
            create_test_vector("domain", "R", &format!("{constraint_domain_elements:?}"), circuit);
        }

        // Get non_zero_domain elements.
        let non_zero_domain = *[&non_zero_a_domain, &non_zero_b_domain, &non_zero_c_domain]
            .iter()
            .max_by_key(|domain| domain.size)
            .unwrap();
        let mut non_zero_domain_elements = Vec::with_capacity(non_zero_domain.size());
        for el in non_zero_domain.elements() {
            non_zero_domain_elements.push(el);
        }
        if create_test_vectors {
            create_test_vector("domain", "K", &format!("{non_zero_domain_elements:?}"), circuit);
        }

        // Get variable domain elements.
        let mut variable_domain_elements = Vec::with_capacity(input_domain.size());
        for el in variable_domain.elements() {
            variable_domain_elements.push(el);
        }
        if create_test_vectors {
            create_test_vector("domain", "C", &format!("{variable_domain_elements:?}"), circuit);
        }

        let fifth_oracles = AHPForR1CS::<_, MM>::prover_fifth_round(verifier_fourth_msg, prover_state, rng).unwrap();

        // Get coefficients of final oracle polynomial from round 5.
        let h_2 = format!("{:?}", fifth_oracles.h_2.coeffs().map(|(_, coeff)| coeff).collect::<Vec<_>>());
        if create_test_vectors {
            create_test_vector("polynomials", "h_2", &h_2, circuit);
        }

        // Check the intermediate oracle polynomials against the test vectors.
        assert_test_vector_equality("polynomials", "w_lde", &w_lde, circuit);
        assert_test_vector_equality("polynomials", "z_lde", &z_lde, circuit);
        assert_test_vector_equality("polynomials", "h_0", &h_0, circuit);
        assert_test_vector_equality("polynomials", "h_1", &h_1, circuit);
        assert_test_vector_equality("polynomials", "g_1", &g_1, circuit);
        assert_test_vector_equality("polynomials", "h_2", &h_2, circuit);
        assert_test_vector_equality("polynomials", "g_a", &g_a, circuit);
        assert_test_vector_equality("polynomials", "g_b", &g_b, circuit);
        assert_test_vector_equality("polynomials", "g_c", &g_c, circuit);

        // Check that the domains match the test vectors.
        assert_test_vector_equality("domain", "R", &format!("{constraint_domain_elements:?}"), circuit);
        assert_test_vector_equality("domain", "K", &format!("{non_zero_domain_elements:?}"), circuit);
        assert_test_vector_equality("domain", "C", &format!("{variable_domain_elements:?}"), circuit);
    }

    #[test]
    fn test_varuna_with_prover_test_vectors() {
        test_varuna_with_all_circuits(false);
    }
}

/// A proof, pinned by its hash, so the device and the host must agree on it.
///
/// This checks the whole pipeline's output rather than one kernel. The circuit
/// is sized so that every device entry point runs: `msm`, `ntt`, `polymul`,
/// `lineval_interpolate_mul`, the fourth-round chain and `accumulate_open`.
/// The prover's randomness comes from the `rng` argument alone, so a fixed
/// seed fixes the proof.
mod proof_vector {
    use crate::{
        crypto_hash::PoseidonSponge,
        snark::varuna::{AHPForR1CS, VarunaHidingMode, VarunaSNARK, VarunaVersion, test_circuit::TestCircuit},
        traits::{AlgebraicSponge, SNARK},
    };
    use blake2::Digest;
    use snarkvm_curves::bls12_377::{Bls12_377, Fq, Fr};
    use snarkvm_utilities::{ToBytes, rand::TestRng};

    type FS = PoseidonSponge<Fq, 2, 1>;
    type Inst = VarunaSNARK<Bls12_377, FS, VarunaHidingMode>;

    // The circuit's shape and both seeds. Changing any of them changes the
    // proof.
    const SETUP_SEED: u64 = 20260911;
    const PROVE_SEED: u64 = 777;
    const MUL_DEPTH: usize = 1;
    /// Large enough that the commitment MSMs cross `VariableBase::msm`'s
    /// `> 1024` threshold and run on the device. Below it, a wrong MSM kernel
    /// would still produce the pinned hash.
    const NUM_CONSTRAINTS: usize = 2000;
    const NUM_VARIABLES: usize = 2000;
    /// Per matrix: `max_degree` builds one non-zero domain from this, and
    /// `TestCircuit` writes one entry per matrix per constraint.
    const NUM_NON_ZERO: usize = NUM_CONSTRAINTS;

    /// Blake2s over `proof.to_bytes_le()`, per Varuna version.
    ///
    /// Any change to the proof for a fixed input moves this: intended if the
    /// prover was meant to change, a regression otherwise. Both feature sets
    /// are checked against these values, so a device that disagrees with the
    /// host fails in one of them. The `rand` generators and the SRS bytes
    /// `universal_setup` produces also move it, so a dependency bump can land
    /// here without a prover change.
    const EXPECTED: [(VarunaVersion, &str); 2] = [
        (VarunaVersion::V2, "620d8f2272d8496df5832bddeffa3cf70ed48c192ce6caffb624c27f73db34b3"),
        (VarunaVersion::V3, "8e2b36c08794204430f20e5e1c26e52b7d8e4588acc8d7799669d9365bd8ef70"),
    ];

    #[test]
    fn a_fixed_input_proves_to_a_fixed_proof() {
        let max_degree = AHPForR1CS::<Fr, VarunaHidingMode>::max_degree(NUM_CONSTRAINTS, NUM_VARIABLES, NUM_NON_ZERO)
            .expect("the test circuit has a max degree");
        prove_and_check(Inst::universal_setup(max_degree).expect("the SRS for the test circuit"));
    }

    fn prove_and_check(srs: crate::snark::varuna::UniversalSRS<Bls12_377>) {
        let setup = &mut TestRng::fixed(SETUP_SEED);
        let prover = &srs.to_universal_prover().expect("a prover from the SRS");
        let verifier = &srs.to_universal_verifier().expect("a verifier from the SRS");
        let fs = FS::sample_parameters();
        let (circuit, inputs) = TestCircuit::gen_rand(MUL_DEPTH, NUM_CONSTRAINTS, NUM_VARIABLES, setup);
        let (pk, vk) = Inst::circuit_setup(&srs, &circuit).expect("the keys for the test circuit");
        for (version, expected) in EXPECTED {
            let rng = &mut TestRng::fixed(PROVE_SEED);
            let proof = Inst::prove(prover, &fs, &pk, version, &circuit, rng).expect("the test circuit proves");

            // Verified before the hash is compared, so a wrong proof fails as
            // wrong rather than as merely different.
            let verified = Inst::verify(verifier, &fs, &vk, version, inputs.as_slice(), &proof)
                .unwrap_or_else(|e| panic!("the pinned {version:?} proof must verify, and verification errored: {e}"));
            assert!(verified, "the pinned {version:?} proof must verify");

            let digest = hex::encode(blake2::Blake2s256::digest(proof.to_bytes_le().expect("a proof serializes")));
            assert_eq!(
                digest, expected,
                "the {version:?} proof for a fixed input changed; see this constant's documentation"
            );
        }
    }
}
