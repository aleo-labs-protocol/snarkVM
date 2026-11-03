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

const ITERATIONS: usize = 100;

fn test_ecdsa<H: Hash<Output = Vec<bool>, Input = bool>>(hasher: &H, rng: &mut TestRng) {
    for i in 1..ITERATIONS {
        let (signing_key, message, signature) = test_helpers::sample_ecdsa_signature(i, hasher, rng);

        // Construct the verifying key.
        let verifying_key = VerifyingKey::from(&signing_key);
        let verifying_key_bytes = verifying_key.to_sec1_point(true).as_bytes().to_vec();
        let recovered_verifying_key = ECDSASignature::verifying_key_from_bytes(&verifying_key_bytes).unwrap();
        assert_eq!(verifying_key, recovered_verifying_key);

        // Verify the signature.
        assert!(signature.verify(&verifying_key, hasher, &message.to_bits_le()).is_ok());
        assert_eq!(signature.recover_public_key(hasher, &message.to_bits_le()).unwrap(), verifying_key);

        // Verify the signature using the digest.
        let message_digest = hasher.hash(&message.to_bits_le()).unwrap();
        assert!(signature.verify_with_digest(&verifying_key, &message_digest).is_ok());
        assert_eq!(signature.recover_public_key_with_digest(&message_digest).unwrap(), verifying_key);
    }
}

#[test]
fn test_ecdsa_signature() {
    let rng = &mut TestRng::default();

    test_ecdsa(&Keccak224::default(), rng);
    test_ecdsa(&Keccak256::default(), rng);
    test_ecdsa(&Keccak384::default(), rng);
    test_ecdsa(&Keccak512::default(), rng);
    test_ecdsa(&Sha3_224::default(), rng);
    test_ecdsa(&Sha3_256::default(), rng);
    test_ecdsa(&Sha3_384::default(), rng);
    test_ecdsa(&Sha3_512::default(), rng);
}

#[test]
fn test_ecdsa_signature_vector_1() {
    let hasher = Keccak256::default();

    // Declare the test vector values.
    let data_string = "0x2bcc5ce70000000100000000000000000000000000000000000000000000000000000000000f424000002712000000000000000000000000a0b86a33e6f8ec61cc62f1b0cb2ad6dfe3c10e8b000000000000000000000000742d35cc6e4c6e42e2a6e1b6d6e19d3bb14d3d1a000000000000000000000000a0b86991c6218b36c1d19d4a2e9eb0ce3606eb480000000000000000000000002222222222222222222222222222222222222222000000000000000000000000000000000000000000000000000000000000c350bfab0940d5a2410c007e06c8b1bb24e34391ddc5298e18840df438e8e05b9ac800000000";
    let signature_string = "0xab5373ec68978e102a9084d6d07aa1e328174d12337e0a028ec3b0c63abdb89e7a906d9de841006143de25cab83b380618972c4803bf978c5b02d4e863465b8a1b";
    let expected_address = "0x1Be31A94361a391bBaFB2a4CCd704F57dc04d4bb";

    // Convert the test vector values to bytes.
    let data_bytes = hex::decode(&data_string[2..]).unwrap();
    let signature_bytes = hex::decode(&signature_string[2..]).unwrap();

    // Recover the public key from the signature.
    let signature = ECDSASignature::from_bytes_le(&signature_bytes).unwrap();
    let verifying_key = signature.recover_public_key(&hasher, &data_bytes.to_bits_le()).unwrap();

    // Check that the recovered public key matches the expected address.
    let expected_address_bytes = ECDSASignature::ethereum_address_from_public_key(&verifying_key).unwrap();
    assert_eq!(hex::decode(&expected_address[2..]).unwrap(), expected_address_bytes);

    // Check that the signature verifies against the recovered public key.
    assert!(signature.verify(&verifying_key, &hasher, &data_bytes.to_bits_le()).is_ok());
    assert!(signature.verify_ethereum(&expected_address_bytes, &hasher, &data_bytes.to_bits_le()).is_ok());

    // Check that the signature verifies using the digest.
    let message_digest = hasher.hash(&data_bytes.to_bits_le()).unwrap();
    assert!(signature.verify_with_digest(&verifying_key, &message_digest).is_ok());
    assert!(signature.verify_ethereum_with_digest(&expected_address_bytes, &message_digest).is_ok());

    // Check that the signature does not verify against modified data.
    let wrong_data = data_bytes[6..].to_vec();
    let wrong_verifying_key = signature.recover_public_key(&hasher, &wrong_data.to_bits_le()).unwrap();
    assert!(signature.verify(&wrong_verifying_key, &hasher, &data_bytes.to_bits_le()).is_err());
}
