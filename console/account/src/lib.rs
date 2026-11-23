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

#![forbid(unsafe_code)]
#![allow(clippy::too_many_arguments)]
#![warn(clippy::cast_possible_truncation)]
#![cfg_attr(test, allow(clippy::assertions_on_result_states))]

#[doc(no_inline)]
pub use snarkvm_console_types::environment::prelude::*;
pub use snarkvm_console_types::{Address, Field, Group, Scalar};

mod address;

pub mod compute_key;
pub use compute_key::*;

pub mod graph_key;
pub use graph_key::*;

pub mod private_key;
pub use private_key::*;

pub mod signature;
pub use signature::*;

pub mod view_key;
pub use view_key::*;

#[cfg(test)]
mod tests {
    use crate::{Address, ComputeKey, PrivateKey, Signature, ViewKey};
    use snarkvm_console_network::{MainnetV0, prelude::*};

    type CurrentNetwork = MainnetV0;

    const ALEO_PRIVATE_KEY: &str = "APrivateKey1zkp8cC4jgHEBnbtu3xxs1Ndja2EMizcvTRDq5Nikdkukg1p";
    const ALEO_VIEW_KEY: &str = "AViewKey1n1n3ZbnVEtXVe3La2xWkUvY3EY7XaCG6RZJJ3tbvrrrD";
    const ALEO_ADDRESS: &str = "aleo1wvgwnqvy46qq0zemj0k6sfp3zv0mp77rw97khvwuhac05yuwscxqmfyhwf";

    const ITERATIONS: usize = 1_000;

    #[test]
    fn test_account_derivation() {
        let private_key = PrivateKey::<CurrentNetwork>::from_str(ALEO_PRIVATE_KEY).unwrap();
        let view_key = ViewKey::<CurrentNetwork>::try_from(&private_key).unwrap();
        let address = Address::<CurrentNetwork>::try_from(&private_key).unwrap();

        assert_eq!(ALEO_PRIVATE_KEY, private_key.to_string());
        assert_eq!(ALEO_VIEW_KEY, view_key.to_string());
        assert_eq!(ALEO_ADDRESS, address.to_string());
    }

    #[test]
    fn test_private_key_from_str() {
        let private_key = PrivateKey::<CurrentNetwork>::from_str(ALEO_PRIVATE_KEY).unwrap();
        assert_eq!(ALEO_PRIVATE_KEY, private_key.to_string());
    }

    #[test]
    fn test_private_key_from_invalid_str() {
        assert!(PrivateKey::<CurrentNetwork>::from_str(ALEO_VIEW_KEY).is_err());
        assert!(PrivateKey::<CurrentNetwork>::from_str(ALEO_ADDRESS).is_err());
        assert!(PrivateKey::<CurrentNetwork>::from_str("APrivateKey1abcdefghijklmnopqrstuvwxyz").is_err());
        assert!(PrivateKey::<CurrentNetwork>::from_str("APrivateKey1").is_err());
        assert!(PrivateKey::<CurrentNetwork>::from_str("").is_err());
    }

    #[test]
    fn test_private_key_try_into_view_key() {
        let private_key = PrivateKey::<CurrentNetwork>::from_str(ALEO_PRIVATE_KEY).unwrap();
        let view_key: ViewKey<_> = private_key.try_into().unwrap();
        assert_eq!(ALEO_VIEW_KEY, view_key.to_string());
    }

    #[test]
    fn test_view_key_from_str() {
        let view_key = ViewKey::<CurrentNetwork>::from_str(ALEO_VIEW_KEY).unwrap();
        assert_eq!(ALEO_VIEW_KEY, view_key.to_string());
    }

    #[test]
    fn test_view_key_from_invalid_str() {
        assert!(ViewKey::<CurrentNetwork>::from_str(ALEO_PRIVATE_KEY).is_err());
        assert!(ViewKey::<CurrentNetwork>::from_str(ALEO_ADDRESS).is_err());
        assert!(ViewKey::<CurrentNetwork>::from_str("AViewKey1abcdefghijklmnopqrstuvwxyz").is_err());
        assert!(ViewKey::<CurrentNetwork>::from_str("AViewKey1").is_err());
        assert!(ViewKey::<CurrentNetwork>::from_str("").is_err());
    }

    #[test]
    fn test_private_key_try_into_address() {
        let private_key = PrivateKey::<CurrentNetwork>::from_str(ALEO_PRIVATE_KEY).unwrap();
        let address: Address<_> = private_key.try_into().unwrap();
        assert_eq!(ALEO_ADDRESS, address.to_string());
    }

    #[test]
    fn test_compute_key_try_into_address() {
        let private_key = PrivateKey::<CurrentNetwork>::from_str(ALEO_PRIVATE_KEY).unwrap();
        let compute_key: ComputeKey<_> = private_key.try_into().unwrap();
        let address: Address<_> = compute_key.try_into().unwrap();
        assert_eq!(ALEO_ADDRESS, address.to_string());
    }

    #[test]
    fn test_view_key_try_into_address() {
        let view_key = ViewKey::<CurrentNetwork>::from_str(ALEO_VIEW_KEY).unwrap();
        let address: Address<_> = view_key.try_into().unwrap();
        assert_eq!(ALEO_ADDRESS, address.to_string());
    }

    #[test]
    fn test_address_from_str() {
        let address = Address::<CurrentNetwork>::from_str(ALEO_ADDRESS).unwrap();
        assert_eq!(ALEO_ADDRESS, address.to_string());
    }

    #[test]
    fn test_address_from_invalid_str() {
        assert!(Address::<CurrentNetwork>::from_str(ALEO_PRIVATE_KEY).is_err());
        assert!(Address::<CurrentNetwork>::from_str(ALEO_VIEW_KEY).is_err());
        assert!(Address::<CurrentNetwork>::from_str("aleo1abcdefghijklmnopqrstuvwxyz").is_err());
        assert!(Address::<CurrentNetwork>::from_str("aleo1").is_err());
        assert!(Address::<CurrentNetwork>::from_str("").is_err());
    }

    #[test]
    fn test_sign_bits() {
        let private_key = PrivateKey::<CurrentNetwork>::from_str(ALEO_PRIVATE_KEY).unwrap();
        let address = Address::<CurrentNetwork>::try_from(&private_key).unwrap();

        let mut rng = TestRng::default();

        for i in 0..ITERATIONS {
            let message: Vec<bool> = (0..(32 * i)).map(|_| bool::rand(&mut rng)).collect();
            let signature = private_key.sign_bits(&message, &mut rng).unwrap();
            let verification = signature.verify_bits(&address, &message);
            assert!(verification);
        }
    }

    #[test]
    fn test_invalid_sign_bits() {
        let private_key = PrivateKey::<CurrentNetwork>::from_str(ALEO_PRIVATE_KEY).unwrap();
        let address = Address::<CurrentNetwork>::try_from(&private_key).unwrap();

        let mut rng = TestRng::default();

        for i in 0..ITERATIONS {
            let message = "Hi, I'm an Aleo account signature!".as_bytes().to_bits_le();
            let incorrect_message: Vec<bool> = (0..(32 * i)).map(|_| bool::rand(&mut rng)).collect();

            let signature = private_key.sign_bits(&message, &mut rng).unwrap();
            let verification = signature.verify_bits(&address, &incorrect_message);
            assert!(!verification);
        }
    }

    #[test]
    fn test_aleo_signature_bech32() {
        let mut rng = TestRng::default();

        for i in 0..25 {
            // Sample an Aleo account.
            let private_key = PrivateKey::<CurrentNetwork>::new(&mut rng).unwrap();

            // Craft the Aleo signature.
            let message: Vec<bool> = (0..(32 * i)).map(|_| bool::rand(&mut rng)).collect();
            let expected_signature = private_key.sign_bits(&message, &mut rng).unwrap();

            let candidate_string = &expected_signature.to_string();
            assert_eq!(216, candidate_string.len(), "Update me if serialization has changed");
            assert_eq!("sign1", &candidate_string[0..5], "Update me if the prefix has changed");
        }
    }

    #[test]
    fn test_aleo_signature_serde_json() {
        let mut rng = TestRng::default();

        for i in 0..25 {
            // Sample an Aleo account.
            let private_key = PrivateKey::<CurrentNetwork>::new(&mut rng).unwrap();

            // Craft the Aleo signature.
            let message: Vec<bool> = (0..(32 * i)).map(|_| bool::rand(&mut rng)).collect();
            let expected_signature = private_key.sign_bits(&message, &mut rng).unwrap();

            // Serialize
            let expected_string = &expected_signature.to_string();
            let candidate_string = serde_json::to_string(&expected_signature).unwrap();
            assert_eq!(expected_string, serde_json::Value::from_str(&candidate_string).unwrap().as_str().unwrap());

            // Deserialize
            assert_eq!(expected_signature, serde_json::from_str(&candidate_string).unwrap());
            assert_eq!(expected_signature, Signature::<CurrentNetwork>::from_str(expected_string).unwrap());
        }
    }

    #[test]
    fn test_aleo_signature_bincode() {
        let mut rng = TestRng::default();

        for i in 0..25 {
            // Sample an Aleo account.
            let private_key = PrivateKey::<CurrentNetwork>::new(&mut rng).unwrap();

            // Craft the Aleo signature.
            let message: Vec<bool> = (0..(32 * i)).map(|_| bool::rand(&mut rng)).collect();
            let expected_signature = private_key.sign_bits(&message, &mut rng).unwrap();

            // Serialize
            let expected_bytes = expected_signature.to_bytes_le().unwrap();
            let candidate_bytes = bincode::serialize(&expected_signature).unwrap();
            assert_eq!(128, expected_bytes.len(), "Update me if serialization has changed");
            assert_eq!(&expected_bytes[..], &candidate_bytes[8..]);

            // Deserialize
            assert_eq!(expected_signature, bincode::deserialize(&candidate_bytes[..]).unwrap());
            assert_eq!(expected_signature, Signature::<CurrentNetwork>::read_le(&expected_bytes[..]).unwrap());
        }
    }
}
