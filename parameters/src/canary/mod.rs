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

pub mod genesis;
pub use genesis::*;

/// The restrictions list as a JSON-compatible string.
pub const RESTRICTIONS_LIST: &str = include_str!("./resources/restrictions.json");

const REMOTE_URLS: [&str; 2] = ["https://parameters.provable.com/canary", "https://s3.us-west-1.amazonaws.com/canary.parameters"];

// BondPublic
impl_remote!(BondPublicProver, REMOTE_URLS, "resources/", "bond_public", "prover", "credits");
impl_local!(BondPublicVerifier, "resources/", "bond_public", "verifier", "credits");
// BondValidator
impl_remote!(BondValidatorProver, REMOTE_URLS, "resources/", "bond_validator", "prover", "credits");
impl_local!(BondValidatorVerifier, "resources/", "bond_validator", "verifier", "credits");
// UnbondPublic
impl_remote!(UnbondPublicProver, REMOTE_URLS, "resources/", "unbond_public", "prover", "credits");
impl_local!(UnbondPublicVerifier, "resources/", "unbond_public", "verifier", "credits");
// ClaimUnbondPublic
impl_remote!(ClaimUnbondPublicProver, REMOTE_URLS, "resources/", "claim_unbond_public", "prover", "credits");
impl_local!(ClaimUnbondPublicVerifier, "resources/", "claim_unbond_public", "verifier", "credits");
// SetValidatorState
impl_remote!(SetValidatorStateProver, REMOTE_URLS, "resources/", "set_validator_state", "prover", "credits");
impl_local!(SetValidatorStateVerifier, "resources/", "set_validator_state", "verifier", "credits");
// TransferPrivate
impl_remote!(TransferPrivateProver, REMOTE_URLS, "resources/", "transfer_private", "prover", "credits");
impl_local!(TransferPrivateVerifier, "resources/", "transfer_private", "verifier", "credits");
// TransferPublic
impl_remote!(TransferPublicProver, REMOTE_URLS, "resources/", "transfer_public", "prover", "credits");
impl_local!(TransferPublicVerifier, "resources/", "transfer_public", "verifier", "credits");
// TransferPublicAsSigner
impl_remote!(TransferPublicAsSignerProver, REMOTE_URLS, "resources/", "transfer_public_as_signer", "prover", "credits");
impl_local!(TransferPublicAsSignerVerifier, "resources/", "transfer_public_as_signer", "verifier", "credits");
// TransferPrivateToPublic
impl_remote!(TransferPrivateToPublicProver, REMOTE_URLS, "resources/", "transfer_private_to_public", "prover", "credits");
impl_local!(TransferPrivateToPublicVerifier, "resources/", "transfer_private_to_public", "verifier", "credits");
// TransferPublicToPrivate
impl_remote!(TransferPublicToPrivateProver, REMOTE_URLS, "resources/", "transfer_public_to_private", "prover", "credits");
impl_local!(TransferPublicToPrivateVerifier, "resources/", "transfer_public_to_private", "verifier", "credits");
// Join
impl_remote!(JoinProver, REMOTE_URLS, "resources/", "join", "prover", "credits");
impl_local!(JoinVerifier, "resources/", "join", "verifier", "credits");
// Split
impl_remote!(SplitProver, REMOTE_URLS, "resources/", "split", "prover", "credits");
impl_local!(SplitVerifier, "resources/", "split", "verifier", "credits");
// FeePrivate
impl_remote!(FeePrivateProver, REMOTE_URLS, "resources/", "fee_private", "prover", "credits");
impl_local!(FeePrivateVerifier, "resources/", "fee_private", "verifier", "credits");
// FeePublic
impl_remote!(FeePublicProver, REMOTE_URLS, "resources/", "fee_public", "prover", "credits");
impl_local!(FeePublicVerifier, "resources/", "fee_public", "verifier", "credits");
// Upgrade
impl_remote!(UpgradeProver, REMOTE_URLS, "resources/", "upgrade", "prover", "credits");
impl_local!(UpgradeVerifier, "resources/", "upgrade", "verifier", "credits");

// V0 Credits Keys

// BondPublic
impl_remote!(BondPublicV0Prover, REMOTE_URLS, "resources/", "bond_public", "prover", "credits_v0");
impl_local!(BondPublicV0Verifier, "resources/", "bond_public", "verifier", "credits_v0");
// BondValidator
impl_remote!(BondValidatorV0Prover, REMOTE_URLS, "resources/", "bond_validator", "prover", "credits_v0");
impl_local!(BondValidatorV0Verifier, "resources/", "bond_validator", "verifier", "credits_v0");
// UnbondPublic
impl_remote!(UnbondPublicV0Prover, REMOTE_URLS, "resources/", "unbond_public", "prover", "credits_v0");
impl_local!(UnbondPublicV0Verifier, "resources/", "unbond_public", "verifier", "credits_v0");
// ClaimUnbondPublic
impl_remote!(ClaimUnbondPublicV0Prover, REMOTE_URLS, "resources/", "claim_unbond_public", "prover", "credits_v0");
impl_local!(ClaimUnbondPublicV0Verifier, "resources/", "claim_unbond_public", "verifier", "credits_v0");
// SetValidatorState
impl_remote!(SetValidatorStateV0Prover, REMOTE_URLS, "resources/", "set_validator_state", "prover", "credits_v0");
impl_local!(SetValidatorStateV0Verifier, "resources/", "set_validator_state", "verifier", "credits_v0");
// TransferPrivate
impl_remote!(TransferPrivateV0Prover, REMOTE_URLS, "resources/", "transfer_private", "prover", "credits_v0");
impl_local!(TransferPrivateV0Verifier, "resources/", "transfer_private", "verifier", "credits_v0");
// TransferPublic
impl_remote!(TransferPublicV0Prover, REMOTE_URLS, "resources/", "transfer_public", "prover", "credits_v0");
impl_local!(TransferPublicV0Verifier, "resources/", "transfer_public", "verifier", "credits_v0");
// TransferPublicAsSigner
impl_remote!(TransferPublicAsSignerV0Prover, REMOTE_URLS, "resources/", "transfer_public_as_signer", "prover", "credits_v0");
impl_local!(TransferPublicAsSignerV0Verifier, "resources/", "transfer_public_as_signer", "verifier", "credits_v0");
// TransferPrivateToPublic
impl_remote!(TransferPrivateToPublicV0Prover, REMOTE_URLS, "resources/", "transfer_private_to_public", "prover", "credits_v0");
impl_local!(TransferPrivateToPublicV0Verifier, "resources/", "transfer_private_to_public", "verifier", "credits_v0");
// TransferPublicToPrivate
impl_remote!(TransferPublicToPrivateV0Prover, REMOTE_URLS, "resources/", "transfer_public_to_private", "prover", "credits_v0");
impl_local!(TransferPublicToPrivateV0Verifier, "resources/", "transfer_public_to_private", "verifier", "credits_v0");
// Join
impl_remote!(JoinV0Prover, REMOTE_URLS, "resources/", "join", "prover", "credits_v0");
impl_local!(JoinV0Verifier, "resources/", "join", "verifier", "credits_v0");
// Split
impl_remote!(SplitV0Prover, REMOTE_URLS, "resources/", "split", "prover", "credits_v0");
impl_local!(SplitV0Verifier, "resources/", "split", "verifier", "credits_v0");
// FeePrivate
impl_remote!(FeePrivateV0Prover, REMOTE_URLS, "resources/", "fee_private", "prover", "credits_v0");
impl_local!(FeePrivateV0Verifier, "resources/", "fee_private", "verifier", "credits_v0");
// FeePublic
impl_remote!(FeePublicV0Prover, REMOTE_URLS, "resources/", "fee_public", "prover", "credits_v0");
impl_local!(FeePublicV0Verifier, "resources/", "fee_public", "verifier", "credits_v0");
// Upgrade
impl_remote!(UpgradeV0Prover, REMOTE_URLS, "resources/", "upgrade", "prover", "credits_v0");
impl_local!(UpgradeV0Verifier, "resources/", "upgrade", "verifier", "credits_v0");

#[macro_export]
macro_rules! insert_canary_credit_keys {
    ($map:ident, $type:ident<$network:ident>, $variant:ident) => {{
        paste::paste! {
            let string = stringify!([<$variant:lower>]);
            $crate::insert_canary_key!($map, string, $type<$network>, ("bond_public", $crate::canary::[<BondPublic $variant>]::load_bytes()));
            $crate::insert_canary_key!($map, string, $type<$network>, ("bond_validator", $crate::canary::[<BondValidator $variant>]::load_bytes()));
            $crate::insert_canary_key!($map, string, $type<$network>, ("unbond_public", $crate::canary::[<UnbondPublic $variant>]::load_bytes()));
            $crate::insert_canary_key!($map, string, $type<$network>, ("claim_unbond_public", $crate::canary::[<ClaimUnbondPublic $variant>]::load_bytes()));
            $crate::insert_canary_key!($map, string, $type<$network>, ("set_validator_state", $crate::canary::[<SetValidatorState $variant>]::load_bytes()));
            $crate::insert_canary_key!($map, string, $type<$network>, ("transfer_private", $crate::canary::[<TransferPrivate $variant>]::load_bytes()));
            $crate::insert_canary_key!($map, string, $type<$network>, ("transfer_public", $crate::canary::[<TransferPublic $variant>]::load_bytes()));
            $crate::insert_canary_key!($map, string, $type<$network>, ("transfer_public_as_signer", $crate::canary::[<TransferPublicAsSigner $variant>]::load_bytes()));
            $crate::insert_canary_key!($map, string, $type<$network>, ("transfer_private_to_public", $crate::canary::[<TransferPrivateToPublic $variant>]::load_bytes()));
            $crate::insert_canary_key!($map, string, $type<$network>, ("transfer_public_to_private", $crate::canary::[<TransferPublicToPrivate $variant>]::load_bytes()));
            $crate::insert_canary_key!($map, string, $type<$network>, ("join", $crate::canary::[<Join $variant>]::load_bytes()));
            $crate::insert_canary_key!($map, string, $type<$network>, ("split", $crate::canary::[<Split $variant>]::load_bytes()));
            $crate::insert_canary_key!($map, string, $type<$network>, ("fee_private", $crate::canary::[<FeePrivate $variant>]::load_bytes()));
            $crate::insert_canary_key!($map, string, $type<$network>, ("fee_public", $crate::canary::[<FeePublic $variant>]::load_bytes()));
            $crate::insert_canary_key!($map, string, $type<$network>, ("upgrade", $crate::canary::[<Upgrade $variant>]::load_bytes()));
        }
    }};
}

#[macro_export]
macro_rules! insert_canary_credit_v0_keys {
    ($map:ident, $type:ident<$network:ident>, $variant:ident) => {{
        paste::paste! {
            let string = stringify!([<$variant:lower>]);
            $crate::insert_canary_key!($map, string, $type<$network>, ("bond_public", $crate::canary::[<BondPublicV0 $variant>]::load_bytes()));
            $crate::insert_canary_key!($map, string, $type<$network>, ("bond_validator", $crate::canary::[<BondValidatorV0 $variant>]::load_bytes()));
            $crate::insert_canary_key!($map, string, $type<$network>, ("unbond_public", $crate::canary::[<UnbondPublicV0 $variant>]::load_bytes()));
            $crate::insert_canary_key!($map, string, $type<$network>, ("claim_unbond_public", $crate::canary::[<ClaimUnbondPublicV0 $variant>]::load_bytes()));
            $crate::insert_canary_key!($map, string, $type<$network>, ("set_validator_state", $crate::canary::[<SetValidatorStateV0 $variant>]::load_bytes()));
            $crate::insert_canary_key!($map, string, $type<$network>, ("transfer_private", $crate::canary::[<TransferPrivateV0 $variant>]::load_bytes()));
            $crate::insert_canary_key!($map, string, $type<$network>, ("transfer_public", $crate::canary::[<TransferPublicV0 $variant>]::load_bytes()));
            $crate::insert_canary_key!($map, string, $type<$network>, ("transfer_public_as_signer", $crate::canary::[<TransferPublicAsSignerV0 $variant>]::load_bytes()));
            $crate::insert_canary_key!($map, string, $type<$network>, ("transfer_private_to_public", $crate::canary::[<TransferPrivateToPublicV0 $variant>]::load_bytes()));
            $crate::insert_canary_key!($map, string, $type<$network>, ("transfer_public_to_private", $crate::canary::[<TransferPublicToPrivateV0 $variant>]::load_bytes()));
            $crate::insert_canary_key!($map, string, $type<$network>, ("join", $crate::canary::[<JoinV0 $variant>]::load_bytes()));
            $crate::insert_canary_key!($map, string, $type<$network>, ("split", $crate::canary::[<SplitV0 $variant>]::load_bytes()));
            $crate::insert_canary_key!($map, string, $type<$network>, ("fee_private", $crate::canary::[<FeePrivateV0 $variant>]::load_bytes()));
            $crate::insert_canary_key!($map, string, $type<$network>, ("fee_public", $crate::canary::[<FeePublicV0 $variant>]::load_bytes()));
            $crate::insert_canary_key!($map, string, $type<$network>, ("upgrade", $crate::canary::[<UpgradeV0 $variant>]::load_bytes()));
        }
    }};
}

#[macro_export]
macro_rules! insert_canary_key {
    ($map:ident, $string:tt, $type:ident<$network:ident>, ($name:tt, $circuit_key:expr)) => {{
        // Load the circuit key bytes.
        let key_bytes: Vec<u8> = $circuit_key.expect(&format!("Failed to load {} bytes", $string));
        // Recover the circuit key.
        let key = $type::<$network>::from_bytes_le(&key_bytes[1..]).expect(&format!("Failed to recover {}", $string));
        // Insert the circuit key.
        $map.insert($name.to_string(), std::sync::Arc::new(key));
    }};
}

// Inclusion
impl_remote!(InclusionV0Prover, REMOTE_URLS, "resources/", "inclusion", "prover", "credits_v0");
impl_local!(InclusionV0Verifier, "resources/", "inclusion", "verifier", "credits_v0");
impl_remote!(InclusionProver, REMOTE_URLS, "resources/", "inclusion", "prover", "credits");
impl_local!(InclusionVerifier, "resources/", "inclusion", "verifier", "credits");

/// The function name for the inclusion circuit.
pub const NETWORK_INCLUSION_FUNCTION_NAME: &str = "inclusion";

lazy_static! {
    pub static ref INCLUSION_V0_PROVING_KEY: Vec<u8> =
        InclusionV0Prover::load_bytes().expect("Failed to load inclusion_v0 proving key");
    pub static ref INCLUSION_V0_VERIFYING_KEY: Vec<u8> =
        InclusionV0Verifier::load_bytes().expect("Failed to load inclusion_v0 verifying key");
    pub static ref INCLUSION_PROVING_KEY: Vec<u8> = InclusionProver::load_bytes().expect("Failed to load inclusion proving key");
    pub static ref INCLUSION_VERIFYING_KEY: Vec<u8> =
        InclusionVerifier::load_bytes().expect("Failed to load inclusion verifying key");
}

// Translation
impl_remote!(TranslationCreditsProver, REMOTE_URLS, "resources/", "translation_credits", "prover", "credits");
impl_local!(TranslationCreditsVerifier, "resources/", "translation_credits", "verifier", "credits");

lazy_static! {
    pub static ref TRANSLATION_CREDITS_PROVING_KEY: Vec<u8> =
        TranslationCreditsProver::load_bytes().expect("Failed to load translation proving key");
    pub static ref TRANSLATION_CREDITS_VERIFYING_KEY: Vec<u8> =
        TranslationCreditsVerifier::load_bytes().expect("Failed to load translation verifying key");
}

#[cfg(test)]
mod tests {
    use super::*;
    use wasm_bindgen_test::*;
    wasm_bindgen_test_configure!(run_in_browser);

    #[allow(dead_code)]
    #[wasm_bindgen_test]
    fn test_load_bytes() {
        BondPublicVerifier::load_bytes().expect("Failed to load bond_public verifier");
        BondValidatorVerifier::load_bytes().expect("Failed to load bond_validator verifier");
        UnbondPublicVerifier::load_bytes().expect("Failed to load unbond_public verifier");
        ClaimUnbondPublicVerifier::load_bytes().expect("Failed to load claim_unbond_public verifier");
        SetValidatorStateVerifier::load_bytes().expect("Failed to load set_validator_state verifier");
        TransferPrivateVerifier::load_bytes().expect("Failed to load transfer_private verifier");
        TransferPublicVerifier::load_bytes().expect("Failed to load transfer_public verifier");
        TransferPublicAsSignerVerifier::load_bytes().expect("Failed to load transfer_public_as_signer verifier");
        TransferPrivateToPublicVerifier::load_bytes().expect("Failed to load transfer_private_to_public verifier");
        TransferPublicToPrivateVerifier::load_bytes().expect("Failed to load transfer_public_to_private verifier");
        FeePrivateProver::load_bytes().expect("Failed to load fee_private prover");
        FeePrivateVerifier::load_bytes().expect("Failed to load fee_private verifier");
        FeePublicProver::load_bytes().expect("Failed to load fee_public prover");
        FeePublicVerifier::load_bytes().expect("Failed to load fee_public verifier");
        UpgradeProver::load_bytes().expect("Failed to load upgrade prover");
        UpgradeVerifier::load_bytes().expect("Failed to load upgrade verifier");
        InclusionProver::load_bytes().expect("Failed to load inclusion prover");
        InclusionVerifier::load_bytes().expect("Failed to load inclusion verifier");
    }
}
