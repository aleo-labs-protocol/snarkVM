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

mod bytes;
mod serialize;
mod string;

use console::{
    account::{Address, ViewKey},
    network::prelude::*,
    program::{Ciphertext, Future, Plaintext, Record, TransitionLeaf, ValueType},
    types::{Field, Group},
};

type Variant = u8;

/// The transition output.
#[derive(Clone, PartialEq, Eq)]
pub enum Output<N: Network> {
    /// The plaintext hash and (optional) plaintext.
    Constant(Field<N>, Option<Plaintext<N>>),
    /// The plaintext hash and (optional) plaintext.
    Public(Field<N>, Option<Plaintext<N>>),
    /// The ciphertext hash and (optional) ciphertext.
    Private(Field<N>, Option<Ciphertext<N>>),
    /// The commitment, checksum, (optional) record ciphertext, and (optional) sender ciphertext.
    Record(Field<N>, Field<N>, Option<Record<N, Ciphertext<N>>>, Option<Field<N>>),
    /// The hash of the external record's (function_id, record, tvk, output index).
    ExternalRecord(Field<N>),
    /// The future hash and (optional) future.
    Future(Field<N>, Option<Future<N>>),
    /// The hash of the dynamic record's (function_id, record, tvk, output index).
    DynamicRecord(Field<N>),
    /// The commitment, checksum, (optional) record ciphertext, (optional) sender ciphertext, and dynamic ID.
    RecordWithDynamicID(Field<N>, Field<N>, Option<Record<N, Ciphertext<N>>>, Option<Field<N>>, Field<N>),
    /// The external record hash and dynamic ID.
    ExternalRecordWithDynamicID(Field<N>, Field<N>),
}

impl<N: Network> Output<N> {
    /// Returns the variant of the output.
    pub const fn variant(&self) -> Variant {
        match self {
            Output::Constant(_, _) => 0,
            Output::Public(_, _) => 1,
            Output::Private(_, _) => 2,
            Output::Record(_, _, _, _) => 3,
            Output::ExternalRecord(_) => 4,
            Output::Future(_, _) => 5,
            Output::DynamicRecord(_) => 6,
            Output::RecordWithDynamicID(..) => 7,
            Output::ExternalRecordWithDynamicID(..) => 8,
        }
    }

    /// Returns the ID of the output.
    pub const fn id(&self) -> &Field<N> {
        match self {
            Output::Constant(id, ..) => id,
            Output::Public(id, ..) => id,
            Output::Private(id, ..) => id,
            Output::Record(commitment, ..) => commitment,
            Output::ExternalRecord(id) => id,
            Output::Future(id, ..) => id,
            Output::DynamicRecord(id) => id,
            Output::RecordWithDynamicID(commitment, ..) => commitment,
            Output::ExternalRecordWithDynamicID(id, ..) => id,
        }
    }

    /// Returns the output as a transition leaf.
    /// Note: RecordWithDynamicID uses leaf variant 3 (same as Record) with version 2.
    /// Note: ExternalRecordWithDynamicID uses leaf variant 4 (same as ExternalRecord) with version 2.
    pub fn to_transition_leaf(&self, index: u8) -> TransitionLeaf<N> {
        match self {
            // RecordWithDynamicID produces leaf with version 2, variant 3.
            Output::RecordWithDynamicID(..) => TransitionLeaf::new_record_with_dynamic_id(index, *self.id()),
            // ExternalRecordWithDynamicID produces leaf with version 2, variant 4.
            Output::ExternalRecordWithDynamicID(..) => {
                TransitionLeaf::new_external_record_with_dynamic_id(index, *self.id())
            }
            // All other variants use their serialization variant byte.
            _ => TransitionLeaf::new(index, self.variant(), *self.id()),
        }
    }

    /// Returns the commitment and record, if the output is a record.
    #[allow(clippy::type_complexity)]
    pub const fn record(&self) -> Option<(&Field<N>, &Record<N, Ciphertext<N>>)> {
        match self {
            Output::Record(commitment, _, Some(record), _)
            | Output::RecordWithDynamicID(commitment, _, Some(record), _, _) => Some((commitment, record)),
            _ => None,
        }
    }

    /// Consumes `self` and returns the commitment and record, if the output is a record.
    #[allow(clippy::type_complexity)]
    pub fn into_record(self) -> Option<(Field<N>, Record<N, Ciphertext<N>>)> {
        match self {
            Output::Record(commitment, _, Some(record), _)
            | Output::RecordWithDynamicID(commitment, _, Some(record), _, _) => Some((commitment, record)),
            _ => None,
        }
    }

    /// Returns the commitment, if the output is a record.
    pub const fn commitment(&self) -> Option<&Field<N>> {
        match self {
            Output::Record(commitment, ..) | Output::RecordWithDynamicID(commitment, ..) => Some(commitment),
            _ => None,
        }
    }

    /// Returns the commitment, if the output is a record, and consumes `self`.
    pub fn into_commitment(self) -> Option<Field<N>> {
        match self {
            Output::Record(commitment, ..) | Output::RecordWithDynamicID(commitment, ..) => Some(commitment),
            _ => None,
        }
    }

    /// Returns the nonce, if the output is a record.
    pub const fn nonce(&self) -> Option<&Group<N>> {
        match self {
            Output::Record(_, _, Some(record), _) | Output::RecordWithDynamicID(_, _, Some(record), _, _) => {
                Some(record.nonce())
            }
            _ => None,
        }
    }

    /// Returns the nonce, if the output is a record, and consumes `self`.
    pub fn into_nonce(self) -> Option<Group<N>> {
        match self {
            Output::Record(_, _, Some(record), _) | Output::RecordWithDynamicID(_, _, Some(record), _, _) => {
                Some(record.into_nonce())
            }
            _ => None,
        }
    }

    /// Returns the checksum, if the output is a record.
    pub const fn checksum(&self) -> Option<&Field<N>> {
        match self {
            Output::Record(_, checksum, ..) | Output::RecordWithDynamicID(_, checksum, ..) => Some(checksum),
            _ => None,
        }
    }

    /// Returns the checksum, if the output is a record, and consumes `self`.
    pub fn into_checksum(self) -> Option<Field<N>> {
        match self {
            Output::Record(_, checksum, ..) | Output::RecordWithDynamicID(_, checksum, ..) => Some(checksum),
            _ => None,
        }
    }

    /// Returns the sender ciphertext, if the output is a record.
    pub const fn sender_ciphertext(&self) -> Option<&Field<N>> {
        match self {
            Output::Record(_, _, _, Some(sender_ciphertext))
            | Output::RecordWithDynamicID(_, _, _, Some(sender_ciphertext), _) => Some(sender_ciphertext),
            _ => None,
        }
    }

    /// Returns the sender ciphertext, if the output is a record, and consumes `self`.
    pub fn into_sender_ciphertext(self) -> Option<Field<N>> {
        match self {
            Output::Record(_, _, _, Some(sender_ciphertext))
            | Output::RecordWithDynamicID(_, _, _, Some(sender_ciphertext), _) => Some(sender_ciphertext),
            _ => None,
        }
    }

    /// Returns the future, if the output is a future.
    pub const fn future(&self) -> Option<&Future<N>> {
        match self {
            Output::Future(_, Some(future)) => Some(future),
            _ => None,
        }
    }
}

impl<N: Network> Output<N> {
    /// Returns the sender address, given the account view key of the record owner.
    ///
    /// If the output is not a record or does not contain a sender ciphertext, it returns `Ok(None)`.
    /// If the record does not belong to the given account view key, it returns `Err`.
    /// If the sender ciphertext is malformed or cannot be decrypted, it returns `Err`.
    pub fn decrypt_sender_ciphertext(&self, account_view_key: &ViewKey<N>) -> Result<Option<Address<N>>> {
        // Retrieve the record ciphertext and sender ciphertext, if they exist.
        let (record_ciphertext, sender_ciphertext) = match self {
            Output::Record(_, _, Some(record_ciphertext), Some(sender_ciphertext))
            | Output::RecordWithDynamicID(_, _, Some(record_ciphertext), Some(sender_ciphertext), _) => {
                (record_ciphertext, sender_ciphertext)
            }
            // If the output is not a record or does not contain a sender ciphertext, return `None`.
            _ => return Ok(None),
        };

        // Compute the record view key.
        let record_view_key = (*record_ciphertext.nonce() * **account_view_key).to_x_coordinate();
        // Retrieve the record owner.
        let expected_owner = match record_ciphertext.owner().is_public() {
            true => record_ciphertext.owner().decrypt_with_randomizer(&[])?,
            false => {
                // Prepare the randomizer for the record owner.
                let randomizers = N::hash_many_psd8(&[N::encryption_domain(), record_view_key], 1);
                ensure!(randomizers.len() == 1, "Expected exactly one randomizer for the record owner");
                // Decrypt the record owner using the randomizer.
                record_ciphertext.owner().decrypt_with_randomizer(&[randomizers[0]])?
            }
        };
        // Ensure this record belongs to the given account view key.
        ensure!(
            *expected_owner == account_view_key.to_address(),
            "The record does not belong to the given account view key"
        );

        // Compute the encryption randomizer for the sender ciphertext.
        let Ok(randomizer) = N::hash_psd4(&[N::encryption_domain(), record_view_key, Field::one()]) else {
            bail!("Failed to compute the encryption randomizer for the sender ciphertext");
        };
        // Decrypt the sender ciphertext using the record view key.
        let sender_x_coordinate = *sender_ciphertext - randomizer;
        // Recover the sender address.
        match Address::from_field(&sender_x_coordinate) {
            Ok(sender_address) => Ok(Some(sender_address)),
            Err(error) => bail!("Failed to recover the sender address - {error}"),
        }
    }
}

impl<N: Network> Output<N> {
    /// Returns the public verifier inputs for the proof.
    pub fn verifier_inputs(&self) -> impl '_ + Iterator<Item = N::Field> {
        // Append the output ID.
        [**self.id()].into_iter()
            // Append the checksum and sender ciphertext, if they exist.
            .chain([self.checksum().map(|sum| **sum), self.sender_ciphertext().map(|sender| **sender)].into_iter().flatten())
    }

    /// Returns the dynamic ID, if the output carries one.
    pub const fn dynamic_id(&self) -> Option<&Field<N>> {
        match self {
            Output::RecordWithDynamicID(_, _, _, _, dynamic_id)
            | Output::ExternalRecordWithDynamicID(_, dynamic_id) => Some(dynamic_id),
            _ => None,
        }
    }

    /// Returns the output from the caller's perspective.
    pub fn to_caller_output(&self) -> Self {
        match self {
            // `RecordWithDynamicID` becomes `DynamicRecord` from caller's view.
            Self::RecordWithDynamicID(_, _, _, _, dynamic_id) => Self::DynamicRecord(*dynamic_id),
            // `ExternalRecordWithDynamicID` becomes `DynamicRecord` from caller's view.
            Self::ExternalRecordWithDynamicID(_, dynamic_id) => Self::DynamicRecord(*dynamic_id),
            // All other variants are unchanged.
            other => other.clone(),
        }
    }

    /// Returns `true` if the output is well-formed.
    /// If the optional value exists, this method checks that it hashes to the output ID.
    pub fn verify(&self, function_id: Field<N>, tcm: &Field<N>, index: usize) -> bool {
        // Ensure the hash of the value (if the value exists) is correct.
        let result = || match self {
            Output::Constant(hash, Some(output)) => {
                match output.to_fields() {
                    Ok(fields) => {
                        // Construct the (console) output index as a field element.
                        let index = Field::from_u16(index as u16);
                        // Construct the preimage as `(function ID || output || tcm || index)`.
                        let mut preimage = Vec::new();
                        preimage.push(function_id);
                        preimage.extend(fields);
                        preimage.push(*tcm);
                        preimage.push(index);
                        // Ensure the hash matches.
                        match N::hash_psd8(&preimage) {
                            Ok(candidate_hash) => Ok(hash == &candidate_hash),
                            Err(error) => Err(error),
                        }
                    }
                    Err(error) => Err(error),
                }
            }
            Output::Public(hash, Some(output)) => {
                match output.to_fields() {
                    Ok(fields) => {
                        // Construct the (console) output index as a field element.
                        let index = Field::from_u16(index as u16);
                        // Construct the preimage as `(function ID || output || tcm || index)`.
                        let mut preimage = Vec::new();
                        preimage.push(function_id);
                        preimage.extend(fields);
                        preimage.push(*tcm);
                        preimage.push(index);
                        // Ensure the hash matches.
                        match N::hash_psd8(&preimage) {
                            Ok(candidate_hash) => Ok(hash == &candidate_hash),
                            Err(error) => Err(error),
                        }
                    }
                    Err(error) => Err(error),
                }
            }
            Output::Private(hash, Some(value)) => {
                match value.to_fields() {
                    // Ensure the hash matches.
                    Ok(fields) => match N::hash_psd8(&fields) {
                        Ok(candidate_hash) => Ok(hash == &candidate_hash),
                        Err(error) => Err(error),
                    },
                    Err(error) => Err(error),
                }
            }
            Output::Record(_, checksum, Some(record_ciphertext), sender_ciphertext)
            | Output::RecordWithDynamicID(_, checksum, Some(record_ciphertext), sender_ciphertext, _) => {
                // Construct the checksum preimage.
                let mut preimage = record_ciphertext.to_bits_le();
                // If the record version is set to Version 0, ensure the sender ciphertext is `None`.
                // If the record version is set to Version 1 or higher, ensure the sender ciphertext is `Some` and non-zero.
                if **record_ciphertext.version() == 0 {
                    ensure!(sender_ciphertext.is_none(), "The sender ciphertext must be None for Version 0 records");
                    // Truncate the last 8 bits of the preimage, as Version 0 records do not include the version in serialization.
                    preimage.truncate(preimage.len().saturating_sub(8));
                } else if **record_ciphertext.version() == 1 {
                    ensure!(sender_ciphertext.is_some(), "The sender ciphertext must be non-empty");
                    // Note: The sender ciphertext feature can become optional or deactivated by removing this check.
                    // Safe: sender_ciphertext.is_some() was verified on the line above.
                    ensure!(sender_ciphertext.unwrap() != Field::zero(), "The sender ciphertext must be non-zero");
                } else {
                    bail!(
                        "The record version must be set to Version 0 or 1, but found Version {}",
                        **record_ciphertext.version()
                    );
                }

                // Ensure the record ciphertext hash matches the checksum.
                match N::hash_bhp1024(&preimage) {
                    Ok(candidate_hash) => Ok(checksum == &candidate_hash),
                    Err(error) => Err(error),
                }
            }
            Output::Future(hash, Some(output)) => {
                match output.to_fields() {
                    Ok(fields) => {
                        // Construct the (future) output index as a field element.
                        let index = Field::from_u16(index as u16);
                        // Construct the preimage as `(function ID || output || tcm || index)`.
                        let mut preimage = Vec::new();
                        preimage.push(function_id);
                        preimage.extend(fields);
                        preimage.push(*tcm);
                        preimage.push(index);
                        // Ensure the hash matches.
                        match N::hash_psd8(&preimage) {
                            Ok(candidate_hash) => Ok(hash == &candidate_hash),
                            Err(error) => Err(error),
                        }
                    }
                    Err(error) => Err(error),
                }
            }
            Output::Constant(_, None)
            | Output::Public(_, None)
            | Output::Private(_, None)
            | Output::Record(_, _, None, _)
            | Output::RecordWithDynamicID(_, _, None, _, _)
            | Output::Future(_, None) => {
                // This enforces that the transition *must* contain the value for this transition output.
                // A similar rule is enforced for the transition input.
                bail!("A transition output value is missing")
            }
            Output::ExternalRecord(_) => Ok(true),
            Output::DynamicRecord(_) => Ok(true),
            Output::ExternalRecordWithDynamicID(_, _) => Ok(true),
        };

        match result() {
            Ok(is_hash_valid) => is_hash_valid,
            Err(error) => {
                eprintln!("{error}");
                false
            }
        }
    }

    /// Returns `true` if the output matches the expected value type.
    pub fn is_type(&self, expected_value_type: &ValueType<N>) -> bool {
        matches!(
            (self, expected_value_type),
            (Self::Constant(..), ValueType::Constant(..))
                | (Self::Public(..), ValueType::Public(..))
                | (Self::Private(..), ValueType::Private(..))
                | (Self::Record(..), ValueType::Record(..))
                | (Self::RecordWithDynamicID(..), ValueType::Record(..))
                | (Self::ExternalRecord(..), ValueType::ExternalRecord(..))
                | (Self::ExternalRecordWithDynamicID(..), ValueType::ExternalRecord(..))
                | (Self::Future(..), ValueType::Future(..))
                | (Self::DynamicRecord(..), ValueType::DynamicRecord)
        )
    }

    /// Returns `true` if the output matches the given value type as produced by the callee.
    /// `Record`, `ExternalRecord`, `DynamicRecord`, `RecordWithDynamicID` and
    /// `ExternalRecordWithDynamicID` outputs are handled according to the value of `is_dynamic`:
    ///  - `Some(true)` enforces type correspondence assuming the outputs refer to a dynamic call.
    ///  - `Some(false)` enforces it assuming a static call.
    ///  - `None` is flexible and makes no assumption about the type of call: both dynamic-call and
    ///    static-call matching patterns return `true`.
    ///
    /// For outputs of an invalid type according to `is_dynamic`, this function returns false
    /// regardless of the value type.
    pub fn valid_as_output(&self, callee_value_type: &ValueType<N>, is_dynamic: Option<bool>) -> bool {
        // These variants are call-type independent, so they always match their value type.
        if matches!(
            (self, callee_value_type),
            (Self::Constant(..), ValueType::Constant(..))
                | (Self::Public(..), ValueType::Public(..))
                | (Self::Private(..), ValueType::Private(..))
                | (Self::Future(..), ValueType::Future(..))
        ) {
            return true;
        }

        if is_dynamic == Some(true) {
            // Unmatched variants:
            //  - Self::Record: cannot be the callee's view of a dynamic-call output, so we return
            //    false regardless of the ValueType
            //  - Self::ExternalRecord: same as above
            matches!(
                (self, callee_value_type),
                // Callee produces a static Record, caller sees DynamicRecord, translation occurs
                (Self::RecordWithDynamicID(..), ValueType::Record(..))
                // Callee produces an ExternalRecord, caller sees DynamicRecord, translation occurs
                | (Self::ExternalRecordWithDynamicID(..), ValueType::ExternalRecord(..))
                // Caller and callee see DynamicRecord, no translation occurs
                | (Self::DynamicRecord(..), ValueType::DynamicRecord)
            )
        } else if is_dynamic == Some(false) {
            // Unmatched variants:
            //  - Self::RecordWithDynamicID: no translation can occur in static calls
            //  - Self::ExternalRecordWithDynamicID: same as above
            matches!(
                (self, callee_value_type),
                // Callee produces a static Record (e.g. the root transition or the fee)
                (Self::Record(..), ValueType::Record(..))
                // Pass-through of External records (no translation)
                | (Self::ExternalRecord(..), ValueType::ExternalRecord(..))
                // Since this is a static call, dynamic records are only passed through
                | (Self::DynamicRecord(..), ValueType::DynamicRecord)
            )
        } else {
            // is_dynamic = None: flexible matching
            self.is_type(callee_value_type)
        }
    }
}

#[cfg(test)]
pub(crate) mod test_helpers {
    use super::*;
    use console::{network::MainnetV0, program::Literal};

    type CurrentNetwork = MainnetV0;

    /// Sample the transition outputs.
    pub(crate) fn sample_outputs() -> Vec<(<CurrentNetwork as Network>::TransitionID, Output<CurrentNetwork>)> {
        let rng = &mut TestRng::default();

        // Sample a transition.
        let transaction = crate::transaction::test_helpers::sample_execution_transaction_with_fee(true, rng, 0);
        let transition = transaction.transitions().next().unwrap();

        // Retrieve the transition ID and output.
        let transition_id = *transition.id();
        let input = transition.outputs().iter().next().unwrap().clone();

        // Sample a random plaintext.
        let plaintext = Plaintext::Literal(Literal::Field(Uniform::rand(rng)), Default::default());
        let plaintext_hash = CurrentNetwork::hash_bhp1024(&plaintext.to_bits_le()).unwrap();
        // Sample a random ciphertext.
        let fields: Vec<_> = (0..10).map(|_| Uniform::rand(rng)).collect();
        let ciphertext = Ciphertext::from_fields(&fields).unwrap();
        let ciphertext_hash = CurrentNetwork::hash_bhp1024(&ciphertext.to_bits_le()).unwrap();
        // Sample a random record.
        let randomizer = Uniform::rand(rng);
        let nonce = CurrentNetwork::g_scalar_multiply(&randomizer);
        let record = Record::<CurrentNetwork, Plaintext<CurrentNetwork>>::from_str(
            &format!("{{ owner: aleo1d5hg2z3ma00382pngntdp68e74zv54jdxy249qhaujhks9c72yrs33ddah.private, token_amount: 100u64.private, _nonce: {nonce}.public }}"),
        ).unwrap();
        let record_ciphertext = record.encrypt(randomizer).unwrap();
        let record_checksum = CurrentNetwork::hash_bhp1024(&record_ciphertext.to_bits_le()).unwrap();
        // Sample a sender ciphertext.
        let sender_ciphertext = match record_ciphertext.version().is_zero() {
            true => None,
            false => Some(Uniform::rand(rng)),
        };

        vec![
            (transition_id, input),
            (Uniform::rand(rng), Output::Constant(Uniform::rand(rng), None)),
            (Uniform::rand(rng), Output::Constant(plaintext_hash, Some(plaintext.clone()))),
            (Uniform::rand(rng), Output::Public(Uniform::rand(rng), None)),
            (Uniform::rand(rng), Output::Public(plaintext_hash, Some(plaintext))),
            (Uniform::rand(rng), Output::Private(Uniform::rand(rng), None)),
            (Uniform::rand(rng), Output::Private(ciphertext_hash, Some(ciphertext))),
            (Uniform::rand(rng), Output::Record(Uniform::rand(rng), Uniform::rand(rng), None, sender_ciphertext)),
            (
                Uniform::rand(rng),
                Output::Record(Uniform::rand(rng), record_checksum, Some(record_ciphertext.clone()), sender_ciphertext),
            ),
            (Uniform::rand(rng), Output::ExternalRecord(Uniform::rand(rng))),
            (
                Uniform::rand(rng),
                Output::RecordWithDynamicID(
                    Uniform::rand(rng),
                    record_checksum,
                    Some(record_ciphertext),
                    sender_ciphertext,
                    Uniform::rand(rng),
                ),
            ),
            (
                Uniform::rand(rng),
                Output::RecordWithDynamicID(
                    Uniform::rand(rng),
                    Uniform::rand(rng),
                    None,
                    sender_ciphertext,
                    Uniform::rand(rng),
                ),
            ),
            (Uniform::rand(rng), Output::ExternalRecordWithDynamicID(Uniform::rand(rng), Uniform::rand(rng))),
            (Uniform::rand(rng), Output::DynamicRecord(Uniform::rand(rng))),
        ]
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use console::network::MainnetV0;

    type CurrentNetwork = MainnetV0;

    #[test]
    fn test_to_caller_output_record_with_dynamic_id() {
        // RecordWithDynamicID should become DynamicRecord(dynamic_id) from caller's view.
        let commitment = Field::<CurrentNetwork>::from_u64(1);
        let checksum = Field::<CurrentNetwork>::from_u64(2);
        let dynamic_id = Field::<CurrentNetwork>::from_u64(3);

        let output = Output::<CurrentNetwork>::RecordWithDynamicID(commitment, checksum, None, None, dynamic_id);
        let caller_output = output.to_caller_output();

        assert_eq!(caller_output, Output::<CurrentNetwork>::DynamicRecord(dynamic_id));
    }

    #[test]
    fn test_to_caller_output_external_record_with_dynamic_id() {
        // ExternalRecordWithDynamicID should become DynamicRecord(dynamic_id) from caller's view.
        let ext_id = Field::<CurrentNetwork>::from_u64(10);
        let dynamic_id = Field::<CurrentNetwork>::from_u64(20);

        let output = Output::<CurrentNetwork>::ExternalRecordWithDynamicID(ext_id, dynamic_id);
        let caller_output = output.to_caller_output();

        assert_eq!(caller_output, Output::<CurrentNetwork>::DynamicRecord(dynamic_id));
    }

    #[test]
    fn test_to_caller_output_non_dynamic_variants_unchanged() {
        // Non-dynamic variants must be returned unchanged.
        let id = Field::<CurrentNetwork>::from_u64(42);

        let constant = Output::<CurrentNetwork>::Constant(id, None);
        assert_eq!(constant.to_caller_output(), constant);

        let dynamic_record = Output::<CurrentNetwork>::DynamicRecord(id);
        assert_eq!(dynamic_record.to_caller_output(), dynamic_record);

        let external = Output::<CurrentNetwork>::ExternalRecord(id);
        assert_eq!(external.to_caller_output(), external);
    }
}
