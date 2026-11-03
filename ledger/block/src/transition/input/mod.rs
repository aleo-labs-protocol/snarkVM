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
    network::prelude::*,
    program::{Ciphertext, Plaintext, TransitionLeaf, ValueType},
    types::Field,
};

type Variant = u8;

/// The transition input.
#[derive(Clone, PartialEq, Eq)]
pub enum Input<N: Network> {
    /// The plaintext hash and (optional) plaintext.
    Constant(Field<N>, Option<Plaintext<N>>),
    /// The plaintext hash and (optional) plaintext.
    Public(Field<N>, Option<Plaintext<N>>),
    /// The ciphertext hash and (optional) ciphertext.
    Private(Field<N>, Option<Ciphertext<N>>),
    /// The serial number and tag of the record.
    Record(Field<N>, Field<N>),
    /// The hash of the external record's (function_id, record, tvk, input index).
    ExternalRecord(Field<N>),
    /// The hash of the dynamic record's (function_id, record, tvk, input index).
    DynamicRecord(Field<N>),
    /// The serial number, tag, and dynamic ID of a record input in a dynamic call transition.
    /// The `dynamic_id` is computed from `hash(function_id, record, tvk, index)`.
    /// From the caller's perspective, this appears as `DynamicRecord(dynamic_id)`.
    RecordWithDynamicID(Field<N>, Field<N>, Field<N>),
    /// The external record hash and dynamic ID of an external record input in a dynamic call transition.
    /// The `dynamic_id` is computed from `hash(function_id, record, tvk, index)`.
    /// From the caller's perspective, this appears as `DynamicRecord(dynamic_id)`.
    ExternalRecordWithDynamicID(Field<N>, Field<N>),
}

impl<N: Network> Input<N> {
    /// Returns the variant of the input.
    pub const fn variant(&self) -> Variant {
        match self {
            Input::Constant(..) => 0,
            Input::Public(..) => 1,
            Input::Private(..) => 2,
            Input::Record(..) => 3, // <- Changing this will invalidate 'console::StatePath' and 'circuit::StatePath'.
            Input::ExternalRecord(..) => 4,
            Input::DynamicRecord(..) => 5,
            Input::RecordWithDynamicID(..) => 6,
            Input::ExternalRecordWithDynamicID(..) => 7,
        }
    }

    /// Returns the ID of the input.
    pub const fn id(&self) -> &Field<N> {
        match self {
            Input::Constant(id, ..) => id,
            Input::Public(id, ..) => id,
            Input::Private(id, ..) => id,
            Input::Record(serial_number, ..) => serial_number,
            Input::ExternalRecord(id) => id,
            Input::DynamicRecord(id) => id,
            Input::RecordWithDynamicID(serial_number, ..) => serial_number,
            Input::ExternalRecordWithDynamicID(id, ..) => id,
        }
    }

    /// Returns the input as a transition leaf.
    /// Note: RecordWithDynamicID uses leaf variant 3 (same as Record) with version 2.
    /// Note: ExternalRecordWithDynamicID uses leaf variant 4 (same as ExternalRecord) with version 2.
    pub fn to_transition_leaf(&self, index: u8) -> TransitionLeaf<N> {
        match self {
            // RecordWithDynamicID produces leaf with version 2, variant 3.
            Input::RecordWithDynamicID(..) => TransitionLeaf::new_record_with_dynamic_id(index, *self.id()),
            // ExternalRecordWithDynamicID produces leaf with version 2, variant 4.
            Input::ExternalRecordWithDynamicID(..) => {
                TransitionLeaf::new_external_record_with_dynamic_id(index, *self.id())
            }
            // All other variants use their serialization variant byte.
            _ => TransitionLeaf::new(index, self.variant(), *self.id()),
        }
    }

    /// Returns the tag, if the input is a record.
    pub const fn tag(&self) -> Option<&Field<N>> {
        match self {
            Input::Record(_, tag) | Input::RecordWithDynamicID(_, tag, _) => Some(tag),
            _ => None,
        }
    }

    /// Returns the tag, if the input is a record, and consumes `self`.
    pub fn into_tag(self) -> Option<Field<N>> {
        match self {
            Input::Record(_, tag) | Input::RecordWithDynamicID(_, tag, _) => Some(tag),
            _ => None,
        }
    }

    /// Returns the serial number, if the input is a record.
    pub const fn serial_number(&self) -> Option<&Field<N>> {
        match self {
            Input::Record(serial_number, ..) | Input::RecordWithDynamicID(serial_number, ..) => Some(serial_number),
            _ => None,
        }
    }

    /// Returns the serial number, if the input is a record, and consumes `self`.
    pub fn into_serial_number(self) -> Option<Field<N>> {
        match self {
            Input::Record(serial_number, ..) | Input::RecordWithDynamicID(serial_number, ..) => Some(serial_number),
            _ => None,
        }
    }

    /// Returns the public verifier inputs for the proof.
    pub fn verifier_inputs(&self) -> impl '_ + Iterator<Item = N::Field> {
        [Some(self.id()), self.tag()].into_iter().flatten().map(|id| **id)
    }

    /// Returns the dynamic ID, if the input carries one.
    pub const fn dynamic_id(&self) -> Option<&Field<N>> {
        match self {
            Input::RecordWithDynamicID(_, _, dynamic_id) | Input::ExternalRecordWithDynamicID(_, dynamic_id) => {
                Some(dynamic_id)
            }
            _ => None,
        }
    }

    /// Returns the input from the caller's perspective.
    /// This converts internal variants (like RecordWithDynamicID) to what
    /// the caller would see (like DynamicRecord).
    pub fn to_caller_input(&self) -> Self {
        match self {
            // RecordWithDynamicID becomes DynamicRecord from caller's view.
            Self::RecordWithDynamicID(_, _, dynamic_id) => Self::DynamicRecord(*dynamic_id),
            // ExternalRecordWithDynamicID becomes DynamicRecord from caller's view.
            Self::ExternalRecordWithDynamicID(_, dynamic_id) => Self::DynamicRecord(*dynamic_id),
            // All other variants are unchanged.
            other => other.clone(),
        }
    }

    /// Returns `true` if the input is well-formed.
    /// If the optional value exists, this method checks that it hashes to the input ID.
    pub fn verify(&self, function_id: Field<N>, tcm: &Field<N>, index: usize) -> bool {
        // Ensure the hash of the value (if the value exists) is correct.
        let result = || match self {
            Input::Constant(hash, Some(input)) => {
                match input.to_fields() {
                    Ok(fields) => {
                        // Construct the (console) input index as a field element.
                        let index = Field::from_u16(index as u16);
                        // Construct the preimage as `(function ID || input || tcm || index)`.
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
            Input::Public(hash, Some(input)) => {
                match input.to_fields() {
                    Ok(fields) => {
                        // Construct the (console) input index as a field element.
                        let index = Field::from_u16(index as u16);
                        // Construct the preimage as `(function ID || input || tcm || index)`.
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
            Input::Private(hash, Some(value)) => {
                match value.to_fields() {
                    // Ensure the hash matches.
                    Ok(fields) => match N::hash_psd8(&fields) {
                        Ok(candidate_hash) => Ok(hash == &candidate_hash),
                        Err(error) => Err(error),
                    },
                    Err(error) => Err(error),
                }
            }
            Input::Constant(_, None) | Input::Public(_, None) | Input::Private(_, None) => {
                // This enforces that the transition *must* contain the value for this transition input.
                // A similar rule is enforced for the transition output.
                bail!("A transition input value is missing")
            }
            Input::Record(_, _)
            | Input::ExternalRecord(_)
            | Input::DynamicRecord(_)
            | Input::RecordWithDynamicID(_, _, _)
            | Input::ExternalRecordWithDynamicID(_, _) => Ok(true),
        };

        match result() {
            Ok(is_hash_valid) => is_hash_valid,
            Err(error) => {
                eprintln!("{error}");
                false
            }
        }
    }

    /// Returns `true` if the input matches the expected value type.
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
                | (Self::DynamicRecord(..), ValueType::DynamicRecord)
        )
    }

    /// Returns `true` if the input matches the given value type as seen by the callee. `Record`,
    /// `ExternalRecord`, `DynamicRecord`, `RecordWithDynamicID` and `ExternalRecordWithDynamicID`
    /// inputs are handled according to the value of `is_dynamic`:
    ///  - `Some(true)` enforces type correspondence assuming the inputs refer to a dynamic call.
    ///  - `Some(false)` enforces it assuming a static call.
    ///  - `None` is flexible and makes no assumption about the type of call: both dynamic-call and
    ///    static-call matching patterns return `true`.
    ///
    /// For inputs of an invalid type according to `is_dynamic`, this function returns false
    /// regardless of the value type.
    pub fn valid_as_argument(&self, callee_value_type: &ValueType<N>, is_dynamic: Option<bool>) -> bool {
        if matches!(
            (self, callee_value_type),
            (Self::Constant(..), ValueType::Constant(..))
                | (Self::Public(..), ValueType::Public(..))
                | (Self::Private(..), ValueType::Private(..))
        ) {
            return true;
        }

        if is_dynamic == Some(true) {
            // Unmatched variants:
            //  - Self::Record: cannot be the callee's view of a dynamic-call input, so we return
            //    false regardless of the ValueType
            //  - Self::ExternalRecord: same as above
            matches!(
                (self, callee_value_type),
                // Caller sees DynamicRecord, callee receives static Record, translation occurs
                (Self::RecordWithDynamicID(..), ValueType::Record(..))
                // Caller sees DynamicRecord, callee receives ExternalRecord, translation occurs
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
                // This can only occur for the root transition since static local calls are
                // disallowed
                (Self::Record(..), ValueType::Record(..))
                // Pass-through of External records (no translation )
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

    /// Sample the transition inputs.
    pub(crate) fn sample_inputs() -> Vec<(<CurrentNetwork as Network>::TransitionID, Input<CurrentNetwork>)> {
        let rng = &mut TestRng::default();

        // Sample a transition.
        let transaction = crate::transaction::test_helpers::sample_execution_transaction_with_fee(true, rng, 0);
        let transition = transaction.transitions().next().unwrap();

        // Retrieve the transition ID and input.
        let transition_id = *transition.id();
        let input = transition.inputs().iter().next().unwrap().clone();

        // Sample a random plaintext.
        let plaintext = Plaintext::Literal(Literal::Field(Uniform::rand(rng)), Default::default());
        let plaintext_hash = CurrentNetwork::hash_bhp1024(&plaintext.to_bits_le()).unwrap();
        // Sample a random ciphertext.
        let fields: Vec<_> = (0..10).map(|_| Uniform::rand(rng)).collect();
        let ciphertext = Ciphertext::from_fields(&fields).unwrap();
        let ciphertext_hash = CurrentNetwork::hash_bhp1024(&ciphertext.to_bits_le()).unwrap();

        vec![
            (transition_id, input),
            (Uniform::rand(rng), Input::Constant(Uniform::rand(rng), None)),
            (Uniform::rand(rng), Input::Constant(plaintext_hash, Some(plaintext.clone()))),
            (Uniform::rand(rng), Input::Public(Uniform::rand(rng), None)),
            (Uniform::rand(rng), Input::Public(plaintext_hash, Some(plaintext))),
            (Uniform::rand(rng), Input::Private(Uniform::rand(rng), None)),
            (Uniform::rand(rng), Input::Private(ciphertext_hash, Some(ciphertext))),
            (Uniform::rand(rng), Input::Record(Uniform::rand(rng), Uniform::rand(rng))),
            (Uniform::rand(rng), Input::ExternalRecord(Uniform::rand(rng))),
            (
                Uniform::rand(rng),
                Input::RecordWithDynamicID(Uniform::rand(rng), Uniform::rand(rng), Uniform::rand(rng)),
            ),
            (Uniform::rand(rng), Input::ExternalRecordWithDynamicID(Uniform::rand(rng), Uniform::rand(rng))),
            (Uniform::rand(rng), Input::DynamicRecord(Uniform::rand(rng))),
        ]
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use console::network::MainnetV0;

    type CurrentNetwork = MainnetV0;

    #[test]
    fn test_to_caller_input_record_with_dynamic_id() {
        // RecordWithDynamicID should become DynamicRecord(dynamic_id) from caller's view.
        let serial_number = Field::<CurrentNetwork>::from_u64(1);
        let tag = Field::<CurrentNetwork>::from_u64(2);
        let dynamic_id = Field::<CurrentNetwork>::from_u64(3);

        let input = Input::<CurrentNetwork>::RecordWithDynamicID(serial_number, tag, dynamic_id);
        let caller_input = input.to_caller_input();

        assert_eq!(caller_input, Input::<CurrentNetwork>::DynamicRecord(dynamic_id));
    }

    #[test]
    fn test_to_caller_input_external_record_with_dynamic_id() {
        // ExternalRecordWithDynamicID should become DynamicRecord(dynamic_id) from caller's view.
        let ext_id = Field::<CurrentNetwork>::from_u64(10);
        let dynamic_id = Field::<CurrentNetwork>::from_u64(20);

        let input = Input::<CurrentNetwork>::ExternalRecordWithDynamicID(ext_id, dynamic_id);
        let caller_input = input.to_caller_input();

        assert_eq!(caller_input, Input::<CurrentNetwork>::DynamicRecord(dynamic_id));
    }

    #[test]
    fn test_to_caller_input_non_dynamic_variants_unchanged() {
        // Non-dynamic variants must be returned unchanged.
        let id = Field::<CurrentNetwork>::from_u64(42);

        let constant = Input::<CurrentNetwork>::Constant(id, None);
        assert_eq!(constant.to_caller_input(), constant);

        let public = Input::<CurrentNetwork>::Public(id, None);
        assert_eq!(public.to_caller_input(), public);

        let dynamic_record = Input::<CurrentNetwork>::DynamicRecord(id);
        assert_eq!(dynamic_record.to_caller_input(), dynamic_record);

        let external = Input::<CurrentNetwork>::ExternalRecord(id);
        assert_eq!(external.to_caller_input(), external);
    }
}
