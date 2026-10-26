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

impl<A: Aleo> Entry<A, Plaintext<A>> {
    /// Returns this entry as a list of field elements, with the specified mode.
    ///
    /// # Hazards
    /// In `Public` and `Private` mode, the two visibility bits are witnesses constrained only to
    /// be 0 or 1, not to this entry's actual visibility. They are sound solely when the returned
    /// fields are hash-bound to committed state, as in `get.record.dynamic`. See
    /// `write_bits_le_with_visibility_as_mode` for details.
    pub fn to_fields_with_visibility_as_mode(&self, mode: Mode) -> Vec<Field<A>> {
        // Encode the data as little-endian bits.
        let mut bits_le = vec![];
        self.write_bits_le_with_visibility_as_mode(&mut bits_le, mode);

        // Adds one final bit to the data, to serve as a terminus indicator.
        // During decryption, this final bit ensures we've reached the end.
        bits_le.push(Boolean::constant(true));
        // Pack the bits into field elements.
        let fields = bits_le.chunks(A::BaseField::size_in_data_bits()).map(Field::from_bits_le).collect::<Vec<_>>();
        // Ensure the number of field elements does not exceed the maximum allowed size.
        match fields.len() <= A::MAX_DATA_SIZE_IN_FIELDS as usize {
            true => fields,
            false => A::halt("Entry<Plaintext> exceeds maximum allowed size"),
        }
    }
}

impl<A: Aleo> ToFields for Entry<A, Plaintext<A>> {
    type Field = Field<A>;

    /// Returns this entry as a list of field elements.
    fn to_fields(&self) -> Vec<Self::Field> {
        self.to_fields_with_visibility_as_mode(Mode::Constant)
    }
}
