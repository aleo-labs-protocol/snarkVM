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

impl<A: Aleo> Visibility<A> for Plaintext<A> {
    /// Returns the number of field elements to encode `self`.
    fn size_in_fields(&self) -> u16 {
        // Compute the number of bits.
        let num_bits = self.to_bits_le().len() + 1; // 1 extra bit for the terminus indicator.
        // Compute the ceiling division of the number of bits by the number of bits in a field element.
        let num_fields = num_bits.div_ceil(A::BaseField::size_in_data_bits());
        // Ensure the number of field elements does not exceed the maximum allowed size.
        match u16::try_from(num_fields) {
            // Return the number of field elements.
            Ok(num_fields) if u32::from(num_fields) <= A::MAX_DATA_SIZE_IN_FIELDS => num_fields,
            _ => A::halt("Plaintext is too large to encode in field elements."),
        }
    }
}
