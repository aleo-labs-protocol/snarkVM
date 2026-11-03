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

impl<N: Network> ToFields for DynamicFuture<N> {
    type Field = Field<N>;

    /// Returns the dynamic future as a list of fields.
    #[inline]
    fn to_fields(&self) -> Result<Vec<Self::Field>> {
        // Encode the data as little-endian bits.
        let mut bits_le = self.to_bits_le();
        // Adds one final bit to the data, to serve as a terminus indicator.
        // This prevents ambiguity from zero-padding: without it, a shorter bit sequence and
        // a longer one (same bits plus trailing zeros) would pack to the same field elements.
        bits_le.push(true);
        // Pack the bits into field elements.
        let fields = bits_le
            .chunks(Field::<N>::size_in_data_bits())
            .map(Field::<N>::from_bits_le)
            .collect::<Result<Vec<_>>>()?;
        // Ensure the number of field elements does not exceed the maximum allowed size.
        match fields.len() <= N::MAX_DATA_SIZE_IN_FIELDS as usize {
            true => Ok(fields),
            false => bail!("DynamicFuture exceeds maximum allowed size"),
        }
    }
}
