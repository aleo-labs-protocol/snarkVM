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

impl<N: Network> ToBits for DynamicRecord<N> {
    /// Returns the dynamic record as a list of **little-endian** bits.
    fn write_bits_le(&self, vec: &mut Vec<bool>) {
        // Construct the owner bits.
        self.owner.write_bits_le(vec);

        // Construct the root bits.
        self.root.write_bits_le(vec);

        // Construct the nonce bits.
        self.nonce.write_bits_le(vec);

        // Construct the version bits.
        self.version.write_bits_le(vec);
    }

    /// Returns the dynamic record as a list of **big-endian** bits.
    fn write_bits_be(&self, vec: &mut Vec<bool>) {
        // Construct the owner bits.
        self.owner.write_bits_be(vec);

        // Construct the root bits.
        self.root.write_bits_be(vec);

        // Construct the nonce bits.
        self.nonce.write_bits_be(vec);

        // Construct the version bits.
        self.version.write_bits_be(vec);
    }
}

impl<N: Network> DynamicRecord<N> {
    /// Returns the number of bits in a dynamic record.
    #[inline]
    pub fn size_in_bits() -> Result<usize> {
        // Account for the owner bits.
        let mut size = Address::<N>::size_in_bits();
        // Account for the root bits.
        size = size.checked_add(Field::<N>::size_in_bits()).ok_or_else(|| anyhow!("`size_in_bits` overflowed"))?;
        // Account for the nonce bits.
        size = size.checked_add(Group::<N>::size_in_bits()).ok_or_else(|| anyhow!("`size_in_bits` overflowed"))?;
        // Account for the version bits.
        size = size.checked_add(U8::<N>::size_in_bits()).ok_or_else(|| anyhow!("`size_in_bits` overflowed"))?;

        Ok(size)
    }

    /// Returns the number of raw bits in a dynamic record.
    #[inline]
    pub fn size_in_bits_raw() -> Result<usize> {
        Self::size_in_bits()
    }
}
