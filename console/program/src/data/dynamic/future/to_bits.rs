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

impl<N: Network> ToBits for DynamicFuture<N> {
    /// Returns the dynamic future as a list of **little-endian** bits.
    #[inline]
    fn write_bits_le(&self, vec: &mut Vec<bool>) {
        // Write the bits for the program name.
        self.program_name.write_bits_le(vec);

        // Write the bits for the program network.
        self.program_network.write_bits_le(vec);

        // Write the bits for the function name.
        self.function_name.write_bits_le(vec);

        // Write the bits for the checksum.
        self.checksum.write_bits_le(vec);
    }

    /// Returns the dynamic future as a list of **big-endian** bits.
    #[inline]
    fn write_bits_be(&self, vec: &mut Vec<bool>) {
        // Write the bits for the program name.
        self.program_name.write_bits_be(vec);

        // Write the bits for the program network.
        self.program_network.write_bits_be(vec);

        // Write the bits for the function name.
        self.function_name.write_bits_be(vec);

        // Write the bits for the checksum.
        self.checksum.write_bits_be(vec);
    }
}

impl<N: Network> DynamicFuture<N> {
    /// Returns the number of bits in a dynamic future.
    #[inline]
    pub fn size_in_bits() -> Result<usize> {
        // A dynamic future contains 4 field elements: program_name, program_network, function_name, and checksum.
        Field::<N>::size_in_bits().checked_mul(4).ok_or_else(|| anyhow!("`size_in_bits` overflowed"))
    }

    /// Returns the number of raw bits in a dynamic future.
    #[inline]
    pub fn size_in_bits_raw() -> Result<usize> {
        Self::size_in_bits()
    }
}
