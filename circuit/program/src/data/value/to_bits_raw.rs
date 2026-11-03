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

impl<A: Aleo> ToBitsRaw for Value<A> {
    /// Returns the circuit value as a list of raw **little-endian** bits.
    #[inline]
    fn write_bits_raw_le(&self, vec: &mut Vec<Boolean<A>>) {
        match self {
            Self::Plaintext(plaintext) => plaintext.write_bits_raw_le(vec),
            // Note: We use the standard `write_bits_le` for records and futures because they are Aleo-specific types.
            Self::Record(record) => record.write_bits_le(vec),
            Self::Future(future) => future.write_bits_le(vec),
            Self::DynamicRecord(dynamic_record) => dynamic_record.write_bits_le(vec),
            Self::DynamicFuture(dynamic_future) => dynamic_future.write_bits_le(vec),
        };
    }

    /// Returns the circuit value as a list of raw **big-endian** bits.
    #[inline]
    fn write_bits_raw_be(&self, vec: &mut Vec<Boolean<A>>) {
        match self {
            Self::Plaintext(plaintext) => plaintext.write_bits_raw_be(vec),
            // Note: We use `write_bits_be` for records and futures to maintain consistency with the `ToBits` trait.
            Self::Record(record) => record.write_bits_be(vec),
            Self::Future(future) => future.write_bits_be(vec),
            Self::DynamicRecord(dynamic_record) => dynamic_record.write_bits_be(vec),
            Self::DynamicFuture(dynamic_future) => dynamic_future.write_bits_be(vec),
        };
    }
}
