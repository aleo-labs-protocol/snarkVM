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

impl<A: Aleo> ToFieldsRaw for Value<A> {
    /// Returns the circuit value as a list of fields using the raw bits.
    #[inline]
    fn to_fields_raw(&self) -> Vec<Field<A>> {
        match self {
            Self::Plaintext(plaintext) => plaintext.to_fields_raw(),
            // Note: We use the standard `to_fields` for records and futures because they are Aleo-specific types.
            Self::Record(record) => record.to_fields(),
            Self::Future(future) => future.to_fields(),
            Self::DynamicRecord(dynamic_record) => dynamic_record.to_fields(),
            Self::DynamicFuture(dynamic_future) => dynamic_future.to_fields(),
        }
    }
}
