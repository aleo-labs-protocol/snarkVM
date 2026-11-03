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

impl<N: Network> DynamicRecord<N> {
    /// Returns the entry from the given path.
    pub fn find<A: Into<Access<N>> + Copy + Debug>(&self, path: &[A]) -> Result<Value<N>> {
        // If the path is of length one, check if the path is requesting the `owner`.
        if path.len() == 1 && path[0].into() == Access::Member(Identifier::from_str("owner")?) {
            Ok(Value::Plaintext(Plaintext::from(Literal::Address(self.owner))))
        } else {
            bail!("Only the 'owner' of a dynamic record can be accessed directly, use 'get.record.dynamic' instead.")
        }
    }
}
