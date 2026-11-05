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
mod try_from;

#[cfg(feature = "view_key")]
use crate::ViewKey;

use snarkvm_console_network::prelude::*;
use snarkvm_console_types::Field;

#[derive(Copy, Clone, PartialEq, Eq, Hash)]
pub struct GraphKey<N: Network> {
    /// The graph key `sk_tag` := Hash(view_key || ctr).
    sk_tag: Field<N>,
}

impl<N: Network> GraphKey<N> {
    /// Returns the graph key.
    pub const fn sk_tag(&self) -> Field<N> {
        self.sk_tag
    }
}
