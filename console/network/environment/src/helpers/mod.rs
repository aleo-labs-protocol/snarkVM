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

mod or_halt;
pub use or_halt::OrHalt;

mod sanitizer;
pub use sanitizer::Sanitizer;

pub mod variable_length;
pub use variable_length::{read_variable_length_integer, variable_length_integer};

/// A bech32m checksum with no hard length limit.
///
/// bech32 0.11 caps [`bech32::Bech32m`] at 1023 characters, but Aleo types such as
/// ciphertexts, state paths, and snark keys can legitimately exceed this. This type
/// uses identical generator coefficients and target residue as `Bech32m`, so encoded
/// strings are valid bech32m and round-trip correctly with any standard decoder that
/// does not enforce a maximum length.
pub enum LongBech32m {}

impl bech32::primitives::checksum::Checksum for LongBech32m {
    type MidstateRepr = u32;

    const CHECKSUM_LENGTH: usize = 6;
    const CODE_LENGTH: usize = usize::MAX;
    const GENERATOR_SH: [u32; 5] = [0x3b6a_57b2, 0x2650_8e6d, 0x1ea1_19fa, 0x3d42_33dd, 0x2a14_62b3];
    const TARGET_RESIDUE: u32 = 0x2bc830a3;
}
