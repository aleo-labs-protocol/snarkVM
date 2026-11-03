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

use console::network::{Network, TestnetV0};

/// Returns `true` if the given transaction ID belongs to the set of transactions accepted on
/// Testnet. These transactions remain valid for historical chain continuity.
pub(crate) fn is_pre_accepted_testnet_transaction<N: Network>(id: N::TransactionID) -> bool {
    if N::ID != TestnetV0::ID {
        return false;
    }
    const IDS: &[&str] = &[
        "at16r0qm288yvprqyvq22dj0elsx3dsvep43tslwz65r8a7t0z0zvpsqxxpmf",
        "at14lzzs3fxeuazwfhh5tw66z4pwlleskzcmdsvwtrfsr52xkytmygs0kqfhl",
        "at1mk6em0zj0s07cs0s4h39xtq9w9rktnxfehmwxqetmv2d96ct059q62tu7t",
    ];
    let id_str = id.to_string();
    IDS.iter().any(|&s| id_str == s)
}
