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

//! Each network reads its own consensus version heights. The test implementation reads one table for all networks.

#![cfg(not(any(feature = "test", feature = "test_consensus_heights")))]

use snarkvm_console_network::prelude::*;

#[test]
fn test_consensus_heights_are_network_specific() {
    assert_eq!(TestnetV0::CONSENSUS_VERSION_HEIGHTS(), &TestnetV0::_CONSENSUS_VERSION_HEIGHTS);
    assert_eq!(CanaryV0::CONSENSUS_VERSION_HEIGHTS(), &CanaryV0::_CONSENSUS_VERSION_HEIGHTS);
    assert_eq!(MainnetV0::CONSENSUS_VERSION_HEIGHTS(), &MainnetV0::_CONSENSUS_VERSION_HEIGHTS);
}
