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

// Tests specific to older consensus versions, not executed in most flows by default.
#[cfg(feature = "test-old-consensus-versions")]
mod test_v8;

#[cfg(feature = "test-old-consensus-versions")]
mod test_v9;

#[cfg(feature = "test-old-consensus-versions")]
mod test_v10;

#[cfg(feature = "test-old-consensus-versions")]
mod test_v11;

#[cfg(feature = "test-old-consensus-versions")]
mod test_v13;

#[cfg(feature = "test-old-consensus-versions")]
mod test_v14;

// Tests specific to recent consensus versions, executed in more flows than the older ones by
// default.
#[cfg(feature = "test")]
mod test_v15;

mod test_prune;

#[cfg(feature = "test")]
mod test_v16;

#[cfg(feature = "test")]
mod test_v18;

#[cfg(feature = "test")]
mod test_v20;

#[cfg(feature = "test")]
mod test_v22;

use super::*;
use crate::vm::test_helpers::*;
