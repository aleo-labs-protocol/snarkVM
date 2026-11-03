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

// Tests for stack fetching relevant to the record-existence check.
mod record_existence_stacks;

// Tests with Aleo functions which output scalars.
// The relevant changes are not ConsensusVersion::V18-gated, but they were introduced at that point
// in time.
mod scalar_outputs;

// Tests for block-wide synthesis limits.
mod blockwide_synthesis_limit;

use super::*;

use console::account::ViewKey;
use snarkvm_ledger_narwhal_subdag::test_helpers::subdag_with_cert_count;
use snarkvm_synthesizer_snark::VerifyingKey;
