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

// Tests for the record-existence check.
mod record_existence;

// Tests on the input/output behaviour of closures and related functionality.
mod closure_records;

// Tests on the use of `commit_*_raw` instruction variants.
mod commit_raw;

// Additional test for cost estimation without a private key.
mod cost_for_call;

// Tests for the externally-callable `view` function prototype.
mod views;

// Tests for restricted keywords at V15.
mod restricted_keywords;

use super::*;

use console::{
    account::ViewKey,
    network::ConsensusVersion,
    program::{Identifier, Value},
};

use snarkvm_synthesizer_program::Program;
use snarkvm_utilities::TestRng;
