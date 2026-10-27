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

// Tests for quorum block compute spend limits.
mod block_spend_limit;

// Tests for increased program size limits.
mod program_size;

// Tests for the `<name>/checksum` component checksum operand.
mod component_checksum;

// Tests an example flow with sample_authorization_extended and authorize_requests.
pub(crate) mod construct_authorization;

use super::*;

use console::{account::Address, network::ConsensusVersion, prelude::FromStr, program::Value};

use snarkvm_ledger_block::{Solutions, Transaction};
use snarkvm_synthesizer_process::{execute_compute_cost_in_microcredits, execution_cost};
use snarkvm_synthesizer_program::{FinalizeGlobalState, Program};
use snarkvm_utilities::TestRng;
