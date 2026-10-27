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

// Tests for casting static records to `dynamic.record`.
mod cast;

// Tests for the `get.record.dynamic` instruction.
mod get_record_dynamic;

// Tests for `contains.dynamic`, `get.dynamic`, and `get.or_use.dynamic` in finalize blocks.
mod dynamic_mapping_operations;

// Integration tests combining translation, casting, and dynamic record operations.
mod mixed;

// Tests for the `call.dynamic` instruction with various call patterns.
mod call_dynamic;

// Tests for `DynamicFuture` behavior including await ordering and conditional execution.
mod dynamic_futures;

// Tests for recursive dynamic function calls and double-spend detection.
mod recursion;

// Tests for record translation between static and dynamic representations.
mod translation;

// Tests comparing static vs dynamic calls to all credits.aleo functions.
mod compare_calls_to_credits;

// Tests for restricted keywords at V14.
mod restricted_keywords;

// Tests for aleo generator opcodes migration.
mod generators;

// Tests for max writes migration.
mod max_writes;

// Tests for increased program size limits.
mod program_size;

// Tests for snark.verify opcode.
mod snark_verify;

// Tests for identifier literal types with V14 features.
mod identifier_literal;

// Tests for V3 deployments (amendments).
mod amendments;

use super::*;

use crate::{
    circuit::{Eject, Inject, Mode},
    vm::test_helpers::{sample_vm_at_height, *},
};

use anyhow::Result;
use console::{
    account::{Address, ViewKey},
    network::ConsensusVersion,
    program::{DynamicRecord, Entry, Identifier, Value},
};
use snarkvm_synthesizer_process::{deployment_cost, execution_cost};
use snarkvm_synthesizer_program::Program;
use snarkvm_utilities::TestRng;

/************************* Dynamic-record test cases *************************/
//
// The following list contains some translation- and dynamic-record-related
// situations tested in this module. Note it is non-exhaustive in that it does
// not detail all tested aspects of the functionality. Each situation is
// followed by a test case (of several, in some instances) where it arises.
//
// Single-translation test cases
// - input dynamic -> static external
//   In: translation.rs::test_translation_input_dynamic_external
// - input dynamic -> static non-external
//   In: translation.rs::test_translation_input_dynamic_non_external
// - output static non-external -> dynamic
//   In: translation.rs::test_translation_output_non_external_dynamic
// - output static external -> dynamic
//   In: translation.rs::test_translation_output_external_dynamic
//
// Chained cases
// - Static record minted in previous transaction converted to dynamic one outside the ledger and VM, then:
//       passed as input dynamic -> static
//       modify it (= mint new one)
//       output static -> dynamic
//       input dynamic -> dynamic (no translation)
//       input dynamic -> static
//   In: translation.rs::test_translation_triple
// - Input (dynamic, dynamic, dynamic) -> (static, static, static), output as static -> dynamic
//   In: mixed.rs: test_execution_cost_for_authorization
//
// get.record.dynamic
// - Record entries with different visibility but coinciding identifiers can be read with the same get.record.dynamic instruction
//   In: mixed.rs::test_translation_get_dynamic_cast_to_dynamic
//       note product_id is private in toy.record and public in ladder.record and both are read in manager.aleo/verify_signature
// - Dynamic records coming from different static records can be read with the same get.record.dynamic instruction
//   In: mixed.rs::test_translation_get_dynamic_cast_to_dynamic (e. g. manager.aleo/verify_signature)
//
// Consumption/production
// - Casting a static record into a dynamic one and passing the latter to a function expecting a dynamic record does not consume it
//   In: mixed.rs::test_translation_get_dynamic_cast_to_dynamic Case 1
//       (the call to function_verify_signature_field does not cause a double spend, as expected)
// - Casting a static record into a dynamic one and passing the latter to a function expecting a static record (translation involved) consumes it
//   In: cast.rs::test_cast_simple Case 2 (fails due to double spend)
// - A record is only produced once even if it is subsequently output as a dynamic record by the caller
//   In: mixed.rs::test_execution_cost_for_authorization
// - A record is only consumed once even if it is subsequently passed as a dynamic record to a callee
//   In: mixed.rs::test_translation_get_dynamic_cast_to_dynamic
//
// Key-fetching
// - Translations for the same record across different transitions are proved/verified with the same key (in the same Varuna batch)
//   In: translation.rs::test_translation_triple
//       three translations for gas.record:
//        - input dynamic -> static non-external
//        - output static non-external -> dynamic
//        - input dynamic -> static external
//       Run with the snark-print feature and observe the batch with 3 instances at the end
// - output static {program_a/record_name_a, program_a/record_name_b, program_b/record_name_a, program_b/ record_name_b} -> dynamic: four different keys should be fetched
//   In: translation.rs::test_differing_keys
//       Run with the snark-print feature and observe the batch sizes [1, 1, 1, 1, 1, 1, 1, 1, 1] (translation key IDs are also displayed for convenience)
//
// Signature consistency
// - Translate an output record from a call to a preexisting program to ensure signature-verification circuit has not changed
//   In: get_record_dynamic.rs::translate_transfer_public_to_private
