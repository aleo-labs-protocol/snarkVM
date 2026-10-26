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

// Tests that the translation-marked variants of Input and Output are checked correctly.
mod translated_type_checks;

// Tests for the V20 plaintext-type size bound.
mod plaintext_size;

// Tests on the deployment of programs with non-deterministic dynamic-call targets. The relevant
// changes are not ConsensusVersion::V19-gated, but they were introduced at that point in time.
mod non_deterministic_dynamic_targets;

use super::*;
