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

use crate::FinalizeOperation;
use console::{
    network::Network,
    prelude::Result,
    program::{Identifier, Plaintext, ProgramID, Value},
};

/// This trait is sealed. Only snarkVM implements it.
pub trait FinalizeStoreTrait<N: Network>: crate::sealed_execution::Sealed {
    /// Returns `true` if the given `program ID` and `mapping name` is confirmed to exist.
    fn contains_mapping_confirmed(&self, program_id: &ProgramID<N>, mapping_name: &Identifier<N>) -> Result<bool>;

    /// Returns `true` if the given `program ID` and `mapping name` exist.
    /// This method was added to support execution of constructors during deployment.
    /// Prior to supporting program upgrades, `contains_mapping_confirmed` was used to check that a mapping exists before executing a command like `set`, `get`, `remove`, etc.
    /// However, during deployment, the mapping only speculatively exists, so `contains_mapping_speculative` should be used instead.
    /// This usage is safe because the mappings used in a program are statically verified to exist in `FinalizeTypes::from_*` before the deployment or upgrade's constructor is executed.
    fn contains_mapping_speculative(&self, program_id: &ProgramID<N>, mapping_name: &Identifier<N>) -> Result<bool>;

    /// Returns `true` if the given `program ID`, `mapping name`, and `key` exist.
    fn contains_key_speculative(
        &self,
        program_id: ProgramID<N>,
        mapping_name: Identifier<N>,
        key: &Plaintext<N>,
    ) -> Result<bool>;

    /// Returns the speculative value for the given `program ID`, `mapping name`, and `key`.
    fn get_value_speculative(
        &self,
        program_id: ProgramID<N>,
        mapping_name: Identifier<N>,
        key: &Plaintext<N>,
    ) -> Result<Option<Value<N>>>;

    /// Stores the given `(key, value)` pair at the given `program ID` and `mapping name` in storage.
    /// If the `mapping name` is not initialized, an error is returned.
    /// If the `key` already exists, the method returns an error.
    fn insert_key_value(
        &self,
        program_id: ProgramID<N>,
        mapping_name: Identifier<N>,
        key: Plaintext<N>,
        value: Value<N>,
    ) -> Result<FinalizeOperation<N>>;

    /// Stores the given `(key, value)` pair at the given `program ID` and `mapping name` in storage.
    /// If the `mapping name` is not initialized, an error is returned.
    /// If the `key` does not exist, the `(key, value)` pair is initialized.
    /// If the `key` already exists, the `value` is overwritten.
    fn update_key_value(
        &self,
        program_id: ProgramID<N>,
        mapping_name: Identifier<N>,
        key: Plaintext<N>,
        value: Value<N>,
    ) -> Result<FinalizeOperation<N>>;

    /// Removes the key-value pair for the given `program ID`, `mapping name`, and `key` from storage.
    /// If the `key` does not exist, the method returns `None`.
    fn remove_key_value(
        &self,
        program_id: ProgramID<N>,
        mapping_name: Identifier<N>,
        key: &Plaintext<N>,
    ) -> Result<Option<FinalizeOperation<N>>>;
}
