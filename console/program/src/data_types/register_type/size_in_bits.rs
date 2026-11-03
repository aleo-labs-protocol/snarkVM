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

use crate::{DynamicFuture, DynamicRecord, RecordType, StructType};

use super::*;

impl<N: Network> RegisterType<N> {
    /// Returns the number of bits of a register type.
    pub fn size_in_bits<F0, F1, F2, F3, F4>(
        &self,
        get_struct: &F0,
        get_external_struct: &F1,
        get_record: &F2,
        get_external_record: &F3,
        get_future: &F4,
    ) -> Result<usize>
    where
        F0: Fn(&Identifier<N>) -> Result<StructType<N>>,
        F1: Fn(&Locator<N>) -> Result<StructType<N>>,
        F2: Fn(&Identifier<N>) -> Result<RecordType<N>>,
        F3: Fn(&Locator<N>) -> Result<RecordType<N>>,
        F4: Fn(&Locator<N>) -> Result<Vec<FinalizeType<N>>>,
    {
        match self {
            RegisterType::Plaintext(plaintext_type) => plaintext_type.size_in_bits(get_struct, get_external_struct),
            RegisterType::Record(identifier) => get_record(identifier)?.size_in_bits(get_struct, get_external_struct),
            RegisterType::ExternalRecord(locator) => {
                get_external_record(locator)?.size_in_bits(get_struct, get_external_struct)
            }
            RegisterType::Future(locator) => {
                FinalizeType::future_size_in_bits(locator, get_struct, get_external_struct, get_future)
            }
            RegisterType::DynamicRecord => DynamicRecord::<N>::size_in_bits(),
            RegisterType::DynamicFuture => DynamicFuture::<N>::size_in_bits(),
        }
    }

    /// Returns the number of raw bits of a register type.
    pub fn size_in_bits_raw<F0, F1, F2, F3, F4>(
        &self,
        get_struct: &F0,
        get_external_struct: &F1,
        get_record: &F2,
        get_external_record: &F3,
        get_future: &F4,
    ) -> Result<usize>
    where
        F0: Fn(&Identifier<N>) -> Result<StructType<N>>,
        F1: Fn(&Locator<N>) -> Result<StructType<N>>,
        F2: Fn(&Identifier<N>) -> Result<RecordType<N>>,
        F3: Fn(&Locator<N>) -> Result<RecordType<N>>,
        F4: Fn(&Locator<N>) -> Result<Vec<FinalizeType<N>>>,
    {
        match self {
            RegisterType::Plaintext(plaintext_type) => plaintext_type.size_in_bits_raw(get_struct, get_external_struct),
            RegisterType::Record(identifier) => {
                get_record(identifier)?.size_in_bits_raw(get_struct, get_external_struct)
            }
            RegisterType::ExternalRecord(locator) => {
                get_external_record(locator)?.size_in_bits_raw(get_struct, get_external_struct)
            }
            RegisterType::Future(locator) => {
                FinalizeType::future_size_in_bits_raw(locator, get_struct, get_external_struct, get_future)
            }
            RegisterType::DynamicRecord => DynamicRecord::<N>::size_in_bits_raw(),
            RegisterType::DynamicFuture => DynamicFuture::<N>::size_in_bits_raw(),
        }
    }
}
