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

use super::*;

impl<N: Network> Stack<N> {
    /// Samples a plaintext value according to the given plaintext type.
    pub fn sample_plaintext<R: Rng + CryptoRng>(
        &self,
        plaintext_type: &PlaintextType<N>,
        rng: &mut R,
    ) -> Result<Plaintext<N>> {
        // Sample a plaintext value.
        let plaintext = self.sample_plaintext_internal(plaintext_type, 0, rng)?;
        // Ensure the plaintext value matches the plaintext type.
        self.matches_plaintext(&plaintext, plaintext_type)?;
        // Return the plaintext value.
        Ok(plaintext)
    }

    /// Samples a future value according to the given future type.
    pub fn sample_future<R: Rng + CryptoRng>(&self, locator: &Locator<N>, rng: &mut R) -> Result<Future<N>> {
        // Sample a future value.
        let future = self.sample_future_internal(locator, 0, rng)?;
        // Ensure the future value matches the future type.
        self.matches_future(&future, locator)?;
        // Return the future value.
        Ok(future)
    }

    /// Samples a dynamic future value.
    pub fn sample_dynamic_future<R: Rng + CryptoRng>(&self, rng: &mut R) -> Result<DynamicFuture<N>> {
        // Sample a random program name.
        let program_name = Field::rand(rng);
        // Use the `.aleo` program network.
        let program_network = Identifier::from_str("aleo").unwrap().to_field()?; // Safe: "aleo" is always a valid identifier.
        // Sample a random function name.
        let function_name = Field::rand(rng);
        // Sample a random argument root.
        let argument_root = Field::rand(rng);

        Ok(DynamicFuture::new_unchecked(program_name, program_network, function_name, argument_root, None))
    }

    /// Samples a dynamic record value.
    pub fn sample_dynamic_record<R: Rng + CryptoRng>(&self, rng: &mut R) -> Result<DynamicRecord<N>> {
        // Sample a random address.
        let owner = Address::rand(rng);
        // Sample a random root.
        let root = Field::rand(rng);
        // Sample a random nonce.
        let nonce = Group::<N>::rand(rng);
        // Sample a random version.
        let version = U8::<N>::rand(rng);

        Ok(DynamicRecord::new_unchecked(owner, root, nonce, version, None))
    }

    /// Returns a record for the given record name.
    pub(crate) fn sample_record_internal<R: Rng + CryptoRng>(
        &self,
        burner_address: &Address<N>,
        record_name: &Identifier<N>,
        nonce: Group<N>,
        depth: usize,
        rng: &mut R,
    ) -> Result<Record<N, Plaintext<N>>> {
        // If the depth exceeds the maximum depth, then the plaintext type is invalid.
        ensure!(depth <= N::MAX_DATA_DEPTH, "Plaintext exceeded maximum depth of {}", N::MAX_DATA_DEPTH);

        // Retrieve the record type from the program.
        let record_type = self.program.get_record(record_name)?;

        // Initialize the owner based on the visibility.
        let owner = match record_type.owner().is_public() {
            true => RecordOwner::Public(*burner_address),
            false => RecordOwner::Private(Plaintext::Literal(Literal::Address(*burner_address), Default::default())),
        };

        // Initialize the record data according to the defined type.
        let data = record_type
            .entries()
            .iter()
            .map(|(entry_name, entry_type)| {
                // Sample the entry value.
                let entry = self.sample_entry_internal(entry_type, depth + 1, rng)?;
                // Return the entry.
                Ok((*entry_name, entry))
            })
            .collect::<Result<IndexMap<_, _>>>()?;

        // Set the record version.
        let version = U8::<N>::rand(rng);

        // Return the record.
        Record::<N, Plaintext<N>>::from_plaintext(owner, data, nonce, version)
    }

    /// Samples an entry according to the given entry type.
    fn sample_entry_internal<R: Rng + CryptoRng>(
        &self,
        entry_type: &EntryType<N>,
        depth: usize,
        rng: &mut R,
    ) -> Result<Entry<N, Plaintext<N>>> {
        // If the depth exceeds the maximum depth, then the entry type is invalid.
        ensure!(depth <= N::MAX_DATA_DEPTH, "Entry exceeded maximum depth of {}", N::MAX_DATA_DEPTH);

        match entry_type {
            EntryType::Constant(plaintext_type)
            | EntryType::Public(plaintext_type)
            | EntryType::Private(plaintext_type) => {
                // Sample the plaintext value.
                let plaintext = self.sample_plaintext_internal(plaintext_type, depth, rng)?;
                // Return the entry.
                match entry_type {
                    EntryType::Constant(..) => Ok(Entry::Constant(plaintext)),
                    EntryType::Public(..) => Ok(Entry::Public(plaintext)),
                    EntryType::Private(..) => Ok(Entry::Private(plaintext)),
                }
            }
        }
    }

    /// Samples a plaintext value according to the given plaintext type.
    fn sample_plaintext_internal<R: Rng + CryptoRng>(
        &self,
        plaintext_type: &PlaintextType<N>,
        depth: usize,
        rng: &mut R,
    ) -> Result<Plaintext<N>> {
        // If the depth exceeds the maximum depth, then the plaintext type is invalid.
        ensure!(depth <= N::MAX_DATA_DEPTH, "Plaintext exceeded maximum depth of {}", N::MAX_DATA_DEPTH);

        // Sample the plaintext value.
        let plaintext = match plaintext_type {
            // Sample a literal.
            PlaintextType::Literal(literal_type) => {
                Plaintext::Literal(Literal::sample(*literal_type, rng), Default::default())
            }
            // Sample a struct.
            PlaintextType::Struct(struct_name) => {
                // Retrieve the struct.
                let struct_ = self.program.get_struct(struct_name)?;
                // Sample each member of the struct.
                let members = struct_
                    .members()
                    .iter()
                    .map(|(member_name, member_type)| {
                        // Sample the member value.
                        let member = self.sample_plaintext_internal(member_type, depth + 1, rng)?;
                        // Return the member.
                        Ok((*member_name, member))
                    })
                    .collect::<Result<IndexMap<_, _>>>()?;

                Plaintext::Struct(members, Default::default())
            }
            PlaintextType::ExternalStruct(locator) => {
                let external_stack = self.get_external_stack(locator.program_id())?;
                let new_type = PlaintextType::Struct(*locator.resource());
                return external_stack.sample_plaintext_internal(&new_type, depth, rng);
            }
            // Sample an array.
            PlaintextType::Array(array_type) => {
                // Sample each element of the array.
                let elements = (0..**array_type.length())
                    .map(|_| {
                        // Sample the element value.
                        self.sample_plaintext_internal(array_type.next_element_type(), depth + 1, rng)
                    })
                    .collect::<Result<Vec<_>>>()?;

                Plaintext::Array(elements, Default::default())
            }
        };
        // Return the plaintext.
        Ok(plaintext)
    }

    /// Samples a future value according to the given locator.
    fn sample_future_internal<R: Rng + CryptoRng>(
        &self,
        locator: &Locator<N>,
        depth: usize,
        rng: &mut R,
    ) -> Result<Future<N>> {
        // Retrieve the external stack, if needed.
        let external_stack = match locator.program_id() == self.program_id() {
            true => None,
            // Attention - This method must fail here and early return if the external program is missing.
            // Otherwise, this method will proceed to look for the requested function in its own program.
            false => Some(self.get_external_stack(locator.program_id())?),
        };
        // Retrieve the associated function.
        let function = match &external_stack {
            Some(external_stack) => external_stack.get_function_ref(locator.resource())?,
            None => self.get_function_ref(locator.resource())?,
        };

        // Retrieve the finalize inputs.
        let inputs = match function.finalize_logic() {
            Some(finalize_logic) => finalize_logic.inputs(),
            None => bail!("Function '{locator}' does not have a finalize block"),
        };

        // Sample the arguments using the external stack if the future is from an external program.
        let arguments = inputs
            .into_iter()
            .map(|input| {
                match input.finalize_type() {
                    FinalizeType::Plaintext(plaintext_type) => {
                        // Sample the plaintext value using the appropriate stack.
                        let plaintext = match &external_stack {
                            Some(external_stack) => {
                                external_stack.sample_plaintext_internal(plaintext_type, depth + 1, rng)?
                            }
                            None => self.sample_plaintext_internal(plaintext_type, depth + 1, rng)?,
                        };
                        // Return the argument.
                        Ok(Argument::Plaintext(plaintext))
                    }
                    FinalizeType::Future(locator) => {
                        // Sample the future value using the appropriate stack.
                        let future = match &external_stack {
                            Some(external_stack) => external_stack.sample_future_internal(locator, depth + 1, rng)?,
                            None => self.sample_future_internal(locator, depth + 1, rng)?,
                        };
                        // Return the argument.
                        Ok(Argument::Future(future))
                    }
                    FinalizeType::DynamicFuture => {
                        // Sample the dynamic future value.
                        let dynamic_future = self.sample_dynamic_future(rng)?;
                        // Return the argument.
                        Ok(Argument::DynamicFuture(dynamic_future))
                    }
                }
            })
            .collect::<Result<Vec<_>>>()?;

        Ok(Future::new(*locator.program_id(), *locator.resource(), arguments))
    }
}
