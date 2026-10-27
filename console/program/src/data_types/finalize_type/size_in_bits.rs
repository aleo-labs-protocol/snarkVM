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

use crate::{DynamicFuture, Identifier, PlaintextType, StructType};

use super::*;

use std::collections::HashMap;

impl<N: Network> FinalizeType<N> {
    /// Returns the number of bits of a finalize type.
    /// Note. The plaintext variant is assumed to be an argument of a `Future` and this does not have a "raw" serialization.
    pub fn future_size_in_bits<F0, F1, F2>(
        locator: &Locator<N>,
        get_struct: &F0,
        get_external_struct: &F1,
        get_future: &F2,
    ) -> Result<usize>
    where
        F0: Fn(&Identifier<N>) -> Result<StructType<N>>,
        F1: Fn(&Locator<N>) -> Result<StructType<N>>,
        F2: Fn(&Locator<N>) -> Result<Vec<FinalizeType<N>>>,
    {
        FinalizeType::Future(*locator).size_in_bits_internal(get_struct, get_external_struct, get_future, 0)
    }

    /// A helper function to determine the number of bits of a plaintext type, while tracking the depth of the data.
    /// Note. The plaintext variant is assumed to be an argument of a `Future` and thus does not have a "raw" serialization.
    pub fn size_in_bits_internal<F0, F1, F2>(
        &self,
        get_struct: &F0,
        get_external_struct: &F1,
        get_future: &F2,
        depth: usize,
    ) -> Result<usize>
    where
        F0: Fn(&Identifier<N>) -> Result<StructType<N>>,
        F1: Fn(&Locator<N>) -> Result<StructType<N>>,
        F2: Fn(&Locator<N>) -> Result<Vec<FinalizeType<N>>>,
    {
        // Track the `(size, height)` of the futures and struct types that have already been sized, so that one
        // shared by many arguments is expanded at most once. Futures nest — a finalize input may be a future of an
        // imported function, whose own finalize inputs may again be futures — so, exactly as for structs, this
        // graph is acyclic with exponentially many paths and the walk below would not otherwise terminate.
        let mut memoized_futures = HashMap::new();
        let mut memoized_structs = HashMap::new();
        Ok(self
            .size_in_bits_inner(
                get_struct,
                get_external_struct,
                get_future,
                depth,
                &mut memoized_futures,
                &mut memoized_structs,
            )?
            .0)
    }

    /// The memoized inner traversal for [`Self::size_in_bits_internal`], returning `(size, height)`.
    ///
    /// `height` is the number of levels below this type at which its deepest node sits, and lets a memoized hit at
    /// a deeper position re-apply the depth check the skipped subtree would have performed.
    #[allow(clippy::too_many_arguments)]
    fn size_in_bits_inner<F0, F1, F2>(
        &self,
        get_struct: &F0,
        get_external_struct: &F1,
        get_future: &F2,
        depth: usize,
        memoized_futures: &mut HashMap<Locator<N>, (usize, usize)>,
        memoized_structs: &mut HashMap<PlaintextType<N>, (usize, usize)>,
    ) -> Result<(usize, usize)>
    where
        F0: Fn(&Identifier<N>) -> Result<StructType<N>>,
        F1: Fn(&Locator<N>) -> Result<StructType<N>>,
        F2: Fn(&Locator<N>) -> Result<Vec<FinalizeType<N>>>,
    {
        // Ensure that the depth is within the maximum limit.
        ensure!(depth <= N::MAX_DATA_DEPTH, "Finalize type depth exceeds maximum limit: {}", N::MAX_DATA_DEPTH);

        match self {
            Self::Plaintext(plaintext_type) => {
                plaintext_type.size_in_bits_internal(get_struct, get_external_struct, depth, memoized_structs)
            }
            Self::Future(locator) => {
                // If this future has already been sized in the current traversal, reuse that result, re-checking
                // the depth limit against its height as the skipped recursion would have on its deepest node.
                if let Some(&(size, height)) = memoized_futures.get(locator) {
                    ensure!(
                        depth.saturating_add(height) <= N::MAX_DATA_DEPTH,
                        "Finalize type depth exceeds maximum limit: {}",
                        N::MAX_DATA_DEPTH
                    );
                    return Ok((size, height));
                }

                // Initialize the size in bits.
                let mut size = 0usize;

                // Account for the length of the program ID bits.
                size = size.checked_add(16).ok_or(anyhow!("`size_in_bits` overflowed"))?;

                // Account for the bits of the program ID.
                size = size
                    .checked_add(locator.name().size_in_bits() as usize)
                    .ok_or(anyhow!("`size_in_bits` overflowed"))?;
                size = size
                    .checked_add(locator.network().size_in_bits() as usize)
                    .ok_or(anyhow!("`size_in_bits` overflowed"))?;

                // Account for the length of the function name bits.
                size = size.checked_add(16).ok_or(anyhow!("`size_in_bits` overflowed"))?;

                // Account for the bits of the function name.
                size = size
                    .checked_add(locator.resource().size_in_bits() as usize)
                    .ok_or(anyhow!("`size_in_bits` overflowed"))?;

                // Look up the argument types of the future.
                let arguments = get_future(locator)?;

                // Account for the number of arguments.
                size = size.checked_add(8).ok_or(anyhow!("`size_in_bits` overflowed"))?;

                // Track the maximum height of any argument's subtree.
                let mut argument_height = 0usize;

                // Account for each of the arguments.
                for argument in &arguments {
                    // Account for the argument variant bit.
                    size = size.checked_add(1).ok_or(anyhow!("`size_in_bits` overflowed"))?;

                    // Calculate argument bits size.
                    let (argument_size_in_bits, subtree_height) = argument.size_in_bits_inner(
                        get_struct,
                        get_external_struct,
                        get_future,
                        depth + 1,
                        memoized_futures,
                        memoized_structs,
                    )?;
                    argument_height = argument_height.max(subtree_height);

                    // Account for the size of the argument bits
                    match argument_size_in_bits <= u16::MAX as usize {
                        true => {
                            // Account for the size of the argument bits (u16).
                            size = size.checked_add(16).ok_or(anyhow!("`size_in_bits` overflowed"))?;
                        }
                        false => {
                            // Account for the size of the argument bits (u32).
                            size = size.checked_add(32).ok_or(anyhow!("`size_in_bits` overflowed"))?;
                        }
                    }

                    // Account for the argument bits.
                    size = size.checked_add(argument_size_in_bits).ok_or(anyhow!("`size_in_bits` overflowed"))?;
                }

                // The future sits one level above its deepest argument; an argumentless future recurses nowhere.
                let height = match arguments.is_empty() {
                    true => 0,
                    false => argument_height + 1,
                };
                memoized_futures.insert(*locator, (size, height));
                Ok((size, height))
            }
            Self::DynamicFuture => Ok((DynamicFuture::<N>::size_in_bits()?, 0)),
        }
    }

    /// Returns the number of raw bits of a finalize type.
    pub fn future_size_in_bits_raw<F0, F1, F2>(
        locator: &Locator<N>,
        get_struct: &F0,
        get_external_struct: &F1,
        get_future: &F2,
    ) -> Result<usize>
    where
        F0: Fn(&Identifier<N>) -> Result<StructType<N>>,
        F1: Fn(&Locator<N>) -> Result<StructType<N>>,
        F2: Fn(&Locator<N>) -> Result<Vec<FinalizeType<N>>>,
    {
        Self::future_size_in_bits(locator, get_struct, get_external_struct, get_future)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{LiteralType, PlaintextType};
    use snarkvm_console_network::MainnetV0;

    use std::{sync::mpsc, thread, time::Duration};

    type CurrentNetwork = MainnetV0;

    /// Builds a chain of `depth` finalize scopes in which every scope takes `MAX_INPUTS` futures of the scope
    /// below it, and the bottom scope takes a single `field`. Sizing the top future therefore walks an acyclic
    /// graph with `MAX_INPUTS ^ (depth - 1)` distinct root-to-leaf paths, even though only `depth` distinct
    /// futures exist — the same shape as the shared-struct DoS, one level up.
    ///
    /// Returns the top locator and the `get_future` lookup table.
    #[allow(clippy::type_complexity)]
    fn sample_future_chain(
        depth: usize,
    ) -> (Locator<CurrentNetwork>, HashMap<Locator<CurrentNetwork>, Vec<FinalizeType<CurrentNetwork>>>) {
        assert!(depth >= 1);
        let locator = |level: usize| Locator::<CurrentNetwork>::from_str(&format!("f{level}.aleo/g")).unwrap();

        let mut futures = HashMap::new();
        futures.insert(locator(0), vec![FinalizeType::Plaintext(PlaintextType::Literal(LiteralType::Field))]);
        for level in 1..depth {
            futures.insert(locator(level), vec![FinalizeType::Future(locator(level - 1)); CurrentNetwork::MAX_INPUTS]);
        }

        (locator(depth - 1), futures)
    }

    #[test]
    fn test_future_size_in_bits_shared_future_dag_terminates() {
        // Without caching, sizing this future expands 16^11 argument nodes and never returns; with caching each
        // of the 12 distinct futures is expanded once.
        let (top, futures) = sample_future_chain(12);

        let (sender, receiver) = mpsc::channel();
        thread::spawn(move || {
            let get_struct = |_: &Identifier<CurrentNetwork>| bail!("this program declares no structs");
            let get_external_struct = |_: &Locator<CurrentNetwork>| bail!("this program declares no external structs");
            let get_future = |locator: &Locator<CurrentNetwork>| {
                futures.get(locator).cloned().ok_or_else(|| anyhow!("Failed to find future '{locator}'"))
            };
            let _ =
                sender.send(FinalizeType::future_size_in_bits(&top, &get_struct, &get_external_struct, &get_future));
        });

        // 5 minutes is generous even if the CI machine is heavily loaded.
        match receiver.recv_timeout(Duration::from_secs(300)) {
            Ok(Ok(size)) => assert!(size > 0),
            Ok(Err(error)) => panic!("Failed to size a chain of shared futures: {error}"),
            Err(_) => panic!(
                "future_size_in_bits did not terminate within 300s: the future argument tree is being expanded \
                 exponentially (memoization is missing)"
            ),
        }
    }
}
