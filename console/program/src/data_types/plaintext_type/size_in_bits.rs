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

use std::collections::HashMap;

/// Returns a memoized `(size, height)` for a struct reached at `depth`, after re-checking the depth limit against
/// its height. This is the check the skipped recursion would have performed on the subtree's deepest node, so a
/// memoized hit rejects exactly the deeply-nested cases the full recursion would.
fn memoized_size<N: Network>(depth: usize, (size, height): (usize, usize)) -> Result<(usize, usize)> {
    ensure!(
        depth.saturating_add(height) <= N::MAX_DATA_DEPTH,
        "Plaintext depth exceeds maximum limit: {}",
        N::MAX_DATA_DEPTH
    );
    Ok((size, height))
}

impl<N: Network> PlaintextType<N> {
    /// Returns the number of bits of a plaintext type.
    pub fn size_in_bits<F0, F1>(&self, get_struct: &F0, get_external_struct: &F1) -> Result<usize>
    where
        F0: Fn(&Identifier<N>) -> Result<StructType<N>>,
        F1: Fn(&Locator<N>) -> Result<StructType<N>>,
    {
        // Track the `(size, height)` of the struct types that have already been sized, so that a struct shared by
        // many members is expanded at most once. Without this, a program in which every member of each struct
        // refers to the same earlier struct forms an acyclic graph with exponentially many paths, and the walk
        // below would make up to `MAX_STRUCT_ENTRIES ^ MAX_STRUCTS` recursive calls.
        let mut memoized = HashMap::new();
        Ok(self.size_in_bits_internal(get_struct, get_external_struct, 0, &mut memoized)?.0)
    }

    /// A helper function to determine the `(size, height)` of a plaintext type, while tracking the depth of the data.
    ///
    /// `memoized` is keyed on the struct type itself rather than its name, since an external struct resolves
    /// through a different lookup whose struct names may collide with the current program's. It holds
    /// `(size, height)`, where `height` is the number of levels below a type at which its deepest node sits (a
    /// literal is `0`); see [`memoized_size`] for why the height is tracked.
    pub(crate) fn size_in_bits_internal<F0, F1>(
        &self,
        get_struct: &F0,
        get_external_struct: &F1,
        depth: usize,
        memoized: &mut HashMap<PlaintextType<N>, (usize, usize)>,
    ) -> Result<(usize, usize)>
    where
        F0: Fn(&Identifier<N>) -> Result<StructType<N>>,
        F1: Fn(&Locator<N>) -> Result<StructType<N>>,
    {
        // Ensure that the depth is within the maximum limit.
        ensure!(depth <= N::MAX_DATA_DEPTH, "Plaintext depth exceeds maximum limit: {}", N::MAX_DATA_DEPTH);

        // Computes the `(size, height)` in bits of a resolved struct definition.
        let compute_struct_size = |struct_: &StructType<N>,
                                   memoized: &mut HashMap<PlaintextType<N>, (usize, usize)>|
         -> Result<(usize, usize)> {
            // Account for the plaintext variant bits.
            let mut total = PlaintextType::<N>::STRUCT_PREFIX_BITS.len();
            // Account for the number of members in the struct.
            total = total.checked_add(8).ok_or(anyhow!("`size_in_bits` overflowed"))?;
            // Track the maximum height of any member's subtree.
            let mut member_height = 0usize;
            // Add up the sizes of each member.
            for (identifier, member_type) in struct_.members() {
                // Account for the size of the identifier.
                total = total.checked_add(8).ok_or(anyhow!("`size_in_bits` overflowed"))?;
                // Account for the identifier.
                total = total
                    .checked_add(identifier.size_in_bits() as usize)
                    .ok_or(anyhow!("`size_in_bits` overflowed"))?;
                // Account for the size of the member.
                total = total.checked_add(16).ok_or(anyhow!("`size_in_bits` overflowed"))?;
                // Account for the member itself.
                let (member_size, subtree_height) =
                    member_type.size_in_bits_internal(get_struct, get_external_struct, depth + 1, memoized)?;
                total = total.checked_add(member_size).ok_or(anyhow!("`size_in_bits` overflowed"))?;
                member_height = member_height.max(subtree_height);
            }

            // The struct sits one level above its deepest member; a memberless struct recurses nowhere.
            let height = match struct_.members().is_empty() {
                true => 0,
                false => member_height + 1,
            };
            Ok((total, height))
        };

        match &self {
            PlaintextType::Literal(literal) => {
                // Account for the plaintext variant bits.
                let mut total = PlaintextType::<N>::LITERAL_PREFIX_BITS.len();
                // Account for the literal variant bits.
                total = total.checked_add(8).ok_or(anyhow!("`size_in_bits` overflowed"))?;
                // Account for the size of the literal in bits.
                total = total.checked_add(16).ok_or(anyhow!("`size_in_bits` overflowed"))?;
                // Account for the literal.

                total = total
                    .checked_add(literal.size_in_bits::<N>() as usize)
                    .ok_or(anyhow!("`size_in_bits` overflowed"))?;

                Ok((total, 0))
            }
            PlaintextType::Struct(identifier) => {
                // If this struct has already been sized in the current traversal, reuse that result.
                if let Some(&result) = memoized.get(self) {
                    return memoized_size::<N>(depth, result);
                }
                // Look up the struct.
                let struct_ = get_struct(identifier)?;
                let result = compute_struct_size(&struct_, memoized)?;
                memoized.insert(self.clone(), result);
                Ok(result)
            }
            PlaintextType::ExternalStruct(locator) => {
                // If this struct has already been sized in the current traversal, reuse that result.
                if let Some(&result) = memoized.get(self) {
                    return memoized_size::<N>(depth, result);
                }
                // Look up the struct
                let struct_ = get_external_struct(locator)?;
                let result = compute_struct_size(&struct_, memoized)?;
                memoized.insert(self.clone(), result);
                Ok(result)
            }
            PlaintextType::Array(array_type) => {
                // Account for the plaintext variant bits.
                let mut total = PlaintextType::<N>::ARRAY_PREFIX_BITS.len();
                // Account for the size of the array length.
                total = total.checked_add(32).ok_or(anyhow!("`size_in_bits` overflowed"))?;
                // Get the size of the element type.
                let (element_size, element_height) = array_type.next_element_type().size_in_bits_internal(
                    get_struct,
                    get_external_struct,
                    depth + 1,
                    memoized,
                )?;
                // Get the total size of an element.
                let element_total = 16usize.checked_add(element_size).ok_or(anyhow!("`size_in_bits` overflowed"))?;
                // Multiply by the length of the array, ensuring no overflow occurs.
                total = total
                    .checked_add(
                        element_total
                            .checked_mul(**array_type.length() as usize)
                            .ok_or(anyhow!("`size_in_bits` overflowed"))?,
                    )
                    .ok_or(anyhow!("`size_in_bits` overflowed"))?;

                // The array sits one level above its element.
                Ok((total, element_height + 1))
            }
        }
    }

    /// Returns the number of raw bits of a plaintext type.
    pub fn size_in_bits_raw<F0, F1>(&self, get_struct: &F0, get_external_struct: &F1) -> Result<usize>
    where
        F0: Fn(&Identifier<N>) -> Result<StructType<N>>,
        F1: Fn(&Locator<N>) -> Result<StructType<N>>,
    {
        // See `size_in_bits` for why the traversal is memoized; the two size definitions differ, so they must not
        // share a map.
        let mut memoized = HashMap::new();
        Ok(self.size_in_bits_raw_internal(get_struct, get_external_struct, 0, &mut memoized)?.0)
    }

    // A helper function to determine the `(size, height)` of raw bits of a plaintext type, while tracking the depth.
    // See `size_in_bits_internal` for how `memoized` is keyed.
    fn size_in_bits_raw_internal<F0, F1>(
        &self,
        get_struct: &F0,
        get_external_struct: &F1,
        depth: usize,
        memoized: &mut HashMap<PlaintextType<N>, (usize, usize)>,
    ) -> Result<(usize, usize)>
    where
        F0: Fn(&Identifier<N>) -> Result<StructType<N>>,
        F1: Fn(&Locator<N>) -> Result<StructType<N>>,
    {
        // Ensure that the depth is within the maximum limit.
        ensure!(depth <= N::MAX_DATA_DEPTH, "Plaintext depth exceeds maximum limit: {}", N::MAX_DATA_DEPTH);

        // Computes the raw `(size, height)` in bits of a resolved struct definition.
        let compute_struct_size_raw = |struct_: &StructType<N>,
                                       memoized: &mut HashMap<PlaintextType<N>, (usize, usize)>|
         -> Result<(usize, usize)> {
            // Add up the sizes of each member.
            let mut total = 0usize;
            // Track the maximum height of any member's subtree.
            let mut member_height = 0usize;

            for member_type in struct_.members().values() {
                // Get the size of the member.
                let (member_size, subtree_height) =
                    member_type.size_in_bits_raw_internal(get_struct, get_external_struct, depth + 1, memoized)?;

                // Add to the total size, ensuring no overflow occurs.
                total = total.checked_add(member_size).ok_or(anyhow!("`size_in_bits_raw` overflowed"))?;
                member_height = member_height.max(subtree_height);
            }

            // The struct sits one level above its deepest member; a memberless struct recurses nowhere.
            let height = match struct_.members().is_empty() {
                true => 0,
                false => member_height + 1,
            };
            Ok((total, height))
        };

        match &self {
            PlaintextType::Literal(literal) => Ok((literal.size_in_bits::<N>() as usize, 0)),
            PlaintextType::Struct(identifier) => {
                // If this struct has already been sized in the current traversal, reuse that result.
                if let Some(&result) = memoized.get(self) {
                    return memoized_size::<N>(depth, result);
                }
                // Look up the struct.
                let struct_ = get_struct(identifier)?;
                let result = compute_struct_size_raw(&struct_, memoized)?;
                memoized.insert(self.clone(), result);
                Ok(result)
            }
            PlaintextType::ExternalStruct(locator) => {
                // If this struct has already been sized in the current traversal, reuse that result.
                if let Some(&result) = memoized.get(self) {
                    return memoized_size::<N>(depth, result);
                }
                // Look up the struct.
                let struct_ = get_external_struct(locator)?;
                let result = compute_struct_size_raw(&struct_, memoized)?;
                memoized.insert(self.clone(), result);
                Ok(result)
            }
            PlaintextType::Array(array_type) => {
                // Get the size of the element type.
                let (element_size, element_height) = array_type.next_element_type().size_in_bits_raw_internal(
                    get_struct,
                    get_external_struct,
                    depth + 1,
                    memoized,
                )?;
                // Multiply by the length of the array, ensuring no overflow occurs.
                let total = element_size
                    .checked_mul(**array_type.length() as usize)
                    .ok_or(anyhow!("`size_in_bits_raw` overflowed"))?;

                // The array sits one level above its element.
                Ok((total, element_height + 1))
            }
        }
    }
}
