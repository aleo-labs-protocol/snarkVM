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

impl<E: Environment> Group<E> {
    /// Attempts to recover an affine group element from a given x-coordinate field element.
    /// For safety, the resulting point is always enforced to be on the curve and in the correct subgroup.
    pub fn from_x_coordinate(x_coordinate: Field<E>) -> Result<Self> {
        if let Some((p1, p2)) = E::Affine::pair_from_x_coordinate(*x_coordinate) {
            for point in [p2, p1] {
                if point.is_in_correct_subgroup_assuming_on_curve() {
                    return Ok(Self::new(point));
                }
            }
        }
        bail!("Failed to recover an affine group from an x-coordinate of {x_coordinate}")
    }
}
