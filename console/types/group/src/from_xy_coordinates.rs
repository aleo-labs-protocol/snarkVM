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
    /// Initializes a new group from the `(x, y)` affine coordinates.
    pub fn from_xy_coordinates(x: Field<E>, y: Field<E>) -> Self {
        match E::Affine::from_coordinates((*x, *y)) {
            Some(point) => Self { group: point.into() },
            None => E::halt("Attempted to recover an invalid group element from (x, y) coordinates"),
        }
    }

    /// Initializes a new group from the `(x, y)` affine coordinates.
    /// Note: This skips the curve and subgroup checks, so the resulting point may be off the curve or
    /// outside the subgroup. Prefer `from_xy_coordinates` or `Group::try_new`.
    ///
    /// This stays public only because `circuit::Group::eject_value` needs it. We expect to deprecate it
    /// once that changes (see <https://github.com/aleo-labs-protocol/snarkVM/issues/3685>).
    pub fn from_xy_coordinates_unchecked(x: Field<E>, y: Field<E>) -> Self {
        Self { group: E::Affine::from_coordinates_unchecked((*x, *y)).into() }
    }
}
