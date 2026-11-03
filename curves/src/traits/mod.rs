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

pub mod group;
pub use group::*;

pub mod pairing_engine;
pub use pairing_engine::*;

#[cfg(test)]
pub mod tests_field;

#[cfg(test)]
pub mod tests_group;

#[cfg(test)]
mod tests_sqrt;

#[cfg(test)]
pub mod tests_projective;
