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

impl<N: Network> Eq for Value<N> {}

impl<N: Network> PartialEq for Value<N> {
    /// Returns `true` if `self` and `other` are equal.
    fn eq(&self, other: &Self) -> bool {
        *self.is_equal(other)
    }
}

impl<N: Network> Equal<Self> for Value<N> {
    type Output = Boolean<N>;

    /// Returns `true` if `self` and `other` are equal.
    fn is_equal(&self, other: &Self) -> Self::Output {
        match (self, other) {
            (Self::Plaintext(a), Self::Plaintext(b)) => a.is_equal(b),
            (Self::Record(a), Self::Record(b)) => a.is_equal(b),
            (Self::Future(a), Self::Future(b)) => a.is_equal(b),
            (Self::DynamicRecord(a), Self::DynamicRecord(b)) => a.is_equal(b),
            (Self::DynamicFuture(a), Self::DynamicFuture(b)) => a.is_equal(b),
            (Self::Plaintext(..), _)
            | (Self::Record(..), _)
            | (Self::Future(..), _)
            | (Self::DynamicRecord(..), _)
            | (Self::DynamicFuture(..), _) => Boolean::new(false),
        }
    }

    /// Returns `true` if `self` and `other` are *not* equal.
    fn is_not_equal(&self, other: &Self) -> Self::Output {
        match (self, other) {
            (Self::Plaintext(a), Self::Plaintext(b)) => a.is_not_equal(b),
            (Self::Record(a), Self::Record(b)) => a.is_not_equal(b),
            (Self::Future(a), Self::Future(b)) => a.is_not_equal(b),
            (Self::DynamicRecord(a), Self::DynamicRecord(b)) => a.is_not_equal(b),
            (Self::DynamicFuture(a), Self::DynamicFuture(b)) => a.is_not_equal(b),
            (Self::Plaintext(..), _)
            | (Self::Record(..), _)
            | (Self::Future(..), _)
            | (Self::DynamicRecord(..), _)
            | (Self::DynamicFuture(..), _) => Boolean::new(true),
        }
    }
}
