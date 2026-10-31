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

#[derive(Error, Debug)]
pub enum SerializationError {
    #[error(transparent)]
    AnyhowError(#[from] anyhow::Error),
    /// During serialization with bincode, we encountered a serialization issue
    #[error(transparent)]
    BincodeError(#[from] bincode::Error),
    /// During serialization we could not serialize to the right sized int
    #[error(transparent)]
    IntError(#[from] std::num::TryFromIntError),
    /// During serialization, the data was invalid.
    #[error("the input buffer contained invalid data")]
    InvalidData,
    /// During serialization, we countered an I/O error.
    #[error("I/O error")]
    IoError(#[from] std::io::Error),
    /// During serialization, we didn't have enough space to write extra info.
    #[error("the last byte does not have enough space to encode the extra info bits")]
    NotEnoughSpace,
    /// During serialization, non-empty flags were given where none were
    /// expected.
    #[error("the call expects empty flags")]
    UnexpectedFlags,
    /// During serialization, the target was found to be incompatible
    #[error("the value was serialized on a target that is incompatible with the current target")]
    IncompatibleTarget,
}

impl From<SerializationError> for std::io::Error {
    fn from(error: SerializationError) -> Self {
        std::io::Error::other(format!("{error}"))
    }
}
