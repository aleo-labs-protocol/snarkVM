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

#[derive(Debug, Error)]
pub enum GroupError {
    #[error("{}: {}", _0, _1)]
    Crate(&'static str, String),

    #[error("field error")]
    FieldError(#[from] snarkvm_fields::FieldError),

    #[error("Invalid group element")]
    InvalidGroupElement,

    #[error("Attempting to parse an invalid string into a group element")]
    InvalidString,

    #[error("{}", _0)]
    Message(String),

    #[error("Attempting to parse an empty string into a group element")]
    ParsingEmptyString,

    #[error("Attempting to parse a non-digit character into a group element")]
    ParsingNonDigitCharacter,
}

impl From<std::io::Error> for GroupError {
    fn from(error: std::io::Error) -> Self {
        GroupError::Crate("std::io", format!("{error:?}"))
    }
}

impl From<GroupError> for std::io::Error {
    fn from(error: GroupError) -> Self {
        std::io::Error::other(format!("{error}"))
    }
}
