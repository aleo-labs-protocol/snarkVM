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

use nom::{
    Err as NomErr,
    IResult,
    error::{VerboseError, convert_error},
};

/// The `nom`-compatible parser return type.
pub type ParserResult<'a, O> = IResult<&'a str, O, VerboseError<&'a str>>;

/// Converts a `ParserResult` into a human-readable message.
pub fn convert_result<'a, O>(result: ParserResult<'a, O>, input: &'a str) -> String {
    match result {
        Ok(_) => "Parsing was successful.".to_string(),
        Err(error) => match error {
            NomErr::Incomplete(_) => "Parsing failed to consume the entire input.".to_string(),
            NomErr::Error(err) | NomErr::Failure(err) => convert_error(input, err),
        },
    }
}

/// Operations to parse a string literal into an object.
pub trait Parser: core::fmt::Display + core::str::FromStr {
    /// Parses a string literal into an object.
    fn parse(string: &str) -> ParserResult<'_, Self>
    where
        Self: Sized;
}
