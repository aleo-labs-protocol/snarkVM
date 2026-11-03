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

#![forbid(unsafe_code)]
#![allow(clippy::too_many_arguments)]
#![warn(clippy::cast_possible_truncation)]

pub use modules::*;

pub mod prelude {
    pub use crate::modules::*;
    pub use io_error as error;
    pub use snarkvm_console_network_environment::prelude::*;
}

pub mod modules {
    pub use snarkvm_console_network_environment as environment;

    #[cfg(feature = "address")]
    pub use snarkvm_console_types_address as address;
    #[cfg(feature = "address")]
    pub use snarkvm_console_types_address::Address;

    #[cfg(feature = "boolean")]
    pub use snarkvm_console_types_boolean as boolean;
    #[cfg(feature = "boolean")]
    pub use snarkvm_console_types_boolean::Boolean;

    #[cfg(feature = "field")]
    pub use snarkvm_console_types_field as field;
    #[cfg(feature = "field")]
    pub use snarkvm_console_types_field::Field;

    #[cfg(feature = "group")]
    pub use snarkvm_console_types_group as group;
    #[cfg(feature = "group")]
    pub use snarkvm_console_types_group::Group;

    #[cfg(feature = "integers")]
    pub use snarkvm_console_types_integers as integers;
    #[cfg(feature = "integers")]
    pub use snarkvm_console_types_integers::{I8, I16, I32, I64, I128, U8, U16, U32, U64, U128};

    #[cfg(feature = "scalar")]
    pub use snarkvm_console_types_scalar as scalar;
    #[cfg(feature = "scalar")]
    pub use snarkvm_console_types_scalar::Scalar;

    #[cfg(feature = "string")]
    pub use snarkvm_console_types_string as string;
    #[cfg(feature = "string")]
    pub use snarkvm_console_types_string::{IdentifierLiteral, StringType};
}
