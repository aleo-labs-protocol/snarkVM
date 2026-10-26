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

use crate::QueryTrait;

use snarkvm_console::{
    network::prelude::*,
    program::{ProgramID, StatePath},
    types::Field,
};
use snarkvm_ledger_block::Transaction;
use snarkvm_ledger_store::{BlockStorage, BlockStore};
use snarkvm_synthesizer_program::Program;

use anyhow::{Context, Result};
// ureq re-exports the `http` crate.
use ureq::http;

mod static_;
pub use static_::StaticQuery;

mod rest;
pub use rest::RestQuery;

/// Make the REST error type available public as it can be used for any API endpoint.
pub use rest::RestError;

/// Allows inspecting the state of the blockstain using either local state or a remote endpoint.
#[derive(Clone)]
pub enum Query<N: Network, B: BlockStorage<N>> {
    /// Query state in a local block store.
    VM(BlockStore<N, B>),
    /// Query state using a node's REST API.
    REST(RestQuery<N>),
    // Return static state for testing and performance.
    STATIC(StaticQuery<N>),
}

/// Initialize the `Query` object from a local `BlockStore`.
impl<N: Network, B: BlockStorage<N>> From<BlockStore<N, B>> for Query<N, B> {
    fn from(block_store: BlockStore<N, B>) -> Self {
        Self::VM(block_store)
    }
}

/// Initialize the `Query` object from a local `BlockStore`.
impl<N: Network, B: BlockStorage<N>> From<&BlockStore<N, B>> for Query<N, B> {
    fn from(block_store: &BlockStore<N, B>) -> Self {
        Self::VM(block_store.clone())
    }
}

/// Initialize the `Query` object from an endpoint URL. The URI should point to a snarkOS node's REST API.
impl<N: Network, B: BlockStorage<N>> From<http::Uri> for Query<N, B> {
    fn from(uri: http::Uri) -> Self {
        Self::REST(RestQuery::from(uri))
    }
}

/// Initialize the `Query` object from an endpoint URL (passed as a string). The URI should point to a snarkOS node's REST API.
impl<N: Network, B: BlockStorage<N>> TryFrom<String> for Query<N, B> {
    type Error = anyhow::Error;

    fn try_from(string_representation: String) -> Result<Self> {
        Self::try_from(string_representation.as_str())
    }
}

/// Initialize the `Query` object from an endpoint URL (passed as a string). The URI should point to a snarkOS node's REST API.
impl<N: Network, B: BlockStorage<N>> TryFrom<&String> for Query<N, B> {
    type Error = anyhow::Error;

    fn try_from(string_representation: &String) -> Result<Self> {
        Self::try_from(string_representation.as_str())
    }
}

/// Initialize the `Query` object from an endpoint URL (passed as a string). The URI should point to a snarkOS node's REST API.
impl<N: Network, B: BlockStorage<N>> TryFrom<&str> for Query<N, B> {
    type Error = anyhow::Error;

    fn try_from(str_representation: &str) -> Result<Self> {
        str_representation.parse::<Self>()
    }
}

/// Initialize the `Query` object from an endpoint URL (passed as a string). The URI should point to a snarkOS node's REST API.
impl<N: Network, B: BlockStorage<N>> FromStr for Query<N, B> {
    type Err = anyhow::Error;

    fn from_str(str_representation: &str) -> Result<Self> {
        // A static query is represented as JSON and a valid URI does not start with `}`.
        if str_representation.trim().starts_with('{') {
            let static_query =
                str_representation.parse::<StaticQuery<N>>().with_context(|| "Failed to parse static query")?;
            Ok(Self::STATIC(static_query))
        } else {
            let rest_query = RestQuery::from_str(str_representation).with_context(|| "Failed to parse query")?;
            Ok(Self::REST(rest_query))
        }
    }
}

#[cfg_attr(feature = "async", async_trait::async_trait(?Send))]
impl<N: Network, B: BlockStorage<N>> QueryTrait<N> for Query<N, B> {
    /// Returns the current state root.
    fn current_state_root(&self) -> Result<N::StateRoot> {
        match self {
            Self::VM(block_store) => Ok(block_store.current_state_root()),
            Self::REST(query) => query.current_state_root(),
            Self::STATIC(query) => query.current_state_root(),
        }
    }

    /// Returns the current state root.
    #[cfg(feature = "async")]
    async fn current_state_root_async(&self) -> Result<N::StateRoot> {
        match self {
            Self::VM(block_store) => Ok(block_store.current_state_root()),
            Self::REST(query) => query.current_state_root_async().await,
            Self::STATIC(query) => query.current_state_root_async().await,
        }
    }

    /// Returns a state path for the given `commitment`.
    fn get_state_path_for_commitment(&self, commitment: &Field<N>) -> Result<StatePath<N>> {
        match self {
            Self::VM(block_store) => block_store.get_state_path_for_commitment(commitment),
            Self::REST(query) => query.get_state_path_for_commitment(commitment),
            Self::STATIC(query) => query.get_state_path_for_commitment(commitment),
        }
    }

    /// Returns a state path for the given `commitment`.
    #[cfg(feature = "async")]
    async fn get_state_path_for_commitment_async(&self, commitment: &Field<N>) -> Result<StatePath<N>> {
        match self {
            Self::VM(block_store) => block_store.get_state_path_for_commitment(commitment),
            Self::REST(query) => query.get_state_path_for_commitment_async(commitment).await,
            Self::STATIC(query) => query.get_state_path_for_commitment_async(commitment).await,
        }
    }

    /// Returns a list of state paths for the given list of `commitment`s.
    fn get_state_paths_for_commitments(&self, commitments: &[Field<N>]) -> Result<Vec<StatePath<N>>> {
        // Return an empty vector if there are no commitments.
        if commitments.is_empty() {
            return Ok(vec![]);
        }

        match self {
            Self::VM(block_store) => block_store.get_state_paths_for_commitments(commitments),
            Self::REST(query) => query.get_state_paths_for_commitments(commitments),
            Self::STATIC(query) => query.get_state_paths_for_commitments(commitments),
        }
    }

    /// Returns a list of state paths for the given list of `commitment`s.
    #[cfg(feature = "async")]
    async fn get_state_paths_for_commitments_async(&self, commitments: &[Field<N>]) -> Result<Vec<StatePath<N>>> {
        // Return an empty vector if there are no commitments.
        if commitments.is_empty() {
            return Ok(vec![]);
        }

        match self {
            Self::VM(block_store) => block_store.get_state_paths_for_commitments(commitments),
            Self::REST(query) => query.get_state_paths_for_commitments_async(commitments).await,
            Self::STATIC(query) => query.get_state_paths_for_commitments(commitments),
        }
    }

    /// Returns a state path for the given `commitment`.
    fn current_block_height(&self) -> Result<u32> {
        match self {
            Self::VM(block_store) => Ok(block_store.max_height().unwrap_or_default()),
            Self::REST(query) => query.current_block_height(),
            Self::STATIC(query) => query.current_block_height(),
        }
    }

    /// Returns a state path for the given `commitment`.
    #[cfg(feature = "async")]
    async fn current_block_height_async(&self) -> Result<u32> {
        match self {
            Self::VM(block_store) => Ok(block_store.max_height().unwrap_or_default()),
            Self::REST(query) => query.current_block_height_async().await,
            Self::STATIC(query) => query.current_block_height_async().await,
        }
    }
}

impl<N: Network, B: BlockStorage<N>> Query<N, B> {
    /// Returns the transaction for the given transaction ID.
    pub fn get_transaction(&self, transaction_id: &N::TransactionID) -> Result<Transaction<N>> {
        match self {
            Self::VM(block_store) => block_store
                .get_transaction(transaction_id)?
                .ok_or_else(|| anyhow!("Missing transaction '{transaction_id}' in block storage")),
            Self::REST(query) => query.get_transaction(transaction_id),
            Self::STATIC(_query) => bail!("get_transaction is not supported by StaticQuery"),
        }
    }

    /// Returns the transaction for the given transaction ID.
    #[cfg(feature = "async")]
    pub async fn get_transaction_async(&self, transaction_id: &N::TransactionID) -> Result<Transaction<N>> {
        match self {
            Self::VM(block_store) => block_store
                .get_transaction(transaction_id)?
                .ok_or_else(|| anyhow!("Missing transaction '{transaction_id}' in block storage")),
            Self::REST(query) => query.get_transaction_async(transaction_id).await,
            Self::STATIC(_query) => bail!("get_transaction is not supported by StaticQuery"),
        }
    }

    /// Returns the program for the given program ID.
    pub fn get_program(&self, program_id: &ProgramID<N>) -> Result<Program<N>> {
        match self {
            Self::VM(block_store) => block_store
                .get_latest_program(program_id)?
                .ok_or_else(|| anyhow!("Program {program_id} not found in storage")),
            Self::REST(query) => query.get_program(program_id),
            Self::STATIC(_query) => bail!("get_program is not supported by StaticQuery"),
        }
    }

    /// Returns the program for the given program ID.
    #[cfg(feature = "async")]
    pub async fn get_program_async(&self, program_id: &ProgramID<N>) -> Result<Program<N>> {
        match self {
            Self::VM(block_store) => block_store
                .get_latest_program(program_id)?
                .with_context(|| format!("Program {program_id} not found in storage")),
            Self::REST(query) => query.get_program_async(program_id).await,
            Self::STATIC(_query) => bail!("get_program_async is not supported by StaticQuery"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use snarkvm_console::network::TestnetV0;
    use snarkvm_ledger_store::helpers::memory::BlockMemory;

    type CurrentNetwork = TestnetV0;
    type CurrentQuery = Query<CurrentNetwork, BlockMemory<CurrentNetwork>>;

    #[test]
    fn test_static_query_parse() {
        let json = r#"{"state_root": "sr1dz06ur5spdgzkguh4pr42mvft6u3nwsg5drh9rdja9v8jpcz3czsls9geg", "height": 14}"#
            .to_string();
        let query = CurrentQuery::try_from(json).unwrap();

        assert!(matches!(query, Query::STATIC(_)));
    }

    #[test]
    fn test_static_query_parse_invalid() {
        let json = r#"{"invalid_key": "sr1dz06ur5spdgzkguh4pr42mvft6u3nwsg5drh9rdja9v8jpcz3czsls9geg", "height": 14}"#
            .to_string();
        let result = json.parse::<CurrentQuery>();

        assert!(result.is_err());
    }

    #[test]
    fn test_rest_url_parse_invalid_scheme() {
        let str = "ftp://localhost:3030";
        let result = CurrentQuery::try_from(str);

        assert!(result.is_err());
    }

    #[test]
    fn test_rest_url_parse_invalid_host() {
        let str = "http://:3030";
        let result = CurrentQuery::try_from(str);

        assert!(result.is_err());
    }
}
