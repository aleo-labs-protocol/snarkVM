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

use serde::{Deserialize, Serialize};

use aleo_std::{StorageMode, aleo_ledger_dir};

use anyhow::Result;
use std::{
    fmt::{Display, Formatter},
    path::PathBuf,
    str::FromStr,
};

/// Returns the path where a `history` directory may be stored.
///
/// Production and custom ledgers keep `history-{network}` beside the ledger directory. A
/// development ledger keeps `.{history}-{network}-{id}` beside its ledger directory. Test storage
/// keeps the files inside the ephemeral ledger directory.
pub fn history_directory_path(network: u16, storage_mode: &StorageMode) -> PathBuf {
    const HISTORY_DIRECTORY_NAME: &str = "history";

    let mut path = aleo_ledger_dir(network, storage_mode);
    match storage_mode {
        // Test files live in the ephemeral ledger directory, which is removed with the test.
        StorageMode::Test(_) => path.push(HISTORY_DIRECTORY_NAME),
        StorageMode::Development(id) => {
            path.pop();
            path.push(format!(".{HISTORY_DIRECTORY_NAME}-{network}-{id}"));
        }
        StorageMode::Production | StorageMode::Custom(..) => {
            path.pop();
            path.push(format!("{HISTORY_DIRECTORY_NAME}-{network}"));
        }
    }
    path
}

#[derive(Copy, Clone, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum MappingName {
    /// The `bonded` mapping.
    Bonded,
    /// The `delegated` mapping.
    Delegated,
    /// The `metadata` mapping.
    Metadata,
    /// The `unbonding` mapping.
    Unbonding,
    /// The `withdraw` mapping.
    Withdraw,
    /// The `stakingrewards` mapping.
    StakingRewards,
}

impl FromStr for MappingName {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self> {
        match s {
            "bonded" => Ok(Self::Bonded),
            "delegated" => Ok(Self::Delegated),
            "metadata" => Ok(Self::Metadata),
            "unbonding" => Ok(Self::Unbonding),
            "withdraw" => Ok(Self::Withdraw),
            "stakingrewards" => Ok(Self::StakingRewards),
            _ => anyhow::bail!("Invalid mapping name '{s}'"),
        }
    }
}

impl Display for MappingName {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Bonded => write!(f, "bonded"),
            Self::Delegated => write!(f, "delegated"),
            Self::Metadata => write!(f, "metadata"),
            Self::Unbonding => write!(f, "unbonding"),
            Self::Withdraw => write!(f, "withdraw"),
            Self::StakingRewards => write!(f, "stakingrewards"),
        }
    }
}

pub struct History {
    /// The path to the history directory.
    path: PathBuf,
}

impl History {
    /// Initializes a new instance of `History`.
    pub fn new(network: u16, storage_mode: &StorageMode) -> Self {
        Self { path: history_directory_path(network, storage_mode) }
    }

    /// Stores a mapping from a given block in the history directory as JSON.
    pub fn store_mapping<T>(&self, height: u32, mapping: MappingName, data: &T) -> Result<()>
    where
        T: Serialize + ?Sized,
    {
        // Get the path to the block directory.
        let path = self.block_path(height);
        // Create the block directory if it does not exist.
        if !path.exists() {
            std::fs::create_dir_all(&path)?;
        }

        // Write the entry to the block directory.
        let path = path.join(format!("block-{height}-{mapping}.json"));
        std::fs::write(path, serde_json::to_string_pretty(data)?)?;

        Ok(())
    }

    /// Loads the JSON string for a mapping from a given block from the history directory.
    pub fn load_mapping(&self, height: u32, mapping: MappingName) -> Result<String> {
        // Get the path to the block directory.
        let path = self.block_path(height);
        // Get the path to the block file.
        let path = path.join(format!("block-{height}-{mapping}.json"));

        // Read the file.
        let data = std::fs::read_to_string(path)?;

        Ok(data)
    }

    // A helper function to get the path to the block directory.
    fn block_path(&self, height: u32) -> PathBuf {
        // Get the path the directory group.
        let group = Self::group(height);
        let path = self.path.join(format!("group-{group}"));
        // Get the path to the block directory.
        path.join(format!("block-{height}"))
    }

    // A helper function to calculate the group number for a given block height.
    fn group(height: u32) -> u32 {
        height.saturating_div(u16::MAX as u32)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_history_json_roundtrip() {
        let storage = StorageMode::new_test(None);
        let history = History::new(0, &storage);
        let height = u16::MAX as u32;
        history.store_mapping(height, MappingName::Bonded, &vec!["aleo1".to_string()]).unwrap();

        let loaded = history.load_mapping(height, MappingName::Bonded).unwrap();
        assert_eq!(loaded, serde_json::to_string_pretty(&vec!["aleo1".to_string()]).unwrap());
        assert!(history.block_path(height).starts_with(history.path.join("group-1")));
        assert!(history.load_mapping(height, MappingName::Delegated).is_err());

        history.store_mapping(height, MappingName::StakingRewards, &vec!["reward".to_string()]).unwrap();
        let rewards_file = format!("block-{height}-stakingrewards.json");
        let rewards_path = history.block_path(height).join(&rewards_file);
        assert_eq!(
            std::fs::read_to_string(&rewards_path).unwrap(),
            history.load_mapping(height, MappingName::StakingRewards).unwrap()
        );
        assert_eq!(MappingName::StakingRewards.to_string(), "stakingrewards");
        assert!(matches!("stakingrewards".parse::<MappingName>(), Ok(MappingName::StakingRewards)));
    }
}
