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

use dirs::home_dir;
use std::{path::PathBuf, sync::Arc};
use tempfile::TempDir;

/// The directory name for Aleo-related resources.
const ALEO_DIRECTORY: &str = ".aleo";

/// An enum to define the operating mode of the Aleo node.
#[derive(Clone, Debug)]
pub enum StorageMode {
    /// The production mode is used for running a node on the Aleo mainnet.
    Production,
    /// The development mode is used for running a node on a local network.
    Development(u16),
    /// The custom mode is used for running a node on custom configurations.
    /// The second, optional path is used if the storage is to be opened in
    /// secondary mode.
    Custom(PathBuf, Option<PathBuf>),
    /// Test-only ephemeral storage which self-destructs afterwards.
    Test(Option<Arc<TempDir>>),
}

impl StorageMode {
    /// Returns the test mode backed by the given temporary directory, or by a new one if none is given.
    ///
    /// # Panics
    ///
    /// Panics if a new temporary directory cannot be created.
    pub fn new_test(tempdir: Option<Arc<TempDir>>) -> Self {
        if tempdir.is_some() {
            Self::Test(tempdir)
        } else {
            // This unwrap is a documented panic: test-only storage has no way to proceed without its directory.
            Self::Test(Some(Arc::new(TempDir::with_prefix("aleo_storage_").unwrap())))
        }
    }

    /// Returns the development ID if the mode is development.
    pub const fn dev(&self) -> Option<u16> {
        match self {
            Self::Development(id) => Some(*id),
            Self::Production | Self::Custom(..) | Self::Test(_) => None,
        }
    }
}

impl PartialEq for StorageMode {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (StorageMode::Production, StorageMode::Production) => true,
            (StorageMode::Development(id1), StorageMode::Development(id2)) => id1 == id2,
            (StorageMode::Custom(primary1, secondary1), StorageMode::Custom(primary2, secondary2)) => {
                primary1 == primary2 && secondary1 == secondary2
            }
            (StorageMode::Test(Some(temp1)), StorageMode::Test(Some(temp2))) => temp1.path() == temp2.path(),
            _ => false,
        }
    }
}

impl Eq for StorageMode {}

impl From<u16> for StorageMode {
    fn from(id: u16) -> Self {
        StorageMode::Development(id)
    }
}

impl From<PathBuf> for StorageMode {
    fn from(primary_path: PathBuf) -> Self {
        StorageMode::Custom(primary_path, None)
    }
}

impl From<(PathBuf, Option<PathBuf>)> for StorageMode {
    fn from((primary_path, secondary_path): (PathBuf, Option<PathBuf>)) -> Self {
        StorageMode::Custom(primary_path, secondary_path)
    }
}

impl From<Arc<TempDir>> for StorageMode {
    fn from(tempdir: Arc<TempDir>) -> Self {
        StorageMode::Test(Some(tempdir))
    }
}

///
/// Returns the directory for accessing resources from Aleo storage.
/// The expected directory path to be returned is `~/.aleo/`.
///
pub fn aleo_dir() -> PathBuf {
    // Locate the home directory as the starting point.
    // If called on a non-standard OS, use the repository directory.
    let mut path = match home_dir() {
        Some(home) => home,
        None => PathBuf::from(env!("CARGO_MANIFEST_DIR")),
    };
    // Append the Aleo directory to the path.
    path.push(ALEO_DIRECTORY);
    path
}

///
/// Returns the directory for accessing the ledger files from Aleo storage.
///
/// In production mode, the expected directory path is `~/.aleo/storage/ledger-{network}`.
/// In development mode, the expected directory path is `/path/to/repo/.ledger-{network}-{id}`.
/// In custom mode, the expected directory path is `/path/to/custom`.
/// In test mode, the expected directory path is the temporary directory.
///
/// # Panics
///
/// Panics in test mode if the mode holds no temporary directory.
///
pub fn aleo_ledger_dir(network: u16, mode: &StorageMode) -> PathBuf {
    // Construct the path to the ledger in storage.
    match mode {
        // In production mode, the ledger is stored in the `~/.aleo/` directory.
        StorageMode::Production => {
            let mut path = aleo_dir();
            path.push("storage");
            path.push(format!("ledger-{network}"));
            path
        }
        // In development mode, the ledger files are stored in a hidden folder in the repository root directory.
        StorageMode::Development(id) => {
            let mut path = match std::env::current_dir() {
                Ok(current_dir) => current_dir,
                _ => PathBuf::from(env!("CARGO_MANIFEST_DIR")),
            };
            path.push(format!(".ledger-{network}-{id}"));
            path
        }
        // In custom mode, the ledger files are stored in the given directory path.
        StorageMode::Custom(primary, _) => primary.to_owned(),
        StorageMode::Test(tempdir) => {
            if let Some(tempdir) = tempdir {
                tempdir.path().to_owned()
            } else {
                // aleo_ledger_dir is only ever called with persistent storage, where TempDir must be present.
                panic!("StorageMode::Test was created in a persistent storage context without a TempDir");
            }
        }
    }
}

/// Returns the directory of the secondary ledger instance, which only the custom mode can hold.
pub fn aleo_secondary_ledger_dir(_network: u16, mode: &StorageMode) -> Option<PathBuf> {
    if let StorageMode::Custom(_, secondary) = mode { secondary.clone() } else { None }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The IDs of the mainnet, testnet and canary networks, and the largest ID.
    const NETWORK_IDS: [u16; 4] = [0, 1, 2, u16::MAX];
    /// The development IDs to check.
    const DEV_IDS: [u16; 4] = [0, 1, 39, u16::MAX];

    #[test]
    fn test_aleo_dir() {
        println!("{:?} exists: {:?}", aleo_dir(), aleo_dir().exists());
    }

    #[test]
    fn test_aleo_ledger_dir() {
        println!(
            "{:?} exists: {:?}",
            aleo_ledger_dir(2, &StorageMode::Production),
            aleo_ledger_dir(2, &StorageMode::Production).exists()
        );
    }

    #[test]
    fn test_aleo_dir_path() {
        let aleo_dir = aleo_dir();
        assert_eq!(aleo_dir.file_name().unwrap(), ".aleo");
        // On Unix, the home directory is `$HOME` whenever that is set and not empty.
        #[cfg(unix)]
        if let Some(home) = std::env::var_os("HOME").filter(|home| !home.is_empty()) {
            assert_eq!(aleo_dir, PathBuf::from(home).join(".aleo"));
        }
    }

    #[test]
    fn test_production_ledger_dir_path() {
        for network in NETWORK_IDS {
            let expected = aleo_dir().join("storage").join(format!("ledger-{network}"));
            assert_eq!(aleo_ledger_dir(network, &StorageMode::Production), expected);
            assert_eq!(aleo_secondary_ledger_dir(network, &StorageMode::Production), None);
        }
        // Pin the literal form of the path for each deployed network.
        assert!(aleo_ledger_dir(0, &StorageMode::Production).ends_with(".aleo/storage/ledger-0"));
        assert!(aleo_ledger_dir(1, &StorageMode::Production).ends_with(".aleo/storage/ledger-1"));
        assert!(aleo_ledger_dir(2, &StorageMode::Production).ends_with(".aleo/storage/ledger-2"));
    }

    #[test]
    fn test_development_ledger_dir_path() {
        let current_dir = std::env::current_dir().unwrap();
        for network in NETWORK_IDS {
            for dev in DEV_IDS {
                let mode = StorageMode::Development(dev);
                let expected = current_dir.join(format!(".ledger-{network}-{dev}"));
                assert_eq!(aleo_ledger_dir(network, &mode), expected);
                assert_eq!(aleo_secondary_ledger_dir(network, &mode), None);
            }
        }
        // Pin the literal form of the path.
        assert_eq!(aleo_ledger_dir(1, &StorageMode::Development(3)), current_dir.join(".ledger-1-3"));
    }

    #[test]
    fn test_custom_ledger_dir_path() {
        let primary = PathBuf::from("/path/to/primary");
        let secondary = PathBuf::from("/path/to/secondary");
        for network in NETWORK_IDS {
            let mode = StorageMode::Custom(primary.clone(), None);
            assert_eq!(aleo_ledger_dir(network, &mode), primary);
            assert_eq!(aleo_secondary_ledger_dir(network, &mode), None);

            let mode = StorageMode::Custom(primary.clone(), Some(secondary.clone()));
            assert_eq!(aleo_ledger_dir(network, &mode), primary);
            assert_eq!(aleo_secondary_ledger_dir(network, &mode), Some(secondary.clone()));
        }
    }

    #[test]
    fn test_test_ledger_dir_path() {
        let mode = StorageMode::new_test(None);
        let StorageMode::Test(Some(tempdir)) = &mode else { panic!("Expected a test mode with a directory") };
        assert!(tempdir.path().is_dir());
        assert!(tempdir.path().file_name().unwrap().to_str().unwrap().starts_with("aleo_storage_"));
        for network in NETWORK_IDS {
            assert_eq!(aleo_ledger_dir(network, &mode), tempdir.path());
            assert_eq!(aleo_secondary_ledger_dir(network, &mode), None);
        }

        // A given directory is kept.
        let given = Arc::new(TempDir::new().unwrap());
        let mode = StorageMode::new_test(Some(given.clone()));
        assert_eq!(aleo_ledger_dir(0, &mode), given.path());
    }

    #[test]
    #[should_panic(expected = "StorageMode::Test was created in a persistent storage context without a TempDir")]
    fn test_test_ledger_dir_without_tempdir_panics() {
        aleo_ledger_dir(0, &StorageMode::Test(None));
    }

    #[test]
    fn test_dev() {
        assert_eq!(StorageMode::Production.dev(), None);
        assert_eq!(StorageMode::Development(7).dev(), Some(7));
        assert_eq!(StorageMode::Custom(PathBuf::from("/path"), None).dev(), None);
        assert_eq!(StorageMode::Test(None).dev(), None);
        assert_eq!(StorageMode::new_test(None).dev(), None);
    }

    #[test]
    fn test_from() {
        let primary = PathBuf::from("/path/to/primary");
        let secondary = PathBuf::from("/path/to/secondary");
        let tempdir = Arc::new(TempDir::new().unwrap());

        assert_eq!(StorageMode::from(7u16), StorageMode::Development(7));
        assert_eq!(StorageMode::from(primary.clone()), StorageMode::Custom(primary.clone(), None));
        assert_eq!(
            StorageMode::from((primary.clone(), Some(secondary.clone()))),
            StorageMode::Custom(primary, Some(secondary))
        );
        assert_eq!(StorageMode::from(tempdir.clone()), StorageMode::Test(Some(tempdir)));
    }

    #[test]
    fn test_eq() {
        let path = PathBuf::from("/path");
        let other = PathBuf::from("/other");
        let tempdir = Arc::new(TempDir::new().unwrap());

        assert_eq!(StorageMode::Production, StorageMode::Production);
        assert_eq!(StorageMode::Development(1), StorageMode::Development(1));
        assert_ne!(StorageMode::Development(1), StorageMode::Development(2));
        assert_ne!(StorageMode::Production, StorageMode::Development(0));
        assert_eq!(StorageMode::Custom(path.clone(), None), StorageMode::Custom(path.clone(), None));
        assert_ne!(StorageMode::Custom(path.clone(), None), StorageMode::Custom(other.clone(), None));
        assert_ne!(StorageMode::Custom(path.clone(), None), StorageMode::Custom(path, Some(other)));
        assert_eq!(StorageMode::Test(Some(tempdir.clone())), StorageMode::Test(Some(tempdir.clone())));
        assert_ne!(StorageMode::Test(Some(tempdir)), StorageMode::new_test(None));
        // Test modes without a directory never compare equal.
        assert_ne!(StorageMode::Test(None), StorageMode::Test(None));
    }
}
