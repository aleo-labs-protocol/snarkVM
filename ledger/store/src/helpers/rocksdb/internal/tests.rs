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

use crate::helpers::{
    Map,
    MapRead,
    rocksdb::{Database, MapID, RocksDB, TestMap as TestMapID},
};
use console::{
    network::{MainnetV0, Network},
    prelude::{TestRng, Uniform},
    types::Scalar,
};
use snarkvm_utilities::StorageMode;

// pub(crate) fn temp_file() -> std::path::PathBuf {
//     tempfile::NamedTempFile::new().expect("Failed to open temporary file").path().to_owned()
// }

#[test]
fn test_open() {
    let _storage = RocksDB::open(0, StorageMode::new_test(None)).expect("Failed to open storage");
}

#[test]
fn test_open_map() {
    let _map = RocksDB::open_map::<_, u32, String, _>(0, StorageMode::new_test(None), MapID::Test(TestMapID::Test))
        .expect("Failed to open data map");
}

// RocksDB reserves disk space with `fallocate`, which it uses only on Linux.
#[cfg(target_os = "linux")]
#[test]
fn test_open_allocates_little_disk_space() {
    use std::os::unix::fs::MetadataExt;

    // RocksDB can reserve space for its write-ahead log and manifest ahead of the data written to them.
    const MAX_ALLOCATED_BYTES: u64 = 1024 * 1024;

    let storage = StorageMode::new_test(None);
    let path = snarkvm_utilities::aleo_ledger_dir(0, &storage);
    let map = RocksDB::open_map(0, storage, MapID::Test(TestMapID::Test)).expect("Failed to open data map");

    for i in 0..100u32 {
        map.insert(i, i.to_string()).expect("Failed to insert");
    }

    // `blocks` counts 512-byte units, including the ones reserved by `fallocate`.
    let allocated: u64 = std::fs::read_dir(&path)
        .expect("Failed to read the database directory")
        .map(|entry| entry.expect("Failed to read a directory entry").metadata().expect("Failed to read metadata"))
        .map(|metadata| metadata.blocks() * 512)
        .sum();
    assert!(allocated < MAX_ALLOCATED_BYTES, "The database allocates {allocated} bytes on disk");
}

/// Returns the value of `name` in the aggregated table properties of `database`.
fn table_property(database: &RocksDB, name: &str) -> u64 {
    let properties = database
        .property_value("rocksdb.aggregated-table-properties")
        .expect("Failed to read the table properties")
        .expect("The table properties are missing");
    properties
        .split(';')
        .filter_map(|property| property.trim().split_once('='))
        .find(|(key, _)| *key == name)
        .unwrap_or_else(|| panic!("The table properties have no '{name}': {properties}"))
        .1
        .parse()
        .expect("The table property is not a number")
}

#[test]
fn test_table_files_have_partitioned_filters() {
    let map = RocksDB::open_map(0, StorageMode::new_test(None), MapID::Test(TestMapID::Test))
        .expect("Failed to open data map");

    for i in 0..1000u32 {
        map.insert(i, i.to_string()).expect("Failed to insert");
    }
    map.database.flush().expect("Failed to flush");

    assert!(table_property(&map.database, "filter block size") > 0);
    assert!(table_property(&map.database, "# index partitions") > 0);

    // Lookups read the table file, as the flush emptied the memtable.
    for i in 0..1000u32 {
        assert_eq!(map.get_confirmed(&i).expect("Failed to get").map(|value| value.into_owned()), Some(i.to_string()));
    }
    for i in 1000..2000u32 {
        assert!(!map.contains_key_confirmed(&i).expect("Failed to check"));
    }
}

#[test]
fn test_seeks_stay_in_the_map_with_filters() {
    let storage = StorageMode::new_test(None);
    let open = |map_id| {
        RocksDB::open_map::<_, u32, u32, _>(0, storage.clone(), MapID::Test(map_id)).expect("Failed to open data map")
    };
    let (first, second, empty) = (open(TestMapID::Test), open(TestMapID::Test2), open(TestMapID::Test3));

    // Each map is in a table file of its own, so that the filter of a file holds the prefix of one map.
    // The keys are below 256, so that the order of their serialized bytes is their numeric order.
    for map in [&first, &second] {
        for key in [10u32, 20, 30] {
            map.insert(key, key).expect("Failed to insert");
        }
        map.database.flush().expect("Failed to flush");
    }
    assert!(table_property(&first.database, "filter block size") > 0);

    let floor = |map: &crate::helpers::rocksdb::DataMap<u32, u32>, key: u32| {
        map.get_floor_confirmed(&key).expect("Failed to get the floor").map(|(key, _)| key.into_owned())
    };
    for map in [&first, &second] {
        assert_eq!(floor(map, 5), None);
        assert_eq!(floor(map, 10), Some(10));
        assert_eq!(floor(map, 25), Some(20));
        assert_eq!(floor(map, 200), Some(30));
        assert_eq!(map.len_confirmed(), 3);
        assert_eq!(map.keys_confirmed().map(|key| key.into_owned()).collect::<Vec<_>>(), vec![10, 20, 30]);
    }
    assert_eq!(floor(&empty, 25), None);
    assert_eq!(empty.len_confirmed(), 0);
    assert_eq!(empty.keys_confirmed().count(), 0);
}

#[test]
fn test_table_config_parse() {
    use super::{FilterPolicy, TableConfig};

    const MIB: usize = 1024 * 1024;

    let default = TableConfig::parse(None, None, None).expect("Failed to parse the defaults");
    assert_eq!(default, TableConfig {
        filter_policy: FilterPolicy::Bloom,
        filter_bits_per_key: 10.0,
        block_cache_size: 2048 * MIB
    });
    assert_eq!(TableConfig::parse(Some("bloom"), Some("10"), Some("2048")).expect("Failed to parse"), default);

    for (value, expected) in
        [("ribbon", FilterPolicy::Ribbon), ("hybrid", FilterPolicy::Hybrid), ("none", FilterPolicy::None)]
    {
        let config = TableConfig::parse(Some(value), Some("9.9"), Some("1")).expect("Failed to parse");
        assert_eq!(config, TableConfig { filter_policy: expected, filter_bits_per_key: 9.9, block_cache_size: MIB });
    }

    for value in ["", "Bloom", "bloom ", "0", "1"] {
        assert!(TableConfig::parse(Some(value), None, None).is_err(), "Accepted the filter policy '{value}'");
    }
    for value in ["", "0", "0.5", "-10", "nan", "inf", "ten"] {
        assert!(TableConfig::parse(None, Some(value), None).is_err(), "Accepted '{value}' bits per key");
    }
    for value in ["", "0", "-1", "1.5", "2048MiB", "18446744073709551615"] {
        assert!(TableConfig::parse(None, None, Some(value)).is_err(), "Accepted a block cache of '{value}' MiB");
    }
}

#[test]
fn test_insert_and_contains_key() {
    let map = RocksDB::open_map(0, StorageMode::new_test(None), MapID::Test(TestMapID::Test))
        .expect("Failed to open data map");

    map.insert(123456789, "123456789".to_string()).expect("Failed to insert");
    assert!(map.contains_key_confirmed(&123456789).expect("Failed to call contains key"));
    assert!(!map.contains_key_confirmed(&000000000).expect("Failed to call contains key"));
}

#[test]
fn test_insert_and_get() {
    let map = RocksDB::open_map(0, StorageMode::new_test(None), MapID::Test(TestMapID::Test))
        .expect("Failed to open data map");

    map.insert(123456789, "123456789".to_string()).expect("Failed to insert");
    assert_eq!(
        Some("123456789".to_string()),
        map.get_confirmed(&123456789).expect("Failed to get").map(|v| v.to_string())
    );

    assert_eq!(None, map.get_confirmed(&000000000).expect("Failed to get"));
}

#[test]
fn test_insert_and_remove() {
    let map = RocksDB::open_map(0, StorageMode::new_test(None), MapID::Test(TestMapID::Test))
        .expect("Failed to open data map");

    map.insert(123456789, "123456789".to_string()).expect("Failed to insert");
    assert_eq!(
        map.get_confirmed(&123456789).expect("Failed to get").map(|v| v.to_string()),
        Some("123456789".to_string())
    );

    map.remove(&123456789).expect("Failed to remove");
    assert!(map.get_confirmed(&123456789).expect("Failed to get").is_none());
}

#[test]
fn test_insert_and_iter() {
    let map = RocksDB::open_map(0, StorageMode::new_test(None), MapID::Test(TestMapID::Test))
        .expect("Failed to open data map");

    map.insert(123456789, "123456789".to_string()).expect("Failed to insert");

    let mut iter = map.iter_confirmed();
    assert_eq!(Some((123456789, "123456789".to_string())), iter.next().map(|(k, v)| (*k, v.to_string())));
    assert_eq!(None, iter.next());
}

#[test]
fn test_insert_and_keys() {
    let map = RocksDB::open_map(0, StorageMode::new_test(None), MapID::Test(TestMapID::Test))
        .expect("Failed to open data map");

    map.insert(123456789, "123456789".to_string()).expect("Failed to insert");

    let mut keys = map.keys_confirmed();
    assert_eq!(Some(123456789), keys.next().map(|k| *k));
    assert_eq!(None, keys.next());
}

#[test]
fn test_insert_and_values() {
    let map = RocksDB::open_map(0, StorageMode::new_test(None), MapID::Test(TestMapID::Test))
        .expect("Failed to open data map");

    map.insert(123456789, "123456789".to_string()).expect("Failed to insert");

    let mut values = map.values_confirmed();
    assert_eq!(Some("123456789".to_string()), values.next().map(|v| v.to_string()));
    assert_eq!(None, values.next());
}

// #[test]
// fn test_export_import() {
//     let file = temp_file();
//     {
//         let mut map = RocksDB::open_map(0, StorageMode::new_test(None), MapID::Test(TestMapID::Test)).expect("Failed to open data map");
//
//         for i in 0..100 {
//             map.insert(i, i.to_string()).expect("Failed to insert");
//         }
//
//         storage.export(&file).expect("Failed to export storage");
//     }
//
//     let storage = RocksDB::open_temporary(temp_dir(), None).expect("Failed to open storage");
//     storage.import(&file).expect("Failed to import storage");
//
//     let map = storage.open_map::<u32, String>(MapID::Test(TestMapID::Test)).expect("Failed to open data map");
//
//     for i in 0..100 {
//         assert_eq!(map.get(&i).expect("Failed to get").map(|v| v.to_string()), Some(i.to_string()));
//     }
// }

#[test]
fn test_scalar_mul() {
    type CurrentNetwork = MainnetV0;

    let rng = &mut TestRng::default();

    const ITERATIONS: u32 = 1_000_000u32;

    let map = RocksDB::open_map(0, StorageMode::new_test(None), MapID::Test(TestMapID::Test))
        .expect("Failed to open data map");

    // Sample `ITERATION` random field elements to store.
    for i in 0..ITERATIONS {
        let value = Scalar::<CurrentNetwork>::rand(rng);
        map.insert(i, value).expect("Failed to insert");
    }

    let timer = std::time::Instant::now();

    // Execute scalar multiplication for each stored element.
    for value in map.values_confirmed() {
        let _group = CurrentNetwork::g_scalar_multiply(&*value);
    }

    let elapsed = timer.elapsed().as_secs();
    println!(" {ITERATIONS} Scalar Muls : {elapsed} s");
}

#[test]
fn test_iterator_ordering() {
    let map = RocksDB::open_map(0, StorageMode::new_test(None), MapID::Test(TestMapID::Test))
        .expect("Failed to open data map");

    // Insert values into the map.
    map.insert(5, "d".to_string()).expect("Failed to insert");
    map.insert(6, "c".to_string()).expect("Failed to insert");
    map.insert(7, "b".to_string()).expect("Failed to insert");
    map.insert(8, "a".to_string()).expect("Failed to insert");
    map.insert(1, "h".to_string()).expect("Failed to insert");
    map.insert(2, "g".to_string()).expect("Failed to insert");
    map.insert(3, "f".to_string()).expect("Failed to insert");
    map.insert(4, "e".to_string()).expect("Failed to insert");

    // Define the expected order of the iterator.
    let expected_order = [
        (1, "h".to_string()),
        (2, "g".to_string()),
        (3, "f".to_string()),
        (4, "e".to_string()),
        (5, "d".to_string()),
        (6, "c".to_string()),
        (7, "b".to_string()),
        (8, "a".to_string()),
    ];

    // Check that the order of the iterator is lexicographical.
    for ((k1, v1), (k2, v2)) in map.iter_confirmed().zip(expected_order.iter()) {
        assert_eq!(&*k1, k2);
        assert_eq!(&*v1, v2);
    }
}
