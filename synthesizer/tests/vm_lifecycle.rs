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

//! Regression tests for sequential worker ownership.

use std::sync::{Arc, Barrier};

use aleo_std::StorageMode;
use snarkvm_console::{
    network::{CanaryV0, MainnetV0, Network, TestnetV0},
    program::ProgramID,
};
use snarkvm_ledger_store::{ConsensusStore, helpers::memory::ConsensusMemory};
use snarkvm_synthesizer::VM;

fn new_vm<N: Network>() -> VM<N, ConsensusMemory<N>> {
    VM::from(ConsensusStore::open(StorageMode::Production).unwrap()).unwrap()
}

fn assert_dropped_vm_releases_process<N: Network>() {
    // Repeated provider replacement must not retain one Process per iteration.
    for _ in 0..3 {
        let vm = new_vm::<N>();
        let process = Arc::downgrade(vm.process());
        let clone = vm.clone();
        drop(vm);
        assert!(process.upgrade().is_some());
        assert!(clone.contains_program(&"credits.aleo".parse::<ProgramID<N>>().unwrap()));
        drop(clone);
        // Final drop joins the worker; no sleep or timing assumption is needed.
        assert!(process.upgrade().is_none(), "worker retained a dropped VM");
    }
}

#[test]
fn dropped_mainnet_vm_releases_process() {
    assert_dropped_vm_releases_process::<MainnetV0>();
}

#[test]
fn dropped_testnet_vm_releases_process() {
    assert_dropped_vm_releases_process::<TestnetV0>();
}

#[test]
fn dropped_canary_vm_releases_process() {
    assert_dropped_vm_releases_process::<CanaryV0>();
}

#[test]
fn concurrent_final_vm_clones_release_process() {
    for _ in 0..8 {
        let vm = new_vm::<MainnetV0>();
        let process = Arc::downgrade(vm.process());
        let barrier = Arc::new(Barrier::new(5));
        std::thread::scope(|scope| {
            for _ in 0..4 {
                let clone = vm.clone();
                let barrier = barrier.clone();
                scope.spawn(move || {
                    barrier.wait();
                    drop(clone);
                });
            }
            drop(vm);
            barrier.wait();
        });
        assert!(process.upgrade().is_none(), "concurrent drops retained a VM");
    }
}
