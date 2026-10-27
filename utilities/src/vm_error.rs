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

pub use std::error::Error;

use std::{cell::Cell, panic, sync::Once};

thread_local! {
    /// Whether the current thread is executing inside the VM runtime.
    static IN_VM_RUNTIME: Cell<bool> = const { Cell::new(false) };
}

/// Ensures the VM-aware panic hook is installed exactly once.
static INSTALL_VM_RUNTIME_HOOK: Once = Once::new();

/// Installs a panic hook that distinguishes VM halts from unrelated panics.
fn install_vm_runtime_hook() {
    INSTALL_VM_RUNTIME_HOOK.call_once(|| {
        let previous_hook = panic::take_hook();

        panic::set_hook(Box::new(move |info| {
            if IN_VM_RUNTIME.try_with(Cell::get).unwrap_or(false) {
                #[cfg(debug_assertions)]
                {
                    // Remove all words up to "panicked".
                    let trimmed = info
                        .to_string()
                        .split_ascii_whitespace()
                        .skip_while(|&word| word != "panicked")
                        .collect::<Vec<&str>>()
                        .join(" ");

                    // Have the message start with "VM safely halted".
                    // Note that some VM code uses Rayon to execute work in parallel. The Rayon worker threads
                    // will not have the IN_VM_RUNTIME thread local variable set to true, so if they panic,
                    // we will get the standard panic message and not the "VM safely handled" one.
                    let msg = trimmed.replacen("panicked", "VM safely halted", 1);
                    eprintln!("{msg}");
                }
            } else {
                previous_hook(info);
            }
        }));
    });
}

/// Provides a VM runtime environment which will safely halt
/// without producing logs that look like unexpected behavior.
/// In debug mode, it prints to stderr using the format: "VM safely halted at {location}: {halt message}".
///
/// The panic hook present on the first invocation is retained for unrelated panics. Custom panic hooks should be
/// installed before calling this function for the first time.
#[inline]
pub fn try_vm_runtime<R, F: FnOnce() -> R>(f: F) -> std::thread::Result<R> {
    install_vm_runtime_hook();

    // Mark only this thread as executing inside the VM runtime.
    let was_in_vm_runtime = IN_VM_RUNTIME.with(|is_active| is_active.replace(true));

    // Perform the operation that may panic.
    let result = panic::catch_unwind(panic::AssertUnwindSafe(f));

    // Restore the previous state to support nested calls.
    IN_VM_RUNTIME.with(|is_active| is_active.set(was_in_vm_runtime));

    result
}

#[cfg(test)]
mod tests {
    use super::try_vm_runtime;

    use std::{
        env,
        panic,
        process::Command,
        sync::{
            Arc,
            Barrier,
            atomic::{AtomicUsize, Ordering},
        },
        thread,
    };

    const CHILD_PROCESS_ENV: &str = "SNARKVM_VM_RUNTIME_HOOK_CHILD";
    const NUM_VM_THREADS: usize = 8;

    #[test]
    fn test_try_vm_runtime_success() {
        assert_eq!(try_vm_runtime(|| 42).unwrap(), 42);
    }

    #[test]
    fn test_try_vm_runtime_preserves_panic_payload() {
        let result = try_vm_runtime(|| panic!("expected VM halt"));
        let payload = result.expect_err("VM panic should be caught");
        assert_eq!(payload.downcast_ref::<&str>(), Some(&"expected VM halt"));
    }

    #[test]
    fn test_nested_try_vm_runtime() {
        let result = try_vm_runtime(|| {
            let inner = try_vm_runtime(|| panic!("inner VM halt"));
            assert!(inner.is_err(), "Inner VM panic should be caught");
            panic!("outer VM halt");
        });

        assert!(result.is_err(), "Outer VM panic should be caught");
    }

    #[test]
    fn test_parallel_vm_runtime_preserves_host_hook() {
        if env::var_os(CHILD_PROCESS_ENV).is_some() {
            run_parallel_vm_runtime_child();
            return;
        }

        // Run this test in a fresh process because panic hooks and `Once` state are process-global.
        let output = Command::new(env::current_exe().expect("Failed to locate the test executable"))
            .arg("test_parallel_vm_runtime_preserves_host_hook")
            .arg("--nocapture")
            .env(CHILD_PROCESS_ENV, "1")
            .output()
            .expect("Failed to launch the child test process");

        assert!(
            output.status.success(),
            "Child test failed.\nstdout:\n{}\nstderr:\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );

        let stderr = String::from_utf8_lossy(&output.stderr);
        #[cfg(debug_assertions)]
        assert_eq!(stderr.matches("VM safely halted").count(), NUM_VM_THREADS, "Unexpected stderr:\n{stderr}");
        #[cfg(not(debug_assertions))]
        assert!(!stderr.contains("VM safely halted"), "Unexpected stderr:\n{stderr}");
    }

    fn run_parallel_vm_runtime_child() {
        let host_panic_count = Arc::new(AtomicUsize::new(0));
        let host_panic_count_ = host_panic_count.clone();
        panic::set_hook(Box::new(move |_| {
            host_panic_count_.fetch_add(1, Ordering::SeqCst);
        }));

        let ready = Arc::new(Barrier::new(NUM_VM_THREADS + 1));
        let host_panic_finished = Arc::new(Barrier::new(NUM_VM_THREADS + 1));
        let mut handles = Vec::with_capacity(NUM_VM_THREADS);

        for index in 0..NUM_VM_THREADS {
            let ready = ready.clone();
            let host_panic_finished = host_panic_finished.clone();
            handles.push(thread::spawn(move || {
                try_vm_runtime(|| {
                    // Keep every VM operation active while an unrelated panic fires on this thread's parent.
                    ready.wait();
                    host_panic_finished.wait();
                    panic!("VM operation {index} failed");
                })
            }));
        }

        // All VM calls have installed the dispatcher and entered their thread-local runtime scopes.
        ready.wait();

        let unrelated_panic = panic::catch_unwind(|| panic!("unrelated host panic"));
        assert!(unrelated_panic.is_err(), "Unrelated panic should be caught by the test");
        assert_eq!(host_panic_count.load(Ordering::SeqCst), 1, "Host hook should receive the unrelated panic");

        // Let the VM operations halt concurrently now that the unrelated panic has been observed.
        host_panic_finished.wait();
        for handle in handles {
            let result = handle.join().expect("VM worker should not panic outside try_vm_runtime");
            assert!(result.is_err(), "VM panic should be caught");
        }
        assert_eq!(host_panic_count.load(Ordering::SeqCst), 1, "VM panics should not reach the host hook");

        let later_panic = panic::catch_unwind(|| panic!("later host panic"));
        assert!(later_panic.is_err(), "Later panic should be caught by the test");
        assert_eq!(host_panic_count.load(Ordering::SeqCst), 2, "Host hook should remain installed after VM calls");
    }
}
