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

use std::{cell::Cell, marker::PhantomData, panic, sync::Once};

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
            // The flag is per thread, in debug and release builds. A rayon job runs with the flag of the thread that
            // runs it, unless the job enters a `VmScope`.
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
/// In release mode, it prints nothing.
///
/// Only the current thread runs inside the VM runtime. A rayon job started by `f` must enter a [`VmScope`] captured
/// in `f`, or its halts may reach the previous panic hook.
///
/// Panics outside the VM runtime go to the panic hook that was present on the first invocation. Custom panic hooks
/// should be installed before calling this function for the first time.
///
/// It is public for other snarkVM crates, but it is not part of the API, and semver does not cover it.
#[doc(hidden)]
#[inline]
pub fn try_vm_runtime<R, F: FnOnce() -> R>(f: F) -> std::thread::Result<R> {
    install_vm_runtime_hook();

    // Mark only this thread as executing inside the VM runtime, until the guard restores the previous state.
    let _vm = VmScope { in_vm_runtime: true }.enter();

    // Perform the operation that may panic.
    panic::catch_unwind(panic::AssertUnwindSafe(f))
}

/// Whether the thread that captured this scope was inside [`try_vm_runtime`].
///
/// A VM operation that runs jobs in parallel captures its scope on the thread that starts the jobs, and each job
/// enters that scope around the code that may halt. A halt in the job is then a VM halt. A scope captured outside the
/// VM runtime leaves the flag unset, so the same code there still reports its panics to the previous panic hook.
///
/// Enter a scope only in jobs whose panics rayon carries back to the capturing thread while it waits inside the VM
/// runtime, as with `par_iter`, `join` and `scope`. A panic in a `rayon::spawn` job does not return to the capturing
/// thread, so a VM scope there silences a panic that nothing catches.
///
/// Keep code that waits on rayon outside an entered scope. A waiting thread can run unrelated jobs, and their panics
/// would be silenced too. For the same reason, the thread that starts the jobs leaves the VM scope while it waits on
/// them, by entering `VmScope::default()`.
#[derive(Clone, Copy, Debug, Default)]
pub struct VmScope {
    in_vm_runtime: bool,
}

impl VmScope {
    /// Captures the VM scope of the current thread.
    pub fn current() -> Self {
        Self { in_vm_runtime: IN_VM_RUNTIME.with(Cell::get) }
    }

    /// Gives the current thread this VM scope until the guard drops, replacing its previous scope.
    pub fn enter(self) -> VmScopeGuard {
        let previous = IN_VM_RUNTIME.with(|is_active| is_active.replace(self.in_vm_runtime));
        VmScopeGuard { previous, _not_send: PhantomData }
    }
}

/// Restores the previous VM scope of its thread when it drops, also during an unwind.
#[must_use = "the VM scope ends when the guard drops"]
pub struct VmScopeGuard {
    previous: bool,
    /// Keeps the guard on the thread whose scope it restores.
    _not_send: PhantomData<*const ()>,
}

impl Drop for VmScopeGuard {
    fn drop(&mut self) {
        IN_VM_RUNTIME.with(|is_active| is_active.set(self.previous));
    }
}

#[cfg(test)]
mod tests {
    use super::{IN_VM_RUNTIME, VmScope, try_vm_runtime};

    use std::{
        cell::Cell,
        env,
        panic,
        process::{Command, Output},
        sync::{
            Arc,
            Barrier,
            atomic::{AtomicUsize, Ordering},
        },
        thread,
    };

    const CHILD_PROCESS_ENV: &str = "SNARKVM_VM_RUNTIME_HOOK_CHILD";
    const NUM_VM_THREADS: usize = 8;

    fn in_vm_runtime() -> bool {
        IN_VM_RUNTIME.with(Cell::get)
    }

    fn is_child_process() -> bool {
        env::var_os(CHILD_PROCESS_ENV).is_some()
    }

    /// Runs the test with the given path in a fresh process, because panic hooks and `Once` state are process-global.
    fn run_in_child_process(test_path: &str) -> Output {
        let output = Command::new(env::current_exe().expect("Failed to locate the test executable"))
            .args([test_path, "--exact", "--nocapture"])
            .env(CHILD_PROCESS_ENV, "1")
            .output()
            .expect("Failed to launch the child test process");

        let stdout = String::from_utf8_lossy(&output.stdout);
        assert!(
            output.status.success() && stdout.contains("1 passed"),
            "Child test failed.\nstdout:\n{stdout}\nstderr:\n{}",
            String::from_utf8_lossy(&output.stderr)
        );
        output
    }

    /// Installs a host hook that counts its calls, then the VM hook on top of it.
    fn install_counting_host_hook() -> Arc<AtomicUsize> {
        let host_panic_count = Arc::new(AtomicUsize::new(0));
        let host_panic_count_ = host_panic_count.clone();
        panic::set_hook(Box::new(move |_| {
            host_panic_count_.fetch_add(1, Ordering::SeqCst);
        }));
        try_vm_runtime(|| ()).expect("An empty VM operation cannot halt");
        host_panic_count
    }

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
    fn test_vm_scope_carries_flag_to_another_thread() {
        let scope = try_vm_runtime(VmScope::current).unwrap();
        assert!(!in_vm_runtime());

        thread::spawn(move || {
            assert!(!in_vm_runtime());
            {
                let _vm = scope.enter();
                assert!(in_vm_runtime());
            }
            assert!(!in_vm_runtime());
        })
        .join()
        .unwrap();
    }

    #[test]
    fn test_vm_scope_captured_outside_vm_runtime_clears_flag() {
        let scope = VmScope::current();
        {
            let _vm = scope.enter();
            assert!(!in_vm_runtime());
        }

        try_vm_runtime(|| {
            {
                let _vm = scope.enter();
                assert!(!in_vm_runtime());
            }
            assert!(in_vm_runtime());
        })
        .unwrap();
    }

    #[test]
    fn test_vm_scope_guard_restores_flag_on_unwind() {
        let scope = try_vm_runtime(VmScope::current).unwrap();

        thread::spawn(move || {
            let result = panic::catch_unwind(|| {
                let _vm = scope.enter();
                panic!("VM halt");
            });
            assert!(result.is_err());
            assert!(!in_vm_runtime());
        })
        .join()
        .unwrap();
    }

    #[test]
    fn test_parallel_vm_runtime_preserves_host_hook() {
        if is_child_process() {
            run_parallel_vm_runtime_child();
            return;
        }

        let output = run_in_child_process("vm_error::tests::test_parallel_vm_runtime_preserves_host_hook");

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

    #[test]
    fn test_vm_scope_captured_outside_vm_runtime_reaches_host_hook() {
        if !is_child_process() {
            run_in_child_process("vm_error::tests::test_vm_scope_captured_outside_vm_runtime_reaches_host_hook");
            return;
        }
        let host_panic_count = install_counting_host_hook();

        let scope = VmScope::current();
        let result = try_vm_runtime(|| {
            let _vm = scope.enter();
            panic!("panic outside the VM runtime");
        });
        assert!(result.is_err());
        assert_eq!(host_panic_count.load(Ordering::SeqCst), 1, "The panic should reach the host hook");
    }

    #[cfg(not(feature = "serial"))]
    #[test]
    fn test_vm_scope_halt_on_rayon_worker_skips_host_hook() {
        if !is_child_process() {
            run_in_child_process("vm_error::tests::test_vm_scope_halt_on_rayon_worker_skips_host_hook");
            return;
        }
        let host_panic_count = install_counting_host_hook();

        // This thread is not in the pool, so the job runs on the pool's worker.
        let pool = rayon::ThreadPoolBuilder::new().num_threads(1).build().unwrap();
        let result = try_vm_runtime(|| {
            let scope = VmScope::current();
            pool.install(|| {
                let _vm = scope.enter();
                panic!("VM halt on a worker");
            })
        });
        assert!(result.is_err());
        assert_eq!(host_panic_count.load(Ordering::SeqCst), 0, "The halt should not reach the host hook");

        // The worker has left the VM scope.
        let result = pool.install(|| panic::catch_unwind(|| panic!("unrelated panic on the worker")));
        assert!(result.is_err());
        assert_eq!(host_panic_count.load(Ordering::SeqCst), 1, "The unrelated panic should reach the host hook");

        // A VM operation on a worker halts in both jobs of a join. The barrier holds each job until the other one
        // runs on the other worker.
        let pool = rayon::ThreadPoolBuilder::new().num_threads(2).build().unwrap();
        let barrier = Barrier::new(2);
        let halt = |scope: VmScope| {
            let _vm = scope.enter();
            barrier.wait();
            panic!("VM halt in a join");
        };
        let result = pool.install(|| {
            try_vm_runtime(|| {
                let scope = VmScope::current();
                let _waiting = VmScope::default().enter();
                rayon::join(|| halt(scope), || halt(scope))
            })
        });
        assert!(result.is_err());
        assert_eq!(host_panic_count.load(Ordering::SeqCst), 1, "The halts should not reach the host hook");
    }

    /// An unrelated panic on a rayon worker while a VM operation is active, as in #3804.
    #[cfg(not(feature = "serial"))]
    #[test]
    fn test_unrelated_rayon_panic_during_vm_runtime_reaches_host_hook() {
        use rayon::prelude::*;

        if !is_child_process() {
            run_in_child_process("vm_error::tests::test_unrelated_rayon_panic_during_vm_runtime_reaches_host_hook");
            return;
        }
        let host_panic_count = install_counting_host_hook();

        let vm_started = Arc::new(Barrier::new(2));
        let host_panic_finished = Arc::new(Barrier::new(2));
        let (vm_started_, host_panic_finished_) = (vm_started.clone(), host_panic_finished.clone());
        let vm = thread::spawn(move || {
            try_vm_runtime(|| {
                vm_started_.wait();
                host_panic_finished_.wait();
            })
        });

        // The VM operation is active while the unrelated job panics.
        vm_started.wait();
        let pool = rayon::ThreadPoolBuilder::new().num_threads(4).build().unwrap();
        let result = panic::catch_unwind(panic::AssertUnwindSafe(|| {
            pool.install(|| {
                (0..8).into_par_iter().for_each(|i| {
                    if i == 5 {
                        panic!("unrelated panic on a worker");
                    }
                })
            })
        }));
        assert!(result.is_err());
        assert_eq!(host_panic_count.load(Ordering::SeqCst), 1, "The unrelated panic should reach the host hook");

        host_panic_finished.wait();
        vm.join().unwrap().unwrap();
    }

    /// A worker that waits on a join inside the VM runtime runs an unrelated job that panics.
    #[cfg(not(feature = "serial"))]
    #[test]
    fn test_job_stolen_by_waiting_vm_thread_reaches_host_hook() {
        use std::{sync::mpsc, time::Duration};

        /// Signals when it drops, which is during the unwind of the panic, after the hook has run.
        struct SignalOnDrop(mpsc::Sender<()>);

        impl Drop for SignalOnDrop {
            fn drop(&mut self) {
                let _ = self.0.send(());
            }
        }

        if !is_child_process() {
            run_in_child_process("vm_error::tests::test_job_stolen_by_waiting_vm_thread_reaches_host_hook");
            return;
        }
        let host_panic_count = install_counting_host_hook();

        for _ in 0..5 {
            let pool = Arc::new(rayon::ThreadPoolBuilder::new().num_threads(2).panic_handler(|_| {}).build().unwrap());
            let (second_job_started_tx, second_job_started_rx) = mpsc::channel();
            let (spawn_now_tx, spawn_now_rx) = mpsc::channel();
            let (unrelated_ran_tx, unrelated_ran_rx) = mpsc::channel();
            let (unrelated_unwound_tx, unrelated_unwound_rx) = mpsc::channel();

            // Injects the unrelated job once the VM thread is about to wait.
            let pool_ = pool.clone();
            let spawner = thread::spawn(move || {
                spawn_now_rx.recv().unwrap();
                pool_.spawn(move || {
                    let _signal = SignalOnDrop(unrelated_unwound_tx);
                    unrelated_ran_tx.send(rayon::current_thread_index()).unwrap();
                    panic!("unrelated panic in a stolen job");
                });
            });

            let before = host_panic_count.load(Ordering::SeqCst);
            let (vm_thread, stolen_on) = pool.install(move || {
                let vm_thread = rayon::current_thread_index();
                let stolen_on = try_vm_runtime(move || {
                    let scope = VmScope::current();
                    let _waiting = VmScope::default().enter();
                    let ((), stolen_on) = rayon::join(
                        move || {
                            // The other worker runs the second job, so this thread then waits on it.
                            second_job_started_rx.recv().unwrap();
                            spawn_now_tx.send(()).unwrap();
                        },
                        move || {
                            let _vm = scope.enter();
                            second_job_started_tx.send(()).unwrap();
                            // The other worker is busy until the unrelated job has run on the waiting thread.
                            unrelated_ran_rx.recv().unwrap()
                        },
                    );
                    stolen_on
                })
                .unwrap();
                (vm_thread, stolen_on)
            });
            spawner.join().unwrap();
            unrelated_unwound_rx.recv_timeout(Duration::from_secs(10)).unwrap();

            assert_eq!(stolen_on, vm_thread, "The unrelated job should run on the waiting VM thread");
            assert_eq!(
                host_panic_count.load(Ordering::SeqCst) - before,
                1,
                "The unrelated panic should reach the host hook"
            );
        }
    }
}
