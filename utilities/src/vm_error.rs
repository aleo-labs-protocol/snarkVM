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

use std::{any::Any, fmt, panic, sync::Once};

/// The panic payload of a VM halt.
///
/// The payload travels with the panic, including when rayon re-raises a job's panic on the thread that waits on the
/// job. The panic hook and the code that catches the panic can both tell a halt from any other panic, whichever
/// thread halted.
///
/// It is public for other snarkVM crates, but it is not part of the API, and semver does not cover it.
#[doc(hidden)]
#[derive(Debug)]
pub struct VmHalt {
    message: String,
}

impl VmHalt {
    /// Returns the halt message.
    pub fn message(&self) -> &str {
        &self.message
    }
}

impl fmt::Display for VmHalt {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.message)
    }
}

/// Ensures the VM halt hook is installed exactly once.
static INSTALL_VM_HALT_HOOK: Once = Once::new();

/// Installs a panic hook that logs VM halts and passes every other panic to the previous hook.
fn install_vm_halt_hook() {
    INSTALL_VM_HALT_HOOK.call_once(|| {
        let previous_hook = panic::take_hook();

        panic::set_hook(Box::new(move |info| match info.payload().downcast_ref::<VmHalt>() {
            // A halt is an expected outcome that any caller can trigger, so it is logged without a backtrace.
            Some(halt) => match info.location() {
                Some(location) => tracing::debug!("VM halted at {location}: {halt}"),
                None => tracing::debug!("VM halted: {halt}"),
            },
            None => previous_hook(info),
        }));
    });
}

/// Halts the VM with the given message, by panicking with a [`VmHalt`] payload.
///
/// The panic hook logs the halt at the debug level, with the location of the caller. Every other panic goes to the
/// panic hook that was present when the first halt or [`try_vm_runtime`] ran, so custom panic hooks should be
/// installed before then.
///
/// It is public for other snarkVM crates, but it is not part of the API, and semver does not cover it.
#[doc(hidden)]
#[cold]
#[track_caller]
pub fn vm_halt(message: String) -> ! {
    install_vm_halt_hook();
    panic::panic_any(VmHalt { message })
}

/// Runs `f` and catches its panics. The error holds the panic payload, which is a [`VmHalt`] for a VM halt.
///
/// Rayon re-raises the panic of a job on the thread that waits on it, so this also catches halts in the rayon jobs
/// that `f` waits on.
///
/// It is public for other snarkVM crates, but it is not part of the API, and semver does not cover it.
#[doc(hidden)]
#[inline]
pub fn try_vm_runtime<R, F: FnOnce() -> R>(f: F) -> std::thread::Result<R> {
    install_vm_halt_hook();

    panic::catch_unwind(panic::AssertUnwindSafe(f))
}

/// Returns the message of a panic payload that is a [`VmHalt`], a `String` or a `&str`.
///
/// It is public for other snarkVM crates, but it is not part of the API, and semver does not cover it.
#[doc(hidden)]
pub fn panic_message(payload: &(dyn Any + Send)) -> Option<&str> {
    payload
        .downcast_ref::<VmHalt>()
        .map(VmHalt::message)
        .or_else(|| payload.downcast_ref::<String>().map(String::as_str))
        .or_else(|| payload.downcast_ref::<&str>().copied())
}

#[cfg(test)]
mod tests {
    use super::{VmHalt, panic_message, try_vm_runtime, vm_halt};

    use std::{
        env,
        panic,
        process::{Command, Output},
        sync::{
            Arc,
            Barrier,
            atomic::{AtomicUsize, Ordering},
            mpsc,
        },
        thread,
        time::Duration,
    };

    const CHILD_PROCESS_ENV: &str = "SNARKVM_VM_HALT_HOOK_CHILD";
    const NUM_VM_THREADS: usize = 8;

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

    /// Installs a host hook that counts its calls, then the VM halt hook on top of it.
    fn install_counting_host_hook() -> Arc<AtomicUsize> {
        let host_panic_count = Arc::new(AtomicUsize::new(0));
        let host_panic_count_ = host_panic_count.clone();
        panic::set_hook(Box::new(move |_| {
            host_panic_count_.fetch_add(1, Ordering::SeqCst);
        }));
        try_vm_runtime(|| ()).expect("An empty VM operation cannot halt");
        host_panic_count
    }

    /// Returns the message of a caught halt, and fails if the payload is not a halt.
    fn halt_message(payload: &(dyn std::any::Any + Send)) -> &str {
        payload.downcast_ref::<VmHalt>().expect("The payload should be a VM halt").message()
    }

    #[test]
    fn test_try_vm_runtime_success() {
        assert_eq!(try_vm_runtime(|| 42).expect("A VM operation that returns cannot halt"), 42);
    }

    #[test]
    fn test_try_vm_runtime_preserves_halt_payload() {
        let payload =
            try_vm_runtime(|| vm_halt("expected VM halt".to_string())).expect_err("The halt should be caught");
        assert_eq!(halt_message(&*payload), "expected VM halt");
    }

    #[test]
    fn test_nested_try_vm_runtime() {
        let result = try_vm_runtime(|| {
            let inner = try_vm_runtime(|| vm_halt("inner VM halt".to_string()));
            assert_eq!(halt_message(&*inner.expect_err("The inner halt should be caught")), "inner VM halt");
            vm_halt("outer VM halt".to_string());
        });
        assert_eq!(halt_message(&*result.expect_err("The outer halt should be caught")), "outer VM halt");
    }

    #[test]
    fn test_panic_message() {
        let halt = try_vm_runtime(|| vm_halt("a halt".to_string())).expect_err("The halt should be caught");
        assert_eq!(panic_message(&*halt), Some("a halt"));

        let string = panic::catch_unwind(|| panic!("{}", "a String")).expect_err("The panic should be caught");
        assert_eq!(panic_message(&*string), Some("a String"));

        let str = panic::catch_unwind(|| panic!("a &str")).expect_err("The panic should be caught");
        assert_eq!(panic_message(&*str), Some("a &str"));

        let other = panic::catch_unwind(|| panic::panic_any(7u8)).expect_err("The panic should be caught");
        assert_eq!(panic_message(&*other), None);
    }

    /// Concurrent halts skip the host hook, and unrelated panics reach it before, during and after them.
    #[test]
    fn test_concurrent_halts_preserve_host_hook() {
        if !is_child_process() {
            run_in_child_process("vm_error::tests::test_concurrent_halts_preserve_host_hook");
            return;
        }
        let host_panic_count = install_counting_host_hook();

        let ready = Arc::new(Barrier::new(NUM_VM_THREADS + 1));
        let host_panic_finished = Arc::new(Barrier::new(NUM_VM_THREADS + 1));
        let handles = (0..NUM_VM_THREADS)
            .map(|index| {
                let ready = ready.clone();
                let host_panic_finished = host_panic_finished.clone();
                thread::spawn(move || {
                    try_vm_runtime(|| {
                        // Keep every VM operation active while an unrelated panic fires on this thread's parent.
                        ready.wait();
                        host_panic_finished.wait();
                        vm_halt(format!("VM operation {index} halted"));
                    })
                })
            })
            .collect::<Vec<_>>();

        ready.wait();
        let unrelated_panic = panic::catch_unwind(|| panic!("unrelated host panic"));
        assert!(unrelated_panic.is_err());
        assert_eq!(host_panic_count.load(Ordering::SeqCst), 1, "The unrelated panic should reach the host hook");

        // Let the VM operations halt concurrently now that the unrelated panic has been observed.
        host_panic_finished.wait();
        for handle in handles {
            let result = handle.join().expect("The VM thread should not panic outside try_vm_runtime");
            assert!(result.is_err(), "The halt should be caught");
        }
        assert_eq!(host_panic_count.load(Ordering::SeqCst), 1, "The halts should not reach the host hook");

        let later_panic = panic::catch_unwind(|| panic!("later host panic"));
        assert!(later_panic.is_err());
        assert_eq!(host_panic_count.load(Ordering::SeqCst), 2, "The host hook should stay installed after halts");
    }

    /// A panic that is not a halt reaches the host hook, even inside `try_vm_runtime`, and is still caught.
    #[test]
    fn test_other_panic_in_vm_runtime_reaches_host_hook() {
        if !is_child_process() {
            run_in_child_process("vm_error::tests::test_other_panic_in_vm_runtime_reaches_host_hook");
            return;
        }
        let host_panic_count = install_counting_host_hook();

        let payload = try_vm_runtime(|| panic!("a bug in the VM")).expect_err("The panic should be caught");
        assert_eq!(panic_message(&*payload), Some("a bug in the VM"));
        assert_eq!(host_panic_count.load(Ordering::SeqCst), 1, "The panic should reach the host hook");
    }

    /// A halt outside `try_vm_runtime` is still a halt, because `vm_halt` installs the hook itself.
    #[test]
    fn test_halt_outside_vm_runtime_skips_host_hook() {
        if !is_child_process() {
            run_in_child_process("vm_error::tests::test_halt_outside_vm_runtime_skips_host_hook");
            return;
        }
        let host_panic_count = Arc::new(AtomicUsize::new(0));
        let host_panic_count_ = host_panic_count.clone();
        panic::set_hook(Box::new(move |_| {
            host_panic_count_.fetch_add(1, Ordering::SeqCst);
        }));

        let payload = panic::catch_unwind(|| vm_halt("a halt outside the VM runtime".to_string()))
            .expect_err("The halt should unwind");
        assert_eq!(halt_message(&*payload), "a halt outside the VM runtime");
        assert_eq!(host_panic_count.load(Ordering::SeqCst), 0, "The halt should not reach the host hook");
    }

    /// Halts on rayon workers skip the host hook, and their payload reaches `try_vm_runtime` on the waiting thread.
    #[test]
    fn test_halt_on_rayon_worker_skips_host_hook() {
        if !is_child_process() {
            run_in_child_process("vm_error::tests::test_halt_on_rayon_worker_skips_host_hook");
            return;
        }
        let host_panic_count = install_counting_host_hook();

        // This thread is not in the pool, so the job runs on the pool's worker.
        let pool = rayon::ThreadPoolBuilder::new().num_threads(1).build().expect("Failed to build the thread pool");
        let payload = try_vm_runtime(|| pool.install(|| vm_halt("VM halt on a worker".to_string())))
            .expect_err("The halt should be caught");
        assert_eq!(halt_message(&*payload), "VM halt on a worker");
        assert_eq!(host_panic_count.load(Ordering::SeqCst), 0, "The halt should not reach the host hook");

        // A VM operation on a worker halts in both jobs of a join. The barrier holds each job until the other one
        // runs on the other worker.
        let pool = rayon::ThreadPoolBuilder::new().num_threads(2).build().expect("Failed to build the thread pool");
        let barrier = Barrier::new(2);
        let halt = || {
            barrier.wait();
            vm_halt("VM halt in a join".to_string())
        };
        let payload =
            pool.install(|| try_vm_runtime(|| rayon::join(halt, halt))).expect_err("The halts should be caught");
        assert_eq!(halt_message(&*payload), "VM halt in a join");
        assert_eq!(host_panic_count.load(Ordering::SeqCst), 0, "The halts should not reach the host hook");
    }

    /// A worker that waits on a join inside `try_vm_runtime` runs an unrelated job that panics.
    #[test]
    fn test_job_stolen_by_waiting_vm_thread_reaches_host_hook() {
        if !is_child_process() {
            run_in_child_process("vm_error::tests::test_job_stolen_by_waiting_vm_thread_reaches_host_hook");
            return;
        }
        let host_panic_count = install_counting_host_hook();

        // Rayon calls the panic handler of a spawned job after the panic hook has run.
        let (unrelated_unwound_tx, unrelated_unwound_rx) = mpsc::channel();
        let pool = Arc::new(
            rayon::ThreadPoolBuilder::new()
                .num_threads(2)
                .panic_handler(move |_| {
                    let _ = unrelated_unwound_tx.send(());
                })
                .build()
                .expect("Failed to build the thread pool"),
        );
        let (second_job_started_tx, second_job_started_rx) = mpsc::channel();
        let (spawn_now_tx, spawn_now_rx) = mpsc::channel();
        let (unrelated_ran_tx, unrelated_ran_rx) = mpsc::channel();

        // Injects the unrelated job once the VM thread is about to wait.
        let pool_ = pool.clone();
        let spawner = thread::spawn(move || {
            spawn_now_rx.recv().expect("The VM thread should signal the spawn");
            pool_.spawn(move || {
                unrelated_ran_tx.send(rayon::current_thread_index()).expect("The second job should be waiting");
                panic!("unrelated panic in a stolen job");
            });
        });

        let (vm_thread, stolen_on) = pool.install(move || {
            let vm_thread = rayon::current_thread_index();
            let stolen_on = try_vm_runtime(move || {
                let ((), stolen_on) = rayon::join(
                    move || {
                        // The other worker runs the second job, so this thread then waits on it.
                        second_job_started_rx.recv().expect("The second job should start");
                        spawn_now_tx.send(()).expect("The spawner should be waiting");
                    },
                    move || {
                        second_job_started_tx.send(()).expect("The first job should be waiting");
                        // The other worker is busy until the unrelated job has run on the waiting thread.
                        unrelated_ran_rx.recv().expect("The unrelated job should run")
                    },
                );
                stolen_on
            })
            .expect("The VM operation should not panic");
            (vm_thread, stolen_on)
        });
        spawner.join().expect("The spawner should not panic");
        unrelated_unwound_rx.recv_timeout(Duration::from_secs(10)).expect("The unrelated job should unwind");

        assert_eq!(stolen_on, vm_thread, "The unrelated job should run on the waiting VM thread");
        assert_eq!(host_panic_count.load(Ordering::SeqCst), 1, "The unrelated panic should reach the host hook");
    }
}
