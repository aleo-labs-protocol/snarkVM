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

use std::{
    any::Any,
    fmt,
    panic,
    sync::{
        Once,
        atomic::{AtomicUsize, Ordering},
    },
};

/// The panic payload of a VM halt.
///
/// Console and circuit operations halt by panicking with this payload, for example on a division by zero or on an
/// invalid group element. So do the functions that run a program, such as `Process::authorize`, `Process::execute`
/// and `Process::deploy`, when the program halts.
///
/// A caller that must not unwind catches the panic and checks the payload type. Any other payload is a bug, and the
/// caller keeps unwinding:
///
/// ```
/// use snarkvm_utilities::VmHalt;
/// use std::panic::{UnwindSafe, catch_unwind, resume_unwind};
///
/// fn run<T>(operation: impl FnOnce() -> T + UnwindSafe) -> Result<T, String> {
///     catch_unwind(operation).map_err(|payload| match payload.downcast::<VmHalt>() {
///         Ok(halt) => format!("the program halted: {halt}"),
///         Err(payload) => resume_unwind(payload),
///     })
/// }
///
/// assert_eq!(run(|| 1 + 1), Ok(2));
/// ```
///
/// The payload travels with the panic, also when rayon re-raises the panic of a job on the thread that waits on the
/// job. Panic hooks and code that read only `String` and `&str` payloads do not see the message of a halt;
/// [`panic_message`] reads all three.
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

/// Returns the message of a panic payload that is a [`VmHalt`], a `String` or a `&str`.
pub fn panic_message(payload: &(dyn Any + Send)) -> Option<&str> {
    payload
        .downcast_ref::<VmHalt>()
        .map(VmHalt::message)
        .or_else(|| payload.downcast_ref::<String>().map(String::as_str))
        .or_else(|| payload.downcast_ref::<&str>().copied())
}

/// Ensures the VM halt hook is installed exactly once.
static INSTALL_VM_HALT_HOOK: Once = Once::new();

/// The number of [`try_vm_runtime`] calls that are running, on any thread.
static ACTIVE_VM_RUNTIMES: AtomicUsize = AtomicUsize::new(0);

/// Installs a panic hook for VM halts, which passes every other panic to the previous hook.
///
/// While any [`try_vm_runtime`] call runs, the hook logs a halt at the debug level, without a backtrace, because the
/// halt is likely an expected outcome that the call catches. A halt message can hold private values, so only debug
/// builds log it.
///
/// While no [`try_vm_runtime`] call runs, nothing in snarkVM catches the halt. The hook logs the halt with its message
/// at the error level, or prints it to stderr if no tracing subscriber is set, and then passes it to the previous
/// hook. The previous hook does not see the message, because panic hooks format only `String` and `&str` payloads.
///
/// A halt on a thread outside [`try_vm_runtime`] while another thread is inside one is only logged at the debug
/// level, even if no caller catches it.
fn install_vm_halt_hook() {
    INSTALL_VM_HALT_HOOK.call_once(|| {
        let previous_hook = panic::take_hook();

        panic::set_hook(Box::new(move |info| {
            let Some(halt) = info.payload().downcast_ref::<VmHalt>() else {
                return previous_hook(info);
            };
            let location = info.location().map_or_else(|| "an unknown location".to_string(), ToString::to_string);
            if ACTIVE_VM_RUNTIMES.load(Ordering::SeqCst) > 0 {
                #[cfg(debug_assertions)]
                tracing::debug!("VM halted at {location}: {halt}");
                #[cfg(not(debug_assertions))]
                tracing::debug!("VM halted at {location}");
            } else {
                if tracing::dispatcher::has_been_set() {
                    tracing::error!("VM halted at {location}: {halt}");
                } else {
                    eprintln!("VM halted at {location}: {halt}");
                }
                previous_hook(info);
            }
        }));
    });
}

/// Halts the VM with the given message, by panicking with a [`VmHalt`] payload.
///
/// Panic hooks should be installed before the first halt or [`try_vm_runtime`], because the VM halt hook passes
/// panics to the hook that was present then.
///
/// It is public for other snarkVM crates, but it is not part of the API, and semver does not cover it.
#[doc(hidden)]
#[cold]
#[track_caller]
pub fn vm_halt(message: String) -> ! {
    install_vm_halt_hook();
    panic::panic_any(VmHalt { message })
}

/// Counts a running [`try_vm_runtime`] call until it drops.
struct ActiveVmRuntime;

impl ActiveVmRuntime {
    fn enter() -> Self {
        ACTIVE_VM_RUNTIMES.fetch_add(1, Ordering::SeqCst);
        Self
    }
}

impl Drop for ActiveVmRuntime {
    fn drop(&mut self) {
        ACTIVE_VM_RUNTIMES.fetch_sub(1, Ordering::SeqCst);
    }
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

    let _active = ActiveVmRuntime::enter();
    panic::catch_unwind(panic::AssertUnwindSafe(f))
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

    /// A halt while no `try_vm_runtime` runs reaches the host hook, also before the first `try_vm_runtime` and after a
    /// caught halt.
    #[test]
    fn test_halt_outside_vm_runtime_reaches_host_hook() {
        if !is_child_process() {
            let output = run_in_child_process("vm_error::tests::test_halt_outside_vm_runtime_reaches_host_hook");
            // The child sets no tracing subscriber, so the hook prints the messages of the uncaught halts.
            let stderr = String::from_utf8_lossy(&output.stderr);
            assert!(stderr.contains(": a halt before any VM runtime"), "Unexpected stderr:\n{stderr}");
            assert!(stderr.contains(": a halt after the VM runtime"), "Unexpected stderr:\n{stderr}");
            assert!(!stderr.contains("a caught halt"), "Unexpected stderr:\n{stderr}");
            return;
        }
        let host_panic_count = Arc::new(AtomicUsize::new(0));
        let host_panic_count_ = host_panic_count.clone();
        panic::set_hook(Box::new(move |_| {
            host_panic_count_.fetch_add(1, Ordering::SeqCst);
        }));

        // `vm_halt` installs the VM halt hook on top of the host hook.
        let payload = panic::catch_unwind(|| vm_halt("a halt before any VM runtime".to_string()))
            .expect_err("The halt should unwind");
        assert_eq!(halt_message(&*payload), "a halt before any VM runtime");
        assert_eq!(host_panic_count.load(Ordering::SeqCst), 1, "The halt should reach the host hook");

        let payload = try_vm_runtime(|| vm_halt("a caught halt".to_string())).expect_err("The halt should be caught");
        assert_eq!(halt_message(&*payload), "a caught halt");
        assert_eq!(host_panic_count.load(Ordering::SeqCst), 1, "The caught halt should not reach the host hook");

        let payload = panic::catch_unwind(|| vm_halt("a halt after the VM runtime".to_string()))
            .expect_err("The halt should unwind");
        assert_eq!(halt_message(&*payload), "a halt after the VM runtime");
        assert_eq!(host_panic_count.load(Ordering::SeqCst), 2, "The halt should reach the host hook");
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
