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

/// Returns a `TRACE` span for timing a region of code, with the target `timing::<module path>`.
/// The arguments are the name and the fields of the span, as in [`tracing::trace_span!`].
///
/// The span measures the time between entering it and dropping its guard:
/// ```
/// let timer = snarkvm_utilities::timing_span!("Compute", size = 8).entered();
/// snarkvm_utilities::timing_event!("Hashed {} leaves", 8);
/// drop(timer);
/// ```
///
/// A guard is bound to the thread that entered it, and must not be held across an `.await`.
#[macro_export]
macro_rules! timing_span {
    ($($args:tt)*) => {
        $crate::tracing::trace_span!(target: concat!("timing::", module_path!()), $($args)*)
    };
}

/// Emits a `TRACE` event that marks a step inside a timing span, with the target `timing::<module path>`.
/// The arguments are the fields and the message of the event, as in [`tracing::trace!`].
#[macro_export]
macro_rules! timing_event {
    ($($args:tt)*) => {
        $crate::tracing::trace!(target: concat!("timing::", module_path!()), $($args)*)
    };
}

#[cfg(test)]
mod tests {
    use std::{
        cell::Cell,
        io,
        sync::{Arc, Mutex},
    };
    use tracing_subscriber::{EnvFilter, fmt::format::FmtSpan, util::SubscriberInitExt};

    /// A writer that appends to a shared buffer.
    #[derive(Clone, Default)]
    struct Buffer(Arc<Mutex<Vec<u8>>>);

    impl io::Write for Buffer {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            // The lock is only poisoned if another writer panicked, which fails the test regardless.
            self.0.lock().unwrap().extend_from_slice(bytes);
            Ok(bytes.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    /// Runs `f` and returns the output of a subscriber that accepts `filter` and logs when a span closes.
    fn capture(filter: &str, f: impl Fn()) -> String {
        let buffer = Buffer::default();
        let writer = buffer.clone();
        let guard = tracing_subscriber::fmt()
            .with_env_filter(EnvFilter::new(filter))
            .with_span_events(FmtSpan::CLOSE)
            .with_ansi(false)
            .with_writer(move || writer.clone())
            .set_default();
        // `tracing` caches whether a callsite is enabled, and a callsite that another thread registered stays disabled.
        // The first run registers each callsite of `f`. The rebuild then asks this subscriber about each callsite.
        f();
        tracing::callsite::rebuild_interest_cache();
        // The lock is only poisoned if a writer panicked, which fails the test regardless.
        buffer.0.lock().unwrap().clear();
        f();
        drop(guard);
        // The lock is only poisoned if a writer panicked, which fails the test regardless.
        let bytes = buffer.0.lock().unwrap().clone();
        // The formatter only writes UTF-8.
        String::from_utf8(bytes).unwrap()
    }

    fn timed(evaluated: &Cell<bool>) {
        let timer = timing_span!("Outer", size = 8).entered();
        timing_event!("Hashed {} leaves", {
            evaluated.set(true);
            8
        });
        drop(timer);
    }

    #[test]
    fn test_timing_span_and_event_are_emitted() {
        let evaluated = Cell::new(false);
        let output = capture("timing=trace", || timed(&evaluated));
        assert!(evaluated.get());

        let mut lines = output.lines();
        // The event carries the name and the fields of the span that it is in.
        let event = lines.next().unwrap();
        assert!(event.contains("TRACE Outer{size=8}: timing::snarkvm_utilities::timing::tests: Hashed 8 leaves"));
        // The span reports its duration when it closes.
        let close = lines.next().unwrap();
        assert!(close.contains("TRACE Outer{size=8}: timing::snarkvm_utilities::timing::tests: close time.busy="));
        assert!(lines.next().is_none());
    }

    #[test]
    fn test_timing_is_skipped_when_not_enabled() {
        let evaluated = Cell::new(false);
        // A filter on the crate does not enable the `timing` targets.
        let output = capture("snarkvm_utilities=trace", || timed(&evaluated));
        assert!(!evaluated.get());
        assert!(output.is_empty());
    }
}
