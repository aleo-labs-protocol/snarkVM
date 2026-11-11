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

use std::time::{Duration, Instant};

/// How often a long pass logs its progress.
const REPORT_INTERVAL: Duration = Duration::from_secs(10);

/// Counts the units of a long pass done out of its total, and says when a progress line is due.
pub(crate) struct Progress {
    total: usize,
    done: usize,
    timer: Instant,
    next_report: Duration,
}

impl Progress {
    pub(crate) fn new(total: usize) -> Self {
        Self { total, done: 0, timer: Instant::now(), next_report: REPORT_INTERVAL }
    }

    /// Counts `n` more units done. Returns the seconds elapsed and the seconds estimated to remain
    /// when a progress line is due, which is never after the last unit.
    pub(crate) fn advance(&mut self, n: usize) -> Option<(f64, f64)> {
        self.done += n;
        let elapsed = self.timer.elapsed();
        if elapsed < self.next_report || self.done >= self.total {
            return None;
        }
        self.next_report = elapsed + REPORT_INTERVAL;
        let elapsed = elapsed.as_secs_f64();
        Some((elapsed, elapsed * (self.total - self.done) as f64 / self.done as f64))
    }

    pub(crate) fn done(&self) -> usize {
        self.done
    }

    pub(crate) fn elapsed_secs(&self) -> f64 {
        self.timer.elapsed().as_secs_f64()
    }
}
