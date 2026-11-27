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

#![forbid(unsafe_code)]

mod names;
mod report;
mod scan;
mod stats;

pub use names::map_label;
pub use report::{Gauge, ReportHeader, render};
pub use scan::{count_live_keys, count_memtable_ops};
pub use stats::{
    Attribution,
    MapKey,
    MapStats,
    OpCounts,
    SstFile,
    attribute_ssts,
    estimate_num_keys,
    map_prefix,
    spans_maps,
    sst_estimated_active_keys,
    unflushed_ops,
};
