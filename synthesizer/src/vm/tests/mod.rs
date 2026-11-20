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

mod old_versions {
    use super::*;

    mod test_v10;
    mod test_v11;
    mod test_v13;
    mod test_v14;
    mod test_v8;
    mod test_v9;
}

mod test_v15;
mod test_v16;
mod test_v18;
mod test_v20;
mod test_v22;
mod test_v23;

// Tests for the deployment freeze, enforced from `DEPLOYMENT_FREEZE_CONSENSUS_VERSION`.
mod test_deployment_freeze;

use super::*;
use crate::vm::test_helpers::*;
