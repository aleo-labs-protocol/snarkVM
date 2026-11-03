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
#![warn(clippy::cast_possible_truncation)]

#[cfg(feature = "batch-certificate")]
pub use snarkvm_ledger_narwhal_batch_certificate as batch_certificate;
#[cfg(feature = "batch-certificate")]
pub use snarkvm_ledger_narwhal_batch_certificate::BatchCertificate;

#[cfg(feature = "batch-header")]
pub use snarkvm_ledger_narwhal_batch_header as batch_header;
#[cfg(feature = "batch-header")]
pub use snarkvm_ledger_narwhal_batch_header::BatchHeader;

#[cfg(feature = "data")]
pub use snarkvm_ledger_narwhal_data as data;
#[cfg(feature = "data")]
pub use snarkvm_ledger_narwhal_data::{DATA_ENCODING_OVERHEAD, Data};

#[cfg(feature = "subdag")]
pub use snarkvm_ledger_narwhal_subdag as subdag;
#[cfg(feature = "subdag")]
pub use snarkvm_ledger_narwhal_subdag::Subdag;

#[cfg(feature = "transmission")]
pub use snarkvm_ledger_narwhal_transmission as transmission;
#[cfg(feature = "transmission")]
pub use snarkvm_ledger_narwhal_transmission::Transmission;

#[cfg(feature = "transmission-id")]
pub use snarkvm_ledger_narwhal_transmission_id as transmission_id;
#[cfg(feature = "transmission-id")]
pub use snarkvm_ledger_narwhal_transmission_id::TransmissionID;
