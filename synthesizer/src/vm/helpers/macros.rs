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

/// A helper macro to downcast a `$variable` to `$object<$network>`.
#[macro_export]
macro_rules! cast_ref {
    // Example: cast_ref!((foo.bar()) as Bar<MainnetV0>)
    (($variable:expr) as $object:ident<$($traits:path),+>) => {{
        (&$variable as &dyn std::any::Any)
            .downcast_ref::<$object<$($traits),+>>()
            .ok_or_else(|| anyhow!("Failed to downcast {}", stringify!($variable)))?
    }};
    // Example: cast_ref!(bar as Bar<MainnetV0>)
    ($variable:ident as $object:ident<$($traits:path),+>) => {{
        (&$variable as &dyn std::any::Any)
            .downcast_ref::<$object<$($traits),+>>()
            .ok_or_else(|| anyhow!("Failed to downcast {}", stringify!($variable)))?
    }};
    // Example: cast_ref!(&bar as Bar<MainnetV0>)
    (&$variable:ident as $object:ident<$($traits:path),+>) => {{
        ($variable as &dyn std::any::Any)
            .downcast_ref::<$object<$($traits),+>>()
            .ok_or_else(|| anyhow!("Failed to downcast {}", stringify!($variable)))?
    }};
}

/// A helper macro to downcast a `$variable` to `&mut $object<$network>`.
#[macro_export]
macro_rules! cast_mut_ref {
    // Example: cast_mut_ref!((foo.bar()) as Bar<MainnetV0>)
    (($variable:expr) as $object:ident<$($traits:path),+>) => {{
        (&mut $variable as &mut dyn std::any::Any)
            .downcast_mut::<$object<$($traits),+>>()
            .ok_or_else(|| anyhow!("Failed to downcast mut {}", stringify!($variable)))?
    }};
    // Example: cast_mut_ref!(bar as Bar<MainnetV0>)
    ($variable:ident as $object:ident<$($traits:path),+>) => {{
        (&mut $variable as &mut dyn std::any::Any)
            .downcast_mut::<$object<$($traits),+>>()
            .ok_or_else(|| anyhow!("Failed to downcast mut {}", stringify!($variable)))?
    }};
}

/// A helper macro to dedup the `Network` trait and `Aleo` trait and process its given logic.
#[macro_export]
macro_rules! convert {
    // Example: convert!(logic)
    ($logic:ident) => {{
        match N::ID {
            console::network::MainnetV0::ID => {
                // Process the logic.
                $logic!(console::network::MainnetV0, circuit::AleoV0)
            }
            console::network::TestnetV0::ID => {
                // Process the logic.
                $logic!(console::network::TestnetV0, circuit::AleoTestnetV0)
            }
            console::network::CanaryV0::ID => {
                // Process the logic.
                $logic!(console::network::CanaryV0, circuit::AleoCanaryV0)
            }
            _ => return Err(anyhow!("Unsupported VM configuration for network: {}", N::ID).into()),
        }
    }};
}

/// A helper macro to dedup the `Network` trait and `Aleo` trait and process its given logic.
#[macro_export]
macro_rules! process {
    // Example: process!(self, logic)
    ($self:ident, $logic:ident) => {{
        match N::ID {
            console::network::MainnetV0::ID => {
                // Cast the process.
                let process = (&$self.process as &dyn std::any::Any)
                    .downcast_ref::<Arc<Process<console::network::MainnetV0>>>()
                    .ok_or_else(|| anyhow!("Failed to downcast {}", stringify!($self.process)))?;
                // Process the logic.
                $logic!(process, console::network::MainnetV0, circuit::AleoV0)
            }
            console::network::TestnetV0::ID => {
                // Cast the process.
                let process = (&$self.process as &dyn std::any::Any)
                    .downcast_ref::<Arc<Process<console::network::TestnetV0>>>()
                    .ok_or_else(|| anyhow!("Failed to downcast {}", stringify!($self.process)))?;
                // Process the logic.
                $logic!(process, console::network::TestnetV0, circuit::AleoTestnetV0)
            }
            console::network::CanaryV0::ID => {
                // Cast the process.
                let process = (&$self.process as &dyn std::any::Any)
                    .downcast_ref::<Arc<Process<console::network::CanaryV0>>>()
                    .ok_or_else(|| anyhow!("Failed to downcast {}", stringify!($self.process)))?;
                // Process the logic.
                $logic!(process, console::network::CanaryV0, circuit::AleoCanaryV0)
            }
            _ => return Err(anyhow!("Unsupported VM configuration for network: {}", N::ID).into()),
        }
    }};
}
