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

//! The lock types that snarkVM uses.
//!
//! These are `parking_lot`'s locks and guards. Under `--cfg locktick` they are `locktick`'s
//! wrappers, which record where each lock is created and acquired. The `locktick-` cargo aliases
//! in `.cargo/config.toml`, such as `cargo locktick-clippy`, set the cfg.
//!
//! `clippy.toml` disallows the `parking_lot` and `locktick` lock types everywhere else.

#![allow(clippy::disallowed_types)]

#[cfg(locktick)]
use locktick::parking_lot as backend;
#[cfg(not(locktick))]
use parking_lot as backend;

#[cfg(not(locktick))]
type Guard<G> = G;
#[cfg(locktick)]
type Guard<G> = locktick::LockGuard<G>;

/// A mutual exclusion lock.
pub type Mutex<T> = backend::Mutex<T>;

/// A reader-writer lock.
pub type RwLock<T> = backend::RwLock<T>;

/// The guard that [`Mutex::lock`] returns.
pub type MutexGuard<'a, T> = Guard<parking_lot::MutexGuard<'a, T>>;

/// The guard that [`RwLock::read`] returns.
pub type RwLockReadGuard<'a, T> = Guard<parking_lot::RwLockReadGuard<'a, T>>;

/// The guard that [`RwLock::write`] returns.
pub type RwLockWriteGuard<'a, T> = Guard<parking_lot::RwLockWriteGuard<'a, T>>;
