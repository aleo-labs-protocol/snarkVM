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

#![allow(clippy::disallowed_types)]

#[cfg(locktick)]
pub use locktick::lock_snapshots;

/// A mutual exclusion lock.
#[cfg(not(locktick))]
pub type Mutex<T> = parking_lot::Mutex<T>;
/// A mutual exclusion lock.
#[cfg(locktick)]
pub type Mutex<T> = locktick::parking_lot::Mutex<T>;

/// A reader-writer lock.
#[cfg(not(locktick))]
pub type RwLock<T> = parking_lot::RwLock<T>;
/// A reader-writer lock.
#[cfg(locktick)]
pub type RwLock<T> = locktick::parking_lot::RwLock<T>;

/// The guard that [`Mutex::lock`] returns.
#[cfg(not(locktick))]
pub type MutexGuard<'a, T> = parking_lot::MutexGuard<'a, T>;
/// The guard that [`Mutex::lock`] returns.
#[cfg(locktick)]
pub type MutexGuard<'a, T> = locktick::LockGuard<parking_lot::MutexGuard<'a, T>>;

/// The guard that [`RwLock::read`] returns.
#[cfg(not(locktick))]
pub type RwLockReadGuard<'a, T> = parking_lot::RwLockReadGuard<'a, T>;
/// The guard that [`RwLock::read`] returns.
#[cfg(locktick)]
pub type RwLockReadGuard<'a, T> = locktick::LockGuard<parking_lot::RwLockReadGuard<'a, T>>;

/// The guard that [`RwLock::write`] returns.
#[cfg(not(locktick))]
pub type RwLockWriteGuard<'a, T> = parking_lot::RwLockWriteGuard<'a, T>;
/// The guard that [`RwLock::write`] returns.
#[cfg(locktick)]
pub type RwLockWriteGuard<'a, T> = locktick::LockGuard<parking_lot::RwLockWriteGuard<'a, T>>;
