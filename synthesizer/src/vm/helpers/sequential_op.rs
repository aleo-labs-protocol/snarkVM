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

use crate::vm::*;
use console::network::prelude::Network;

#[cfg(feature = "announce-blocks")]
use std::net::{SocketAddr, TcpStream};
use std::{fmt, thread};
use tokio::sync::oneshot;
#[cfg(feature = "announce-blocks")]
use tracing::*;

impl<N: Network, C: ConsensusStorage<N>> VM<N, C> {
    /// Launches a thread dedicated to the sequential processing of storage-related
    /// operations.
    pub fn start_sequential_queue(
        &self,
        request_rx: mpsc::Receiver<SequentialOperationRequest<N>>,
    ) -> thread::JoinHandle<()> {
        #[cfg(feature = "announce-blocks")]
        let mut stream = start_block_announcement_stream();

        // Spawn a dedicated thread.
        // The worker must not own the sender that keeps its receive loop alive.
        // Only external VM clones own the queue and join it when the last clone drops.
        let mut vm = self.clone();
        vm.sequential_ops_tx = None;
        thread::spawn(move || {
            // Sequentially process incoming operations.
            while let Ok(request) = request_rx.recv() {
                let SequentialOperationRequest { op, response_tx } = request;
                trace!("Sequentially processing operation '{op}'");

                // Perform the queued operation.
                let ret = match op {
                    SequentialOperation::AddNextBlock(block) => {
                        #[cfg(feature = "announce-blocks")]
                        let announcement = (block.height(), bincode::serialize(&block));
                        let ret = vm.add_next_block_inner(block);
                        #[cfg(feature = "announce-blocks")]
                        if ret.is_ok()
                            && let Err(e) = announce_block(&mut stream, announcement)
                        {
                            error!("Block announcement error: {e}");
                            // Attempt to restart the stream.
                            stream = start_block_announcement_stream();
                        }
                        SequentialOperationResult::AddNextBlock(ret)
                    }
                    SequentialOperation::AtomicSpeculate(a, b, c, d, e, f) => {
                        let ret = vm.atomic_speculate_inner(a, b, c, d, e, f);
                        SequentialOperationResult::AtomicSpeculate(ret)
                    }
                };

                // Relay the results of the operation to the caller.
                let _ = response_tx.send(ret);
            }
        })
    }

    /// Sends the given operation to the thread used for sequential processing.
    pub fn run_sequential_operation(&self, op: SequentialOperation<N>) -> Option<SequentialOperationResult<N>> {
        trace!("Queuing operation '{op}' for sequential processing");

        // Prepare a oneshot channel to obtain the result of the queued operation.
        let (response_tx, response_rx) = oneshot::channel();
        let request = SequentialOperationRequest { op, response_tx };

        // This pattern match is infallible unless already shutting down the thread.
        if let Some(queue) = &self.sequential_ops_tx {
            // Send the operation to be processed sequentially.
            let _ = queue.sender.as_ref()?.send(request);

            // Wait for the result of the queued operation. This is a blocking method,
            // and will panic in async contexts (which doesn't happen in production, as
            // we already perform all these operations within blocking tasks).
            let Ok(response) = response_rx.blocking_recv() else {
                return None;
            };

            Some(response)
        } else {
            None
        }
    }

    /// A safeguard used to ensure that the given operation is processed in the thread
    /// enforcing sequential processing of operations.
    pub fn ensure_sequential_processing(&self) {
        assert_eq!(
            thread::current().id(),
            *self.sequential_ops_thread_id.get().expect("Sequential ops thread not initialized")
        );
    }
}

/// An operation intended to be executed only in a sequential fashion.
pub enum SequentialOperation<N: Network> {
    AddNextBlock(Block<N>),
    AtomicSpeculate(FinalizeGlobalState, i64, Option<u64>, Vec<Ratify<N>>, Solutions<N>, Vec<Transaction<N>>),
}

impl<N: Network> fmt::Display for SequentialOperation<N> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SequentialOperation::AddNextBlock(block) => {
                write!(f, "add block ({})", block.hash())
            }
            SequentialOperation::AtomicSpeculate(state, ..) => {
                write!(f, "atomic speculate (height {}, round {})", state.block_height(), state.block_round())
            }
        }
    }
}

/// A sequential operation paired with a oneshot sender used to return its result.
pub struct SequentialOperationRequest<N: Network> {
    op: SequentialOperation<N>,
    response_tx: oneshot::Sender<SequentialOperationResult<N>>,
}

/// Represents the results of all the sequential operations.
pub enum SequentialOperationResult<N: Network> {
    AddNextBlock(Result<()>),
    AtomicSpeculate(
        Result<(
            Ratifications<N>,
            Vec<ConfirmedTransaction<N>>,
            Vec<(Transaction<N>, String)>,
            Vec<FinalizeOperation<N>>,
        )>,
    ),
}

/// Owned only by external VM clones. Arc runs this destructor exactly once,
/// including when the final clones are dropped concurrently.
pub(crate) struct SequentialOperationQueue<N: Network> {
    pub(crate) sender: Option<mpsc::Sender<SequentialOperationRequest<N>>>,
    pub(crate) thread: Option<thread::JoinHandle<()>>,
}

impl<N: Network> Drop for SequentialOperationQueue<N> {
    fn drop(&mut self) {
        // Closing the last sender drains queued operations and terminates the worker.
        self.sender.take();
        if let Some(thread) = self.thread.take() {
            trace!("Waiting for sequential ops thread to terminate");
            // Dropping a VM may itself run during unwinding. A worker panic
            // must not become a second panic and abort the process.
            if thread.join().is_err() {
                error!("Sequential ops thread panicked");
            }
        }
    }
}

#[cfg(feature = "announce-blocks")]
fn start_block_announcement_stream() -> Option<TcpStream> {
    let addr = std::env::var("BLOCK_ANNOUNCE_ADDR")
        .map_err(|_| {
            warn!("BLOCK_ANNOUNCE_ADDR env variable must be set in order to publish blocks via TCP");
        })
        .ok()?
        .parse::<SocketAddr>()
        .expect("Invalid socket address provided as the BLOCK_ANNOUNCE_ADDR");

    match TcpStream::connect(addr) {
        Ok(stream) => {
            // Avoid Nagle-induced delays in delivering announcements.
            if let Err(e) = stream.set_nodelay(true) {
                warn!("Couldn't set TCP_NODELAY on the block announcement stream: {e}");
            }
            debug!("Successfully (re)started the TCP stream for block announcements");
            Some(stream)
        }
        Err(e) => {
            warn!("Couldn't (re)start the TCP stream for block announcements: {e}");
            None
        }
    }
}

#[cfg(feature = "announce-blocks")]
fn announce_block(
    stream: &mut Option<TcpStream>,
    payload: (u32, Result<Vec<u8>, Box<bincode::ErrorKind>>),
) -> Result<bool> {
    if let Some(stream) = stream {
        let (block_height, serialized_block) = payload;
        let block_bytes = serialized_block?;
        debug!("Announcing block {block_height} to the TCP stream");
        let payload_size = u32::try_from(std::mem::size_of::<u32>() + block_bytes.len()).unwrap(); // Safe - blocks are smaller than 4GiB.
        stream.write_all(&payload_size.to_le_bytes())?;
        stream.write_all(&block_height.to_le_bytes())?;
        stream.write_all(&block_bytes)?;

        Ok(true)
    } else {
        *stream = start_block_announcement_stream();
        if stream.is_some() { announce_block(stream, payload) } else { Ok(false) }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use aleo_std::StorageMode;
    use console::network::MainnetV0;
    use snarkvm_ledger_store::helpers::memory::ConsensusMemory;

    fn queue_with_panicking_worker() -> SequentialOperationQueue<MainnetV0> {
        SequentialOperationQueue { sender: None, thread: Some(thread::spawn(|| panic!("worker failed"))) }
    }

    #[test]
    fn dropping_panicked_worker_does_not_panic() {
        assert!(std::panic::catch_unwind(|| drop(queue_with_panicking_worker())).is_ok());
    }

    #[test]
    fn dropping_panicked_worker_during_unwind_preserves_original_panic() {
        let error = std::panic::catch_unwind(|| {
            let _queue = queue_with_panicking_worker();
            panic!("original panic");
        })
        .unwrap_err();
        assert_eq!(error.downcast_ref::<&str>(), Some(&"original panic"));
    }

    #[test]
    fn concurrent_final_drop_drains_queued_operations() {
        let store = ConsensusStore::<MainnetV0, ConsensusMemory<MainnetV0>>::open(StorageMode::Production).unwrap();
        let vm = VM::from(store).unwrap();
        let process = Arc::downgrade(vm.process());
        // Keep the worker blocked on its Process lock until queued requests and
        // the final external clones are all ready, without timing assumptions.
        let process_owner = vm.process().clone();
        let process_guard = process_owner.lock();
        let state = FinalizeGlobalState::new_genesis::<MainnetV0>().unwrap();
        let responses = (0..8)
            .map(|_| {
                let (response_tx, response_rx) = oneshot::channel();
                let op = SequentialOperation::AtomicSpeculate(state, 0, None, vec![], Solutions::from(None), vec![]);
                vm.sequential_ops_tx
                    .as_ref()
                    .unwrap()
                    .sender
                    .as_ref()
                    .unwrap()
                    .send(SequentialOperationRequest { op, response_tx })
                    .unwrap();
                response_rx
            })
            .collect::<Vec<_>>();

        let barrier = Arc::new(std::sync::Barrier::new(5));
        thread::scope(|scope| {
            for _ in 0..4 {
                let vm = vm.clone();
                let barrier = barrier.clone();
                scope.spawn(move || {
                    barrier.wait();
                    drop(vm);
                });
            }
            drop(vm);
            barrier.wait();
            drop(process_guard);
        });
        drop(process_owner);
        assert!(process.upgrade().is_none());
        for response in responses {
            assert!(matches!(response.blocking_recv().unwrap(), SequentialOperationResult::AtomicSpeculate(Ok(_))));
        }
    }
}
