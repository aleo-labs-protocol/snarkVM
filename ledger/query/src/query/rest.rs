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

use crate::QueryTrait;

use snarkvm_console::{
    network::Network,
    program::{ProgramID, StatePath},
    types::Field,
};
use snarkvm_ledger_block::Transaction;
use snarkvm_synthesizer_program::Program;

use anyhow::{Context, Result, anyhow, bail, ensure};
use serde::{Deserialize, de::DeserializeOwned};
use ureq::http::{self, uri};

use std::{str::FromStr, time::Duration};

/// How long to wait for a connection to be established, TLS handshake included.
const DEFAULT_CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

/// How long an answer may take to begin, and then how long its body may take; on the async path,
/// how long it may go without delivering more of itself.
const DEFAULT_STALL_TIMEOUT: Duration = Duration::from_secs(30);

/// How long a whole request may take, whatever its phases do.
const DEFAULT_TOTAL_TIMEOUT: Duration = Duration::from_secs(300);

/// Queries that use a node's REST API as their source of information.
///
/// Cloning is cheap and shares the underlying connections: `ureq::Agent` and
/// `reqwest::Client` are both handles onto a pool.
#[derive(Clone)]
pub struct RestQuery<N: Network> {
    base_url: http::Uri,
    /// The bounds every request runs under; see [`Self::with_timeouts`].
    connect: Duration,
    stall: Duration,
    total: Duration,
    /// Holds the connection pool; built from the bounds above.
    agent: ureq::Agent,
    /// Built on first use, since building one can fail and this type is constructed infallibly;
    /// shared by every clone, so that repeated queries reuse a connection.
    #[cfg(feature = "async")]
    client: std::sync::Arc<std::sync::OnceLock<reqwest::Client>>,
    _marker: std::marker::PhantomData<N>,
}

/// Builds the agent that carries these bounds and its connection pool.
fn agent(connect: Duration, stall: Duration, total: Duration) -> ureq::Agent {
    ureq::Agent::new_with_config(
        ureq::Agent::config_builder()
            .http_status_as_error(false)
            .timeout_connect(Some(connect))
            .timeout_recv_response(Some(stall))
            .timeout_recv_body(Some(stall))
            .timeout_global(Some(total))
            .build(),
    )
}

impl<N: Network> From<http::Uri> for RestQuery<N> {
    fn from(base_url: http::Uri) -> Self {
        Self {
            base_url,
            connect: DEFAULT_CONNECT_TIMEOUT,
            stall: DEFAULT_STALL_TIMEOUT,
            total: DEFAULT_TOTAL_TIMEOUT,
            agent: agent(DEFAULT_CONNECT_TIMEOUT, DEFAULT_STALL_TIMEOUT, DEFAULT_TOTAL_TIMEOUT),
            #[cfg(feature = "async")]
            client: Default::default(),
            _marker: Default::default(),
        }
    }
}

impl<N: Network> RestQuery<N> {
    /// The client shared by every request this query makes, built on first use. Racing callers
    /// may build two with identical configuration; the loser is dropped.
    #[cfg(feature = "async")]
    fn client(&self) -> Result<&reqwest::Client> {
        if let Some(client) = self.client.get() {
            return Ok(client);
        }
        let builder = reqwest::Client::builder();
        // reqwest's wasm `ClientBuilder` has neither method (the browser owns the connection);
        // the total bound is set per request, which both backends support.
        #[cfg(not(any(target_arch = "wasm32", target_arch = "wasm64")))]
        let builder = builder.connect_timeout(self.connect).read_timeout(self.stall);
        let built = builder.build().with_context(|| format!("Failed to build an HTTP client for {}", self.base_url))?;
        Ok(self.client.get_or_init(|| built))
    }

    /// Sets how long each request may take: `connect` to establish the connection, `stall` for the
    /// answer to begin and then for its body (on the async path, between successive reads), `total` overall.
    pub fn with_timeouts(mut self, connect: Duration, stall: Duration, total: Duration) -> Self {
        self.connect = connect;
        self.stall = stall;
        self.total = total;
        self.agent = agent(connect, stall, total);
        #[cfg(feature = "async")]
        {
            self.client = Default::default();
        }
        self
    }
}

/// The serialized REST error sent over the network.
#[derive(Debug, Deserialize)]
pub struct RestError {
    /// The type of error (corresponding to the HTTP status code).
    error_type: String,
    /// The top-level error message.
    message: String,
    /// The chain of errors that led to the top-level error.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    chain: Vec<String>,
}

impl RestError {
    /// Converts a `RestError` into an `anyhow::Error`.
    pub fn parse(self) -> anyhow::Error {
        let mut error: Option<anyhow::Error> = None;
        for next in self.chain.into_iter() {
            if let Some(previous) = error {
                error = Some(previous.context(next));
            } else {
                error = Some(anyhow!(next));
            }
        }

        let toplevel = format!("{}: {}", self.error_type, self.message);
        if let Some(error) = error { error.context(toplevel) } else { anyhow!(toplevel) }
    }
}

/// Initialize the `Query` object from an endpoint URL (passed as a string). The URI should point to a snarkOS node's REST API.
impl<N: Network> FromStr for RestQuery<N> {
    type Err = anyhow::Error;

    fn from_str(str_representation: &str) -> Result<Self> {
        let base_url = str_representation.parse::<http::Uri>().with_context(|| "Failed to parse URL")?;

        // Perform checks.
        if let Some(scheme) = base_url.scheme()
            && *scheme != uri::Scheme::HTTP
            && *scheme != uri::Scheme::HTTPS
        {
            bail!("Invalid scheme in URL: {scheme}");
        }

        if let Some(s) = base_url.host()
            && s.is_empty()
        {
            bail!("Invalid URL for REST endpoint. Empty hostname given.");
        } else if base_url.host().is_none() {
            bail!("Invalid URL for REST endpoint. No hostname given.");
        }

        if base_url.query().is_some() {
            bail!("Base URL for REST endpoints cannot contain a query");
        }

        Ok(Self::from(base_url))
    }
}

#[cfg_attr(feature = "async", async_trait::async_trait(?Send))]
impl<N: Network> QueryTrait<N> for RestQuery<N> {
    /// Returns the current state root.
    fn current_state_root(&self) -> Result<N::StateRoot> {
        self.get_request("stateRoot/latest")
    }

    /// Returns the current state root.
    #[cfg(feature = "async")]
    async fn current_state_root_async(&self) -> Result<N::StateRoot> {
        self.get_request_async("stateRoot/latest").await
    }

    /// Returns a state path for the given `commitment`.
    fn get_state_path_for_commitment(&self, commitment: &Field<N>) -> Result<StatePath<N>> {
        self.get_request(&format!("statePath/{commitment}"))
    }

    /// Returns a state path for the given `commitment`.
    #[cfg(feature = "async")]
    async fn get_state_path_for_commitment_async(&self, commitment: &Field<N>) -> Result<StatePath<N>> {
        self.get_request_async(&format!("statePath/{commitment}")).await
    }

    /// Returns a list of state paths for the given list of `commitment`s.
    fn get_state_paths_for_commitments(&self, commitments: &[Field<N>]) -> Result<Vec<StatePath<N>>> {
        // Zero commitments means zero state paths; some nodes answer an empty `?commitments=`
        // with a 502, and every execution without record inputs reaches here with an empty slice.
        if commitments.is_empty() {
            return Ok(Vec::new());
        }
        // Construct the comma separated string of commitments.
        let commitments_string = commitments.iter().map(|cm| cm.to_string()).collect::<Vec<_>>().join(",");
        self.get_request(&format!("statePaths?commitments={commitments_string}"))
    }

    /// Returns a list of state paths for the given list of `commitment`s.
    #[cfg(feature = "async")]
    async fn get_state_paths_for_commitments_async(&self, commitments: &[Field<N>]) -> Result<Vec<StatePath<N>>> {
        // See `get_state_paths_for_commitments`.
        if commitments.is_empty() {
            return Ok(Vec::new());
        }
        // Construct the comma separated string of commitments.
        let commitments_string = commitments.iter().map(|cm| cm.to_string()).collect::<Vec<_>>().join(",");
        self.get_request_async(&format!("statePaths?commitments={commitments_string}")).await
    }

    /// Returns a state path for the given `commitment`.
    fn current_block_height(&self) -> Result<u32> {
        self.get_request("block/height/latest")
    }

    /// Returns a state path for the given `commitment`.
    #[cfg(feature = "async")]
    async fn current_block_height_async(&self) -> Result<u32> {
        self.get_request_async("block/height/latest").await
    }
}

impl<N: Network> RestQuery<N> {
    /// Returns the transaction for the given transaction ID.
    pub fn get_transaction(&self, transaction_id: &N::TransactionID) -> Result<Transaction<N>> {
        self.get_request(&format!("transaction/{transaction_id}"))
    }

    /// Returns the transaction for the given transaction ID.
    #[cfg(feature = "async")]
    pub async fn get_transaction_async(&self, transaction_id: &N::TransactionID) -> Result<Transaction<N>> {
        self.get_request_async(&format!("transaction/{transaction_id}")).await
    }

    /// Returns the program for the given program ID.
    pub fn get_program(&self, program_id: &ProgramID<N>) -> Result<Program<N>> {
        self.get_request(&format!("program/{program_id}"))
    }

    /// Returns the program for the given program ID.
    #[cfg(feature = "async")]
    pub async fn get_program_async(&self, program_id: &ProgramID<N>) -> Result<Program<N>> {
        self.get_request_async(&format!("program/{program_id}")).await
    }

    /// Builds the full endpoint Uri from the base and path. Used internally
    /// for all REST API calls.
    ///
    /// # Arguments
    ///  - `route`: the route to the endpoint (e.g., `stateRoot/latest`). This cannot start with a slash.
    fn build_endpoint(&self, route: &str) -> Result<String> {
        // This function is only called internally but check for additional sanity.
        ensure!(!route.starts_with('/'), "path cannot start with a slash");

        // Work around a bug in the `http` crate where empty paths will be set to '/' but other paths are not appended with a slash.
        // See [this issue](https://github.com/hyperium/http/issues/507).
        let path = if self.base_url.path().ends_with('/') {
            format!("{base_url}{network}/{route}", base_url = self.base_url, network = N::SHORT_NAME)
        } else {
            format!("{base_url}/{network}/{route}", base_url = self.base_url, network = N::SHORT_NAME)
        };

        Ok(path)
    }

    /// What is left of the total bound for a request that started at `started`.
    #[cfg(not(any(target_arch = "wasm32", target_arch = "wasm64")))]
    fn remaining(&self, started: std::time::Instant) -> Duration {
        self.total.saturating_sub(started.elapsed())
    }

    /// Calls `endpoint`, asking once more if the request was lost on a pooled connection the peer
    /// had closed; the second attempt gets only what is left of the total bound.
    #[cfg(not(any(target_arch = "wasm32", target_arch = "wasm64")))]
    fn call(&self, endpoint: &str) -> Result<ureq::http::Response<ureq::Body>, ureq::Error> {
        let started = std::time::Instant::now();
        match self.agent.get(endpoint).call() {
            Err(ureq::Error::Io(_)) => {
                self.agent.get(endpoint).config().timeout_global(Some(self.remaining(started))).build().call()
            }
            first => first,
        }
    }

    /// On wasm there is no clock to budget a retry with, and no connection pool to lose one on.
    #[cfg(any(target_arch = "wasm32", target_arch = "wasm64"))]
    fn call(&self, endpoint: &str) -> Result<ureq::http::Response<ureq::Body>, ureq::Error> {
        self.agent.get(endpoint).call()
    }

    /// Performs a GET request to the given URL and deserializes the returned JSON.
    ///
    /// # Arguments
    ///  - `route`: the specific API route to use, e.g., `stateRoot/latest`
    fn get_request<T: DeserializeOwned>(&self, route: &str) -> Result<T> {
        let endpoint = self.build_endpoint(route)?;
        let mut response = self.call(&endpoint).with_context(|| format!("Failed to fetch from {endpoint}"))?;

        if response.status().is_success() {
            response.body_mut().read_json().with_context(|| format!("Failed to parse JSON response from {endpoint}"))
        } else {
            // v2 will return the error in JSON format.
            let is_json = response
                .headers()
                .get(http::header::CONTENT_TYPE)
                .and_then(|ct| ct.to_str().ok())
                .map(|ct| ct.contains("json"))
                .unwrap_or(false);

            // Convert returned error into an `anyhow::Error`.
            // Depending on the API version, the error is either encoded as a string or as a JSON.
            if is_json {
                let error: RestError = response
                    .body_mut()
                    .read_json()
                    .with_context(|| format!("Failed to parse JSON error response from {endpoint}"))?;
                Err(error.parse().context(format!("Failed to fetch from {endpoint}")))
            } else {
                let error = response
                    .body_mut()
                    .read_to_string()
                    .with_context(|| format!("Failed to read error message {endpoint}"))?;
                Err(anyhow!(error).context(format!("Failed to fetch from {endpoint}")))
            }
        }
    }

    /// Sends a GET to `endpoint` under the total bound, which goes on the request rather than the
    /// client because that is where reqwest's wasm backend accepts it.
    #[cfg(feature = "async")]
    fn request(&self, endpoint: &str, total: Duration) -> Result<reqwest::RequestBuilder> {
        Ok(self.client()?.get(endpoint).timeout(total))
    }

    /// Async counterpart of [`Self::call`]. hyper-util retries only a request it never began
    /// writing; one written to a closed pooled socket surfaces as a plain request error.
    #[cfg(all(feature = "async", not(any(target_arch = "wasm32", target_arch = "wasm64"))))]
    async fn send(&self, endpoint: &str) -> Result<reqwest::Response> {
        let started = std::time::Instant::now();
        match self.request(endpoint, self.total)?.send().await {
            Err(error) if error.is_request() && !error.is_timeout() && !error.is_connect() => {
                Ok(self.request(endpoint, self.remaining(started))?.send().await?)
            }
            first => Ok(first?),
        }
    }

    /// On wasm the browser owns the connection, and there is no clock to budget a retry with.
    #[cfg(all(feature = "async", any(target_arch = "wasm32", target_arch = "wasm64")))]
    async fn send(&self, endpoint: &str) -> Result<reqwest::Response> {
        Ok(self.request(endpoint, self.total)?.send().await?)
    }

    /// Async version of [`Self::get_request`]. Performs a GET request to the given URL and deserializes the returned JSON.
    ///
    /// # Arguments
    ///  - `route`: the specific API route to use, e.g., `stateRoot/latest`
    #[cfg(feature = "async")]
    async fn get_request_async<T: DeserializeOwned>(&self, route: &str) -> Result<T> {
        let endpoint = self.build_endpoint(route)?;
        let response = self.send(&endpoint).await.with_context(|| format!("Failed to fetch from {endpoint}"))?;

        if response.status().is_success() {
            response.json().await.with_context(|| format!("Failed to parse JSON response from {endpoint}"))
        } else {
            // v2 will return the error in JSON format.
            let is_json = response
                .headers()
                .get(http::header::CONTENT_TYPE)
                .and_then(|ct| ct.to_str().ok())
                .map(|ct| ct.contains("json"))
                .unwrap_or(false);

            if is_json {
                // Convert returned error into an `anyhow::Error`.
                let error: RestError = response
                    .json()
                    .await
                    .with_context(|| format!("Failed to parse JSON error response from {endpoint}"))?;
                Err(error.parse().context(format!("Failed to fetch from {endpoint}")))
            } else {
                let error =
                    response.text().await.with_context(|| format!("Failed to read error message {endpoint}"))?;
                Err(anyhow!(error).context(format!("Failed to fetch from {endpoint}")))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::RestQuery;
    use crate::{Query, QueryTrait};

    use snarkvm_console::network::TestnetV0;
    use snarkvm_ledger_store::helpers::memory::BlockMemory;

    use anyhow::Result;

    use std::{
        io::{Read, Write},
        net::{TcpListener, TcpStream},
        str::FromStr,
        sync::{
            Arc,
            atomic::{AtomicUsize, Ordering},
        },
        time::{Duration, Instant},
    };

    type CurrentNetwork = TestnetV0;
    type CurrentQuery = Query<CurrentNetwork, BlockMemory<CurrentNetwork>>;

    /// Listens on a loopback port, serving each connection on its own thread and counting them.
    /// Returns the base URL and the count.
    fn node(serve: impl Fn(TcpStream) + Clone + Send + 'static) -> (String, Arc<AtomicUsize>) {
        let listener = TcpListener::bind("127.0.0.1:0").expect("a loopback port");
        let url = format!("http://{}", listener.local_addr().expect("the bound address"));
        let connections = Arc::new(AtomicUsize::new(0));

        let seen = connections.clone();
        std::thread::spawn(move || {
            for stream in listener.incoming() {
                let Ok(stream) = stream else { break };
                seen.fetch_add(1, Ordering::SeqCst);
                let serve = serve.clone();
                std::thread::spawn(move || serve(stream));
            }
        });
        (url, connections)
    }

    /// Serves `reply` on each connection, then holds the socket open until the client closes.
    /// An empty `reply` is a node that accepts the request and answers nothing.
    fn stalling_node(reply: &'static [u8]) -> (String, Arc<AtomicUsize>) {
        node(move |mut stream| {
            let mut buffer = [0u8; 1024];
            let _ = stream.read(&mut buffer);
            let _ = stream.write_all(reply);
            let _ = stream.flush();
            // Held, not finished: read and discard until the close.
            while matches!(stream.read(&mut buffer), Ok(read) if read > 0) {}
        })
    }

    fn bounded_query(url: &str, stall: Duration, total: Duration) -> RestQuery<CurrentNetwork> {
        RestQuery::<CurrentNetwork>::from_str(url).expect("a loopback URL").with_timeouts(
            Duration::from_secs(5),
            stall,
            total,
        )
    }

    /// A complete, correctly framed height, so the connection returns to the
    /// pool rather than closing.
    const HEIGHT: &[u8] = b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 3\r\n\r\n123";

    /// Answers the first `answers` requests on a connection with `HEIGHT` and abandons the next.
    /// One answer per header terminator, not per read, so a split request is not answered twice.
    fn answer_requests(mut stream: TcpStream, answers: usize) {
        let mut chunk = [0u8; 1024];
        let mut pending: Vec<u8> = Vec::new();
        let mut answered = 0;
        loop {
            match stream.read(&mut chunk) {
                Ok(0) | Err(_) => return,
                Ok(read) => pending.extend_from_slice(&chunk[..read]),
            }
            while let Some(end) = pending.windows(4).position(|w| w == b"\r\n\r\n") {
                pending.drain(..end + 4);
                if answered == answers {
                    // Gone without answering: the client sent this on a
                    // connection the pool believed was good.
                    return;
                }
                let _ = stream.write_all(HEIGHT);
                let _ = stream.flush();
                answered += 1;
            }
        }
    }

    /// Answers every request on every connection.
    fn counting_node() -> (String, Arc<AtomicUsize>) {
        node(|stream| answer_requests(stream, usize::MAX))
    }

    /// Answers the first request on a connection and abandons the second: what a peer that has
    /// given up on a pooled connection looks like to a client still holding it.
    fn abandoning_node() -> (String, Arc<AtomicUsize>) {
        node(|stream| answer_requests(stream, 1))
    }

    /// A timeout is not a lost request, so it is not asked again: the bounds
    /// `with_timeouts` sets are what they say only if they are spent once.
    #[test]
    fn a_query_that_times_out_is_not_asked_again() {
        let (url, connections) = stalling_node(b"");
        let query = bounded_query(&url, Duration::from_secs(30), Duration::from_millis(500));

        let started = Instant::now();
        assert!(query.current_block_height().is_err(), "a node that answers nothing cannot produce a height");
        let waited = started.elapsed();

        assert_eq!(connections.load(Ordering::SeqCst), 1, "the request was asked again and the bound paid twice");
        assert!(waited < Duration::from_secs(5), "the bound was not spent once, it waited {waited:?}");
    }

    /// Accepts, reads the request, waits `hold`, then closes without answering.
    fn closing_node(hold: Duration) -> (String, Arc<AtomicUsize>) {
        node(move |mut stream| {
            let mut buffer = [0u8; 1024];
            let _ = stream.read(&mut buffer);
            std::thread::sleep(hold);
        })
    }

    /// A request lost late in the total bound is asked again, but with only what is left of that
    /// bound: the second attempt is not a second budget.
    #[test]
    fn a_lost_request_is_asked_again_within_the_total_bound() {
        let (url, connections) = closing_node(Duration::from_millis(800));
        let query = bounded_query(&url, Duration::from_secs(30), Duration::from_secs(1));

        let started = Instant::now();
        assert!(query.current_block_height().is_err(), "a node that closes without answering cannot produce a height");
        let waited = started.elapsed();

        assert_eq!(connections.load(Ordering::SeqCst), 2, "the lost request was not asked again");
        assert!(waited < Duration::from_millis(1400), "the total bound was paid twice, it waited {waited:?}");
    }

    /// The second query goes out on the connection the first left in the pool, which the peer
    /// has since abandoned; ureq has no retry of its own.
    #[test]
    fn a_query_lost_on_a_pooled_connection_is_asked_again() {
        let (url, connections) = abandoning_node();
        let query = bounded_query(&url, Duration::from_secs(5), Duration::from_secs(10));

        query.current_block_height().expect("the node answers the first height");
        query.current_block_height().expect("the second height survives the abandoned connection");

        assert_eq!(connections.load(Ordering::SeqCst), 2, "the request was not asked again on a fresh connection");
    }

    /// The point of holding the agent: a caller reading the chain per transaction should not pay
    /// a handshake each time.
    #[test]
    fn repeated_queries_share_a_connection() {
        let (url, connections) = counting_node();
        // Bounded like its neighbours: a stub that desynchronised would
        // otherwise hold this for the default five minutes rather than fail.
        let query = bounded_query(&url, Duration::from_secs(5), Duration::from_secs(10));

        // A height, because the body has to deserialize: a reader abandoned part way leaves the
        // connection unusable, so a failed parse would not exercise pooling at all.
        query.current_block_height().expect("the node answers a height");
        query.current_block_height().expect("the node answers a height");

        assert_eq!(connections.load(Ordering::SeqCst), 1, "each query opened its own connection");
    }

    /// A node that answers nothing is ended by the total bound (and, at `stall`, by the header bound).
    #[test]
    fn a_node_that_never_answers_does_not_block_for_ever() {
        let (url, _) = stalling_node(b"");
        let query = bounded_query(&url, Duration::from_secs(30), Duration::from_millis(500));

        let started = Instant::now();
        let result = query.current_state_root();
        let waited = started.elapsed();

        assert!(result.is_err(), "a node that answers nothing cannot produce a state root");
        assert!(waited < Duration::from_secs(5), "the request was not bounded, it waited {waited:?}");
    }

    /// The stall bound also covers the wait for the answer to begin, so a silent node does not
    /// hold a caller for the whole total bound.
    #[test]
    fn a_node_that_never_answers_is_ended_by_the_stall_bound() {
        let (url, _) = stalling_node(b"");
        let query = bounded_query(&url, Duration::from_millis(500), Duration::from_secs(120));

        let started = Instant::now();
        let result = query.current_state_root();
        let waited = started.elapsed();

        assert!(result.is_err(), "a node that answers nothing cannot produce a state root");
        assert!(waited < Duration::from_secs(5), "the stall bound did not cover the headers, it waited {waited:?}");
    }

    /// A node that begins answering and then stops is caught by the stall bound,
    /// well before the total one it would otherwise wait out.
    #[test]
    fn a_node_that_stops_mid_answer_does_not_block_for_ever() {
        let (url, _) = stalling_node(b"HTTP/1.1 200 OK\r\nContent-Length: 4096\r\n\r\npartial");
        let query = bounded_query(&url, Duration::from_millis(500), Duration::from_secs(120));

        let started = Instant::now();
        let result = query.current_state_root();
        let waited = started.elapsed();

        assert!(result.is_err(), "a truncated body cannot produce a state root");
        assert!(waited < Duration::from_secs(5), "the stall bound did not fire, it waited {waited:?}");
    }

    /// Answers a height whose body arrives in `pieces` slices of whitespace `gap` apart, then the
    /// digits: a healthy response that takes `pieces * gap` to finish.
    fn dribbling_node(pieces: usize, gap: Duration) -> (String, Arc<AtomicUsize>) {
        node(move |mut stream| {
            let mut buffer = [0u8; 1024];
            let _ = stream.read(&mut buffer);
            let header = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n",
                pieces * 8 + 3
            );
            let _ = stream.write_all(header.as_bytes());
            let _ = stream.flush();
            for _ in 0..pieces {
                std::thread::sleep(gap);
                let _ = stream.write_all(b"        ");
                let _ = stream.flush();
            }
            let _ = stream.write_all(b"123");
            let _ = stream.flush();
        })
    }

    /// A body that finishes within the stall bound arrives, however many reads it takes.
    #[test]
    fn a_body_within_the_stall_bound_arrives_in_pieces() {
        let (url, _) = dribbling_node(4, Duration::from_millis(100));
        let query = bounded_query(&url, Duration::from_secs(5), Duration::from_secs(120));

        assert_eq!(query.current_block_height().expect("a body that arrives in pieces is still a height"), 123);
    }

    /// On the sync path `stall` is a budget for the whole body, anchored at the headers, so a
    /// body that keeps moving but outlasts it is cut off. The async path reads the same bound as a
    /// gap between reads; its test below asserts the opposite.
    #[test]
    fn a_body_that_outlasts_the_stall_bound_is_cut_off() {
        let (url, _) = dribbling_node(8, Duration::from_millis(150));
        let query = bounded_query(&url, Duration::from_millis(500), Duration::from_secs(120));

        let started = Instant::now();
        let result = query.current_block_height();
        let waited = started.elapsed();

        assert!(result.is_err(), "the body budget did not cut the response off");
        assert!(waited < Duration::from_secs(5), "the body budget did not fire, it waited {waited:?}");
    }

    #[cfg(feature = "async")]
    mod r#async {
        use super::*;

        /// Runs `future` on a single-threaded runtime, which is all reqwest needs.
        fn block_on<F: std::future::Future>(future: F) -> F::Output {
            tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .expect("a single-threaded runtime")
                .block_on(future)
        }

        /// The async stall bound is a gap between reads, so a body that keeps moving arrives
        /// however long it takes.
        #[test]
        fn a_body_longer_than_the_stall_bound_arrives_if_it_keeps_moving() {
            block_on(async {
                let (url, _) = dribbling_node(8, Duration::from_millis(150));
                let query = bounded_query(&url, Duration::from_millis(500), Duration::from_secs(120));

                assert_eq!(query.current_block_height_async().await.expect("a body that keeps moving arrives"), 123);
            });
        }

        /// A timeout is not a lost request, so it is not asked again.
        #[test]
        fn a_query_that_times_out_is_not_asked_again() {
            block_on(async {
                let (url, connections) = stalling_node(b"");
                let query = bounded_query(&url, Duration::from_secs(30), Duration::from_millis(500));

                let started = Instant::now();
                assert!(
                    query.current_block_height_async().await.is_err(),
                    "a node that answers nothing cannot produce a height"
                );
                let waited = started.elapsed();

                assert_eq!(
                    connections.load(Ordering::SeqCst),
                    1,
                    "the request was asked again and the bound paid twice"
                );
                assert!(waited < Duration::from_secs(5), "the bound was not spent once, it waited {waited:?}");
            });
        }

        /// A request lost late in the total bound is asked again with only what is left of it.
        #[test]
        fn a_lost_request_is_asked_again_within_the_total_bound() {
            block_on(async {
                let (url, connections) = closing_node(Duration::from_millis(800));
                let query = bounded_query(&url, Duration::from_secs(30), Duration::from_secs(1));

                let started = Instant::now();
                assert!(
                    query.current_block_height_async().await.is_err(),
                    "a node that closes without answering cannot produce a height"
                );
                let waited = started.elapsed();

                assert_eq!(connections.load(Ordering::SeqCst), 2, "the lost request was not asked again");
                assert!(waited < Duration::from_millis(1400), "the total bound was paid twice, it waited {waited:?}");
            });
        }

        /// The second query goes out on the connection the first left in the pool, which the peer
        /// has since abandoned; hyper does not retry a request it had begun writing.
        #[test]
        fn a_query_lost_on_a_pooled_connection_is_asked_again() {
            block_on(async {
                let (url, connections) = abandoning_node();
                let query = bounded_query(&url, Duration::from_secs(5), Duration::from_secs(10));

                query.current_block_height_async().await.expect("the node answers the first height");
                query.current_block_height_async().await.expect("the second height survives the abandoned connection");

                assert_eq!(
                    connections.load(Ordering::SeqCst),
                    2,
                    "the request was not asked again on a fresh connection"
                );
            });
        }
    }

    /// Tests HTTP's behavior of printing an empty path `/`
    ///
    /// `generate_endpoint` can handle base_urls with and without a trailing slash.
    /// However, this test is still useful to see if the behavior changes in the future and a second slash is not
    /// appended to a URL with an existing trailing slash.
    #[test]
    fn test_rest_url_parse() -> Result<()> {
        let noslash = "http://localhost:3030";
        let withslash = format!("{noslash}/");
        let route = "some/route";

        let query = noslash.parse::<CurrentQuery>().unwrap();
        let Query::REST(rest) = query else { panic!() };
        assert_eq!(rest.base_url.path_and_query().unwrap().to_string(), "/");
        assert_eq!(rest.base_url.to_string(), withslash);
        assert_eq!(rest.build_endpoint(route)?, format!("{noslash}/testnet/{route}"));

        let query = withslash.parse::<CurrentQuery>().unwrap();
        let Query::REST(rest) = query else { panic!() };
        assert_eq!(rest.base_url.path_and_query().unwrap().to_string(), "/");
        assert_eq!(rest.base_url.to_string(), withslash);
        assert_eq!(rest.build_endpoint(route)?, format!("{noslash}/testnet/{route}"));

        Ok(())
    }

    #[test]
    fn test_rest_url_with_colon_parse() {
        let str = "http://myendpoint.addr/:var/foo/bar";
        let query = str.parse::<CurrentQuery>().unwrap();

        let Query::REST(rest) = query else { panic!() };
        assert_eq!(rest.base_url.to_string(), format!("{str}"));
        assert_eq!(rest.base_url.path_and_query().unwrap().to_string(), "/:var/foo/bar");
    }

    #[test]
    fn test_rest_url_parse_with_suffix() -> Result<()> {
        let base = "http://localhost:3030/a/prefix/v2";
        let route = "a/route";

        // Test without trailing slash.
        let query = base.parse::<CurrentQuery>().unwrap();
        let Query::REST(rest) = query else { panic!() };
        assert_eq!(rest.build_endpoint(route)?, format!("{base}/testnet/{route}"));

        // Set again with trailing slash.
        let query = format!("{base}/").parse::<CurrentQuery>().unwrap();
        let Query::REST(rest) = query else { panic!() };
        assert_eq!(rest.build_endpoint(route)?, format!("{base}/testnet/{route}"));

        Ok(())
    }
}
