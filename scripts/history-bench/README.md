# Program mapping history benchmark

[k6](https://k6.io) scripts that measure how fast a running node serves program mapping history.
They send real requests to the REST API of a snarkOS client that records history
(`--history-programs` or `--archival`). They do not start or configure a node.

| File | Purpose |
|------|---------|
| `corpus.js` | Finds real mapping keys on the node and writes `corpus.json`. |
| `bench.js` | Sends the benchmark requests and prints a latency table. |
| `run-mappings.sh` | Runs `bench.js` once for each mapping, as separate k6 processes. |
| `lib.js` | Shared helpers. |

## Before you run

- Install k6 1.0 or later.
- Run the commands from this directory. k6 reads `corpus.json` relative to the script and writes results relative to the working directory.
- Run k6 on a machine near the node, not on the node. k6 competes with the node for CPU.
- The node limits each IP address to `--rest-rps` requests per second. The default is 10. The default settings here stay below that. For the `ramp` profile, or a `RATE` above 10, restart the node with a higher `--rest-rps`. `bench.js` stops when more than 1% of the requests return `429`.

## 1. Build the corpus

```sh
k6 run -e BASE_URL=http://<node>:3030 corpus.js
```

`corpus.js` samples block windows inside the recorded ranges. It collects the literals in the transactions of each program. It then asks the batch history route which literals are keys of which mapping. It tests each literal at the height of the block that carries it, because a program can remove a key again. A literal with a value becomes a key. A literal without a value becomes an absent key. The corpus also records the first height where each mapping exists.

Sampling finds only keys that are literals (`address`, `field`, integers) and that appear in transactions. It cannot find struct or array keys, or keys that a finalize block computes. For those mappings, pass a node JWT. The script then reads the whole mapping through the protected route:

```sh
k6 run -e BASE_URL=http://<node>:3030 -e JWT=<token> -e DUMP_PROGRAMS=shield_swap.aleo corpus.js
```

Do not list `credits.aleo` in `DUMP_PROGRAMS`. Its `account` mapping is too large to read in one response.

Without a JWT, you can supply candidate keys from another source in a JSON file. `corpus.js` tests them in the same way:

```sh
k6 run -e BASE_URL=http://<node>:3030 -e EXTRA=extra.json corpus.js
```

```json
{ "shield_swap.aleo": { "ticks": [{ "key": "123field", "height": 20664273 }] } }
```

`height` is a height where the key is expected to have a value.

| Setting | Default | Meaning |
|---------|---------|---------|
| `PROGRAMS` | `credits.aleo,shield_swap.aleo` | Programs to find keys for. |
| `MAPPINGS` | all | Mappings to find keys for, each written as `program/mapping`. |
| `SAMPLE_FROM` | start of the history | Lowest block height to sample. |
| `WINDOWS` | `40` | Block windows to sample. Raise it when a program has few transactions. |
| `WINDOW_BLOCKS` | `50` | Blocks in each window. The node allows at most 160. |
| `MAX_KEYS` | `2000` | Keys to keep for each mapping. |
| `MAX_MISSES` | `500` | Absent keys to keep for each mapping. |
| `PROBE_HEIGHTS` | `300` | Block heights at which to test candidates for each mapping. |
| `DISCOVERY_RPS` | `4` | Request rate during discovery. |
| `CORPUS` | `corpus.json` | Output file. |

## 2. Measure latency

```sh
k6 run -e BASE_URL=http://<node>:3030 bench.js
```

The `latency` profile sends `RATE` requests per second for `DURATION`. The arrival rate is fixed, so a slow response does not delay the next request. The operations take turns, one request each, so a slow period on the node affects all of them equally.

| Operation | Request | Measures |
|-----------|---------|----------|
| `ctl_height` | `GET /block/height/latest` | Control: HTTP and middleware cost. |
| `ctl_latest` | `GET /program/{p}/mapping/{m}/{key}` | Control: current-state lookup. |
| `ranges` | `GET /program/{p}/history/ranges` | Coverage lookup. |
| `point_hit` | `GET .../{key}/history/{height}` | Key lookup at a height where the key is expected to exist. |
| `point_early` | same | Key lookup in the first 1% of the heights where the mapping exists. |
| `point_late` | same | Key lookup in the last 1% of those heights. |
| `point_miss` | same | Lookup of a key that the mapping does not contain. |
| `uncovered` | same | Lookup at a height with no history. Expects `404`. |
| `batch_8`, `batch_32`, `batch_128` | `GET .../history/{height}?keys=...` | Batch lookup. `ms/key` is the median divided by the batch size. A mapping with fewer keys than the batch size fills the batch with absent keys. |

The `null` column gives the share of `200` responses with the body `null`.

Each mapping gets the same share of the requests, whatever the number of its keys. A second table gives the latency of `point_hit`, `point_early` and `point_late` for each mapping.

To measure each mapping alone, use `run-mappings.sh`. It starts one k6 process for each mapping and writes one result file and one log for each to `results/mappings/`. `JOBS` is the number of processes that run at the same time:

```sh
BASE_URL=http://<node>:3030 JOBS=1 ./run-mappings.sh credits.aleo/account shield_swap.aleo/ticks
```

Processes that run at the same time send the same operation at the same moment. Use `JOBS=1` when the batch latency matters.

To compare a cold cache with a warm cache, run the same request sequence twice. The script prints the `SEED` and `MAX_HEIGHT` of each run:

```sh
k6 run -e BASE_URL=http://<node>:3030 -e SEED=7 -e MAX_HEIGHT=<height> bench.js   # First run: cold.
k6 run -e BASE_URL=http://<node>:3030 -e SEED=7 -e MAX_HEIGHT=<height> bench.js   # Second run: warm.
```

A new `SEED` gives a new sequence. For a soak test, set a long `DURATION`, for example `-e DURATION=2h`.

## 3. Find the throughput limit

```sh
k6 run -e BASE_URL=http://<node>:3030 -e PROFILE=ramp -e OPS=point_hit bench.js
```

The `ramp` profile holds each of `STEPS` request rates for `STEP_SECONDS`, from `RATE_START` to `RATE_MAX`. It prints one row for each step. The limit is the last step where `ok req/s` matches the target and p99 stays flat. Run it once for each operation of interest, for example `point_hit` and `batch_128`.

## Settings for `bench.js`

| Setting | Default | Meaning |
|---------|---------|---------|
| `PROFILE` | `latency` | `latency` or `ramp`. |
| `OPS` | all (`latency`), `point_hit` (`ramp`) | Operations to run, separated by commas. |
| `PROGRAMS` | all in the corpus | Programs to query. Run once for each program to compare them. |
| `MAPPINGS` | all in the corpus | Mappings to query, each written as `program/mapping`. |
| `RATE`, `DURATION` | `5`, `10m` | Request rate and length of the `latency` profile. |
| `RATE_START`, `RATE_MAX`, `STEPS`, `STEP_SECONDS` | `25`, `400`, `8`, `60` | Steps of the `ramp` profile. |
| `SEED`, `MAX_HEIGHT` | `1`, end of coverage | Fix the request sequence. |
| `PRE_VUS`, `MAX_VUS` | `50`, `500` | k6 virtual users. Raise `MAX_VUS` when k6 reports dropped iterations and the node is not the cause. |
| `CORPUS` | `corpus.json` | Corpus file. |
| `OUT` | `history-bench-<profile>-<time>.json` | Result file. |

For latency over time, add `K6_WEB_DASHBOARD=true K6_WEB_DASHBOARD_EXPORT=report.html` before `k6 run`.
