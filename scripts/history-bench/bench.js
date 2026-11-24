// Benchmarks the program mapping history routes of a running node.
//
//   k6 run -e BASE_URL=http://<node>:3030 scripts/history-bench/bench.js
//   k6 run -e BASE_URL=http://<node>:3030 -e PROFILE=ramp -e OPS=point_hit scripts/history-bench/bench.js
//
// See README.md for the profiles, the operations and the settings.

import http from 'k6/http';
import exec from 'k6/execution';
import { SharedArray } from 'k6/data';
import { Counter, Rate, Trend } from 'k6/metrics';

import {
  BASE_URL,
  MAX_KEYS_PER_REQUEST,
  batchUrl,
  clampRanges,
  coverage,
  envInt,
  envList,
  floorRanges,
  heightAt,
  heightUrl,
  latestValueUrl,
  pad,
  padEnd,
  pointUrl,
  rangesUrl,
  rng,
  selects,
} from './lib.js';

const PROFILE = __ENV.PROFILE || 'latency';
if (!['latency', 'ramp'].includes(PROFILE)) throw new Error(`PROFILE must be 'latency' or 'ramp', got '${PROFILE}'`);

const CORPUS = __ENV.CORPUS || 'corpus.json';
const PROGRAMS = envList('PROGRAMS', '');
// Optional. Limits the run to these mappings, each written as `program/mapping`.
const MAPPINGS = envList('MAPPINGS', '');
const SEED = envInt('SEED', 1);
// Pin the highest height to query. Two runs with the same SEED and MAX_HEIGHT send the same requests.
const MAX_HEIGHT = envInt('MAX_HEIGHT', 0);
const PRE_VUS = envInt('PRE_VUS', 50);
const MAX_VUS = envInt('MAX_VUS', 500);

// The latency profile.
const RATE = envInt('RATE', 5);
const DURATION = __ENV.DURATION || '10m';

// The ramp profile.
const RATE_START = envInt('RATE_START', 25);
const RATE_MAX = envInt('RATE_MAX', 400);
const STEPS = envInt('STEPS', 8);
const STEP_SECONDS = envInt('STEP_SECONDS', 60);

// `p` is a program, `m` a mapping, `g` the index of the mapping in `groups`, `s` the first height
// where the mapping exists, `k` a key, `h` the first sampled height that carries the key, and `l`
// whether the mapping still contains the key at the end of the history.
const hits = new SharedArray('hits', () => flatten((mapping) => mapping.hits.map((hit) => ({ k: hit.key, h: hit.firstSeen, l: hit.live !== false }))));
const misses = new SharedArray('misses', () => flatten((mapping) => mapping.misses.map((key) => ({ k: key, h: null, l: true }))));
// The run of consecutive `hits` that each mapping owns, and the same for `misses`.
const groups = new SharedArray('groups', () => runs((mapping) => mapping.hits.length));
const missGroups = new SharedArray('missGroups', () => runs((mapping) => mapping.misses.length));
const programs = new SharedArray('programs', () => [...new Set(selectedMappings().map(([p]) => p))]);

function selectedMappings() {
  const corpus = JSON.parse(open(CORPUS));
  const result = [];
  for (const [p, entry] of Object.entries(corpus.programs)) {
    if (PROGRAMS.length > 0 && !PROGRAMS.includes(p)) continue;
    for (const [m, mapping] of Object.entries(entry.mappings)) {
      if (selects(MAPPINGS, p, m)) result.push([p, m, mapping]);
    }
  }
  return result;
}

function runs(count) {
  const result = [];
  let offset = 0;
  for (const [p, m, mapping] of selectedMappings()) {
    const length = count(mapping);
    if (length > 0) result.push({ p, m, s: mapping.since || 0, offset, length });
    offset += length;
  }
  return result;
}

function flatten(select) {
  const result = [];
  let g = 0;
  for (const [p, m, mapping] of selectedMappings()) {
    const items = select(mapping);
    for (const item of items) result.push({ p, m, g, s: mapping.since || 0, k: item.k, h: item.h, l: item.l });
    if (items.length > 0) g += 1;
  }
  return result;
}

// Returns the run of `misses` that the mapping of the group owns.
function absent(group) {
  return missGroups.find((other) => other.p === group.p && other.m === group.m) || { offset: 0, length: 0 };
}

if (hits.length === 0) throw new Error(`${CORPUS} has no keys for the selected programs. Run corpus.js first.`);

// Each operation sends one request. `status` is the status the node must return.
const OPERATIONS = {
  // Controls. Neither reads history.
  ctl_height: { status: 200, url: () => heightUrl() },
  ctl_latest: { status: 200, url: (ctx) => latestValueUrl(ctx.hit.p, ctx.hit.m, ctx.hit.k) },
  // History.
  ranges: { status: 200, url: (ctx) => rangesUrl(ctx.hit.p) },
  point_hit: { status: 200, url: (ctx) => pointUrl(ctx.hit.p, ctx.hit.m, ctx.hit.k, ctx.height('live', ctx.hit)) },
  point_early: { status: 200, url: (ctx) => pointUrl(ctx.hit.p, ctx.hit.m, ctx.hit.k, ctx.height('early', ctx.hit)) },
  point_late: { status: 200, url: (ctx) => pointUrl(ctx.hit.p, ctx.hit.m, ctx.hit.k, ctx.height('late', ctx.hit)) },
  point_miss: {
    status: 200,
    available: () => misses.length > 0,
    url: (ctx) => {
      const group = missGroups[Math.floor(ctx.random() * missGroups.length)];
      const miss = misses[group.offset + Math.floor(ctx.random() * group.length)];
      return pointUrl(miss.p, miss.m, miss.k, ctx.height('any', miss));
    },
  },
  uncovered: {
    status: 404,
    url: (ctx) => pointUrl(ctx.hit.p, ctx.hit.m, ctx.hit.k, ctx.uncovered(ctx.hit.p)),
  },
};
for (const size of [8, 32, MAX_KEYS_PER_REQUEST]) {
  OPERATIONS[`batch_${size}`] = {
    status: 200,
    keys: size,
    available: () => groups.some((group) => group.length + absent(group).length >= size),
    // A batch takes existing keys first. When the mapping has too few, absent keys fill the rest.
    url: (ctx) => {
      const eligible = groups.filter((group) => group.length + absent(group).length >= size);
      const group = eligible[Math.floor(ctx.random() * eligible.length)];
      const existing = Math.min(size, group.length);
      const first = Math.floor(ctx.random() * (group.length - existing + 1));
      const keys = [];
      for (let index = 0; index < existing; index++) keys.push(hits[group.offset + first + index].k);
      const fill = absent(group);
      const firstFill = Math.floor(ctx.random() * (fill.length - (size - existing) + 1));
      for (let index = 0; index < size - existing; index++) keys.push(misses[fill.offset + firstFill + index].k);
      return batchUrl(group.p, group.m, keys, ctx.height('any', group));
    },
  };
}

const DEFAULT_OPS = PROFILE === 'ramp' ? 'point_hit' : Object.keys(OPERATIONS).join(',');
const ops = envList('OPS', DEFAULT_OPS).filter((name) => {
  const operation = OPERATIONS[name];
  if (!operation) throw new Error(`Unknown operation '${name}'. Choose from ${Object.keys(OPERATIONS).join(', ')}`);
  const available = !operation.available || operation.available();
  if (!available) console.warn(`Skipping ${name}: the corpus has too few keys for it`);
  return available;
});
if (ops.length === 0) throw new Error('No operation can run with this corpus');

const latency = {};
const failed = {};
const empty = {};
for (const name of ops) {
  latency[name] = new Trend(`lat_${name}`, true);
  failed[name] = new Rate(`err_${name}`);
  empty[name] = new Rate(`null_${name}`);
}
// The lookups of existing keys (point_hit, point_early and point_late), for each mapping.
const mappingLatency = groups.map((group, index) => new Trend(`map_lat_${index}`, true));
const mappingEmpty = groups.map((group, index) => new Rate(`map_null_${index}`));
const stepLatency = [];
const stepFailed = [];
if (PROFILE === 'ramp') {
  for (let step = 0; step < STEPS; step++) {
    stepLatency.push(new Trend(`step_lat_${step}`, true));
    stepFailed.push(new Rate(`step_err_${step}`));
  }
}
const PER_MAPPING = ['point_hit', 'point_early', 'point_late'];
const rateLimited = new Rate('rate_limited');
const unexpected = new Counter('unexpected_status');

function stepRate(step) {
  return STEPS === 1 ? RATE_MAX : Math.round(RATE_START + ((RATE_MAX - RATE_START) * step) / (STEPS - 1));
}

function scenario() {
  if (PROFILE === 'latency') {
    return { executor: 'constant-arrival-rate', rate: RATE, timeUnit: '1s', duration: DURATION, preAllocatedVUs: PRE_VUS, maxVUs: MAX_VUS };
  }
  const stages = [];
  for (let step = 0; step < STEPS; step++) {
    if (step > 0) stages.push({ target: stepRate(step), duration: '0s' });
    stages.push({ target: stepRate(step), duration: `${STEP_SECONDS}s` });
  }
  return { executor: 'ramping-arrival-rate', startRate: stepRate(0), timeUnit: '1s', stages, preAllocatedVUs: PRE_VUS, maxVUs: MAX_VUS };
}

export const options = {
  scenarios: { [PROFILE]: scenario() },
  summaryTrendStats: ['count', 'min', 'med', 'p(90)', 'p(95)', 'p(99)', 'max'],
  thresholds: {
    // A rate-limited run measures the node's `--rest-rps` governor, not the history routes.
    rate_limited: [{ threshold: 'rate<0.01', abortOnFail: true, delayAbortEval: '10s' }],
  },
  setupTimeout: '2m',
};

export function setup() {
  const tipResponse = http.get(heightUrl());
  if (tipResponse.status !== 200) exec.test.abort(`Cannot read the latest height from ${BASE_URL}: status ${tipResponse.status}`);
  const tip = tipResponse.json();

  const ranges = {};
  for (const program of programs) {
    const response = http.get(rangesUrl(program));
    if (response.status !== 200) exec.test.abort(`Cannot read the history ranges of ${program}: ${response.status} ${response.body}`);
    ranges[program] = MAX_HEIGHT > 0 ? clampRanges(response.json(), MAX_HEIGHT) : response.json();
    if (ranges[program].length === 0) exec.test.abort(`The node has no history for ${program} in the selected heights`);
  }

  // Check one lookup before the run starts, so that a wrong route or node mode fails here.
  const sample = hits[0];
  const range = ranges[sample.p][ranges[sample.p].length - 1];
  const probe = http.get(pointUrl(sample.p, sample.m, sample.k, range[1]));
  if (probe.status !== 200) exec.test.abort(`The history lookup failed: ${probe.status} ${probe.body}`);

  const peak = PROFILE === 'ramp' ? RATE_MAX : RATE;
  if (peak > 10) console.warn(`The peak rate is ${peak} requests/s. Start the node with --rest-rps above that, or it returns 429.`);
  const maxHeight = Math.max(...Object.values(ranges).map((list) => list[list.length - 1][1]));
  console.log(`Tip ${tip}. To repeat this request sequence, pass -e SEED=${SEED} -e MAX_HEIGHT=${maxHeight}`);
  return { tip, ranges, maxHeight, startedAt: new Date().toISOString() };
}

function context(data, random) {
  // Each mapping gets the same share of the requests, whatever the number of its keys.
  const group = groups[Math.floor(random() * groups.length)];
  const hit = hits[group.offset + Math.floor(random() * group.length)];
  return {
    hit,
    random,
    // Returns a covered height where the target's mapping exists.
    //   live:  between the height that first carried the key and the end of that range.
    //   early: in the first 1% of those heights.  late: in the last 1%.  any: anywhere.
    height(mode, target) {
      const existing = floorRanges(data.ranges[target.p], target.s);
      const ranges = existing.length > 0 ? existing : data.ranges[target.p];
      const total = coverage(ranges);
      const edge = Math.max(1, Math.floor(total / 100));
      if (mode === 'early') return heightAt(ranges, Math.floor(random() * edge));
      if (mode === 'late') return heightAt(ranges, total - 1 - Math.floor(random() * edge));
      // The program removed the key again, so only the height that carried it is known to have it.
      if (mode === 'live' && target.h !== null && !target.l) return Math.max(target.h, ranges[0][0]);
      if (mode === 'live' && target.h !== null) {
        const range = ranges.find(([start, end]) => target.h >= start && target.h <= end);
        if (range) return target.h + Math.floor(random() * (range[1] - target.h + 1));
      }
      return heightAt(ranges, Math.floor(random() * total));
    },
    // Returns a height just below a covered range that no other range covers.
    uncovered(program) {
      const ranges = data.ranges[program];
      for (let index = ranges.length - 1; index >= 0; index--) {
        const height = ranges[index][0] - 1;
        if (height >= 0 && (index === 0 || ranges[index - 1][1] < height)) return height;
      }
      // History starts at genesis and has no gap, so use a height above the tip.
      return ranges[ranges.length - 1][1] + 1000000;
    },
  };
}

export default function (data) {
  const iteration = exec.scenario.iterationInTest;
  const name = ops[iteration % ops.length];
  const operation = OPERATIONS[name];
  const random = rng(Math.imul(SEED, 0x9e3779b1) + iteration);
  const ctx = context(data, random);
  const url = operation.url(ctx);

  const response = http.get(url, {
    tags: { name, op: name },
    responseCallback: http.expectedStatuses(operation.status),
    timeout: '60s',
  });

  const limited = response.status === 429;
  const ok = response.status === operation.status;
  rateLimited.add(limited);
  failed[name].add(!ok);
  if (ok) {
    latency[name].add(response.timings.duration);
    if (name.startsWith('point_')) empty[name].add(response.body === 'null');
    if (PER_MAPPING.includes(name)) {
      mappingLatency[ctx.hit.g].add(response.timings.duration);
      mappingEmpty[ctx.hit.g].add(response.body === 'null');
    }
  } else if (!limited) {
    unexpected.add(1, { status: String(response.status) });
    if (iteration < 20 * ops.length) console.warn(`${name}: status ${response.status} from ${url.slice(0, 200)}: ${String(response.body).slice(0, 200)}`);
  }

  if (PROFILE === 'ramp') {
    const elapsed = (Date.now() - exec.scenario.startTime) / 1000;
    const step = Math.min(STEPS - 1, Math.floor(elapsed / STEP_SECONDS));
    stepFailed[step].add(!ok);
    if (ok) stepLatency[step].add(response.timings.duration);
  }
}

function milliseconds(value) {
  return value === undefined ? '-' : value.toFixed(2);
}

function percent(metric) {
  return metric ? `${(metric.values.rate * 100).toFixed(2)}%` : '-';
}

function row(label, trend, cells, width) {
  const values = trend ? trend.values : {};
  const stats = ['med', 'p(90)', 'p(95)', 'p(99)', 'max'].map((stat) => pad(milliseconds(values[stat]), 10));
  return padEnd(label, width || 14) + pad(values.count === undefined ? 0 : values.count, 9) + stats.join('') + cells.map((cell) => pad(cell, 10)).join('');
}

export function handleSummary(data) {
  const metrics = data.metrics;
  const header = ['p50 ms', 'p90 ms', 'p95 ms', 'p99 ms', 'max ms'].map((title) => pad(title, 10)).join('');
  const lines = [];
  const result = { profile: PROFILE, seed: SEED, corpus: CORPUS, setup: data.setup_data, operations: {}, mappings: {}, steps: [] };

  lines.push('', padEnd('operation', 14) + pad('ok', 9) + header + pad('errors', 10) + pad('null', 10) + pad('ms/key', 10));
  for (const name of ops) {
    const trend = metrics[`lat_${name}`];
    const keys = OPERATIONS[name].keys;
    const perKey = keys && trend && trend.values.med !== undefined ? (trend.values.med / keys).toFixed(3) : '-';
    const nulls = name.startsWith('point_') ? percent(metrics[`null_${name}`]) : '-';
    lines.push(row(name, trend, [percent(metrics[`err_${name}`]), nulls, perKey]));
    result.operations[name] = {
      latency: trend ? trend.values : null,
      errorRate: metrics[`err_${name}`] ? metrics[`err_${name}`].values.rate : null,
      nullRate: metrics[`null_${name}`] ? metrics[`null_${name}`].values.rate : null,
      keysPerRequest: keys || 1,
    };
  }

  if (ops.some((name) => PER_MAPPING.includes(name))) {
    const width = Math.max(...groups.map((group) => group.p.length + group.m.length)) + 3;
    lines.push('', padEnd('existing keys, by mapping', width) + pad('ok', 9) + header + pad('null', 10) + pad('keys', 10) + pad('absent', 10));
    groups.forEach((group, index) => {
      const trend = metrics[`map_lat_${index}`];
      lines.push(row(`${group.p}/${group.m}`, trend, [percent(metrics[`map_null_${index}`]), group.length, absent(group).length], width));
      result.mappings[`${group.p}/${group.m}`] = {
        latency: trend ? trend.values : null,
        nullRate: metrics[`map_null_${index}`] ? metrics[`map_null_${index}`].values.rate : null,
        keys: group.length,
        absentKeys: absent(group).length,
      };
    });
  }

  if (PROFILE === 'ramp') {
    lines.push('', padEnd('target req/s', 14) + pad('ok', 9) + header + pad('errors', 10) + pad('ok req/s', 10));
    for (let step = 0; step < STEPS; step++) {
      const trend = metrics[`step_lat_${step}`];
      const achieved = trend && trend.values.count !== undefined ? (trend.values.count / STEP_SECONDS).toFixed(1) : '-';
      lines.push(row(stepRate(step), trend, [percent(metrics[`step_err_${step}`]), achieved]));
      result.steps.push({
        targetRate: stepRate(step),
        latency: trend ? trend.values : null,
        errorRate: metrics[`step_err_${step}`] ? metrics[`step_err_${step}`].values.rate : null,
      });
    }
  }

  const dropped = metrics.dropped_iterations ? metrics.dropped_iterations.values.count : 0;
  const limited = metrics.rate_limited ? metrics.rate_limited.values.rate : 0;
  result.droppedIterations = dropped;
  result.rateLimitedRate = limited;
  lines.push('', `rate limited: ${(limited * 100).toFixed(2)}%   dropped iterations: ${dropped}`);
  if (limited > 0) lines.push('The node returned 429. Raise --rest-rps on the node and run again.');
  if (dropped > 0) lines.push('k6 dropped iterations. The node or this machine did not keep up with the target rate.');

  const out = __ENV.OUT || `history-bench-${PROFILE}-${Date.now()}.json`;
  lines.push(`Wrote ${out}`, '');
  return { [out]: JSON.stringify(result, null, 2), stdout: lines.join('\n') };
}
