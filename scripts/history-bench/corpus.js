// Builds the key corpus for bench.js from a running node.
//
// It samples blocks inside the recorded history ranges, takes the literals that the transactions
// of each program carry, and asks the node which of them are keys of which mapping. All the work
// happens in setup(), and handleSummary() writes the result.
//
//   k6 run -e BASE_URL=http://<node>:3030 corpus.js

import http from 'k6/http';
import { sleep } from 'k6';
import exec from 'k6/execution';

import {
  API,
  MAX_KEYS_PER_REQUEST,
  NETWORK,
  batchUrl,
  coverage,
  envInt,
  envList,
  floorRanges,
  heightAt,
  heightUrl,
  rangesUrl,
  rng,
  selects,
} from './lib.js';

const PROGRAMS = envList('PROGRAMS', 'credits.aleo,shield_swap.aleo');
// Optional. Limits the work to these mappings, each written as `program/mapping`.
const MAPPINGS = envList('MAPPINGS', '');
const OUT = __ENV.CORPUS || 'corpus.json';
// The number of block windows to sample, and the blocks in each. The node serves at most 160.
const WINDOWS = envInt('WINDOWS', 40);
const WINDOW_BLOCKS = Math.min(envInt('WINDOW_BLOCKS', 50), 160);
// Sample no block below this height.
const SAMPLE_FROM = envInt('SAMPLE_FROM', 0);
// The caps on the keys kept for each mapping.
const MAX_KEYS = envInt('MAX_KEYS', 2000);
const MAX_MISSES = envInt('MAX_MISSES', 500);
// The number of block heights at which to test candidates for each mapping.
const PROBE_HEIGHTS = envInt('PROBE_HEIGHTS', 300);
// Stay below the node's `--rest-rps`, which defaults to 10 for each IP address.
const DISCOVERY_RPS = envInt('DISCOVERY_RPS', 4);
const SEED = envInt('SEED', 1);
// Optional. A JSON file of more candidates: { "<program>": { "<mapping>": [{ "key": "...", "height": 123 }] } }.
// Use it for keys that a finalize block derives, for example with a hash.
const EXTRA = __ENV.EXTRA ? JSON.parse(open(__ENV.EXTRA)) : {};
// Optional. With a node JWT, the listed programs' mappings are read whole instead of probed.
const JWT = __ENV.JWT || '';
const DUMP_PROGRAMS = envList('DUMP_PROGRAMS', '');

const PROBE_CHUNK = Math.min(100, MAX_KEYS_PER_REQUEST);
const INTEGER_TYPES = ['u8', 'u16', 'u32', 'u64', 'u128', 'i8', 'i16', 'i32', 'i64', 'i128'];
const NUMERIC_TYPES = INTEGER_TYPES.concat(['field', 'group', 'scalar']);

export const options = {
  vus: 1,
  iterations: 1,
  setupTimeout: __ENV.SETUP_TIMEOUT || '120m',
};

let lastRequest = 0;

// Sends a paced GET. Retries when the node rate-limits the request or fails to answer.
function get(url, params) {
  for (let attempt = 0; attempt < 6; attempt++) {
    const wait = lastRequest + 1000 / DISCOVERY_RPS - Date.now();
    if (wait > 0) sleep(wait / 1000);
    lastRequest = Date.now();
    const response = http.get(url, Object.assign({ timeout: '120s', tags: { name: 'corpus' } }, params || {}));
    if (response.status === 429) {
      sleep(Number(response.headers['Retry-After']) || 2);
      continue;
    }
    if (response.status === 0 || response.status >= 500) {
      sleep(1 + attempt);
      continue;
    }
    return response;
  }
  exec.test.abort(`The node did not answer ${url}`);
}

// Returns the literal pattern for a mapping key type, or null for a type with no literal form.
function literalPattern(type) {
  if (type === 'address') return /aleo1[a-z0-9]{58}/g;
  if (type === 'boolean') return /(?<![a-z0-9_])(?:true|false)(?![a-z0-9_])/g;
  if (NUMERIC_TYPES.includes(type)) return new RegExp(`(?<![a-z0-9_])-?\\d+${type}(?![a-z0-9_])`, 'g');
  return null;
}

// Returns each selected mapping of the program with its key type.
function readMappings(program) {
  const response = get(`${API}/program/${program}`);
  if (response.status !== 200) exec.test.abort(`Cannot read ${program}: ${response.status} ${response.body}`);
  const source = response.json();
  const mappings = {};
  for (const match of source.matchAll(/mapping\s+(\w+):\s*key\s+as\s+(.+?)\.public;/g)) {
    if (selects(MAPPINGS, program, match[1])) mappings[match[1]] = match[2].trim();
  }
  return mappings;
}

// Records, for each program and key type, the literals in the sampled blocks and the first sampled
// height that carries each.
function sampleBlocks(programs, candidates) {
  const union = [];
  for (const program of programs) union.push(...program.ranges);
  union.sort((a, b) => a[0] - b[0]);
  let merged = [];
  for (const [start, end] of union) {
    const last = merged[merged.length - 1];
    if (last && start <= last[1] + 1) last[1] = Math.max(last[1], end);
    else merged.push([start, end]);
  }
  merged = floorRanges(merged, SAMPLE_FROM);
  if (merged.length === 0) exec.test.abort(`No history at or above SAMPLE_FROM=${SAMPLE_FROM}`);

  const total = coverage(merged);
  const windows = Math.min(WINDOWS, Math.max(1, Math.ceil(total / WINDOW_BLOCKS)));
  const random = rng(SEED);
  for (let index = 0; index < windows; index++) {
    // One window in each equal slice of the coverage, at a random position inside the slice.
    const slice = total / windows;
    const start = heightAt(merged, Math.floor(index * slice + random() * Math.max(1, slice - WINDOW_BLOCKS)));
    const url = `${API}/blocks/transactions?start=${start}&end=${start + WINDOW_BLOCKS}&allow_partial=true`;
    const response = get(url);
    if (response.status !== 200) {
      console.warn(`Skipping blocks from ${start}: ${response.status} ${response.body}`);
      continue;
    }
    const blocks = response.json();
    for (let offset = 0; offset < blocks.length; offset++) {
      const height = start + offset;
      for (const transaction of blocks[offset]) {
        const text = JSON.stringify(transaction).replace(/\\n/g, ' ');
        for (const program of programs) {
          if (!text.includes(program.id)) continue;
          for (const type of program.keyTypes) {
            const seen = candidates[program.id][type];
            if (seen.size >= 8 * MAX_KEYS) continue;
            for (const literal of text.match(literalPattern(type)) || []) {
              if (!seen.has(literal)) seen.set(literal, height);
            }
          }
        }
      }
    }
    console.log(`Sampled window ${index + 1}/${windows} at block ${start}`);
  }
}

// Asks the node which candidates are keys of the mapping. Each candidate is tested at the height
// that carries it, because a program can remove a key again in a later block.
function probe(program, mapping, entries) {
  const byHeight = new Map();
  for (const [key, height] of entries) {
    if (!byHeight.has(height)) byHeight.set(height, []);
    byHeight.get(height).push(key);
  }
  // Take the heights at even intervals, so that the keys spread over the whole coverage.
  const heights = [...byHeight.keys()].sort((a, b) => a - b);
  const step = Math.max(1, heights.length / PROBE_HEIGHTS);
  const result = { hits: [], misses: [] };
  for (let position = 0; position < heights.length && result.hits.length < MAX_KEYS; position += step) {
    const height = heights[Math.floor(position)];
    const keys = byHeight.get(height);
    for (let offset = 0; offset < keys.length; offset += PROBE_CHUNK) {
      const chunk = keys.slice(offset, offset + PROBE_CHUNK);
      const response = get(batchUrl(program, mapping, chunk, height));
      // The mapping does not exist yet at this height.
      if (response.status === 404) break;
      if (response.status !== 200) {
        console.warn(`Probe of ${program}/${mapping} failed: ${response.status} ${response.body}`);
        continue;
      }
      const values = response.json();
      for (let index = 0; index < values.length; index++) {
        if (values[index].value !== null) {
          if (result.hits.length < MAX_KEYS) result.hits.push({ key: chunk[index], firstSeen: height, live: false });
        } else if (result.misses.length < MAX_MISSES) {
          result.misses.push(chunk[index]);
        }
      }
    }
  }
  return result;
}

// Marks the keys that the mapping still contains at `height`.
function markLive(program, mapping, hits, height) {
  for (let offset = 0; offset < hits.length; offset += PROBE_CHUNK) {
    const chunk = hits.slice(offset, offset + PROBE_CHUNK);
    const response = get(batchUrl(program, mapping, chunk.map((hit) => hit.key), height));
    if (response.status !== 200) continue;
    const values = response.json();
    for (let index = 0; index < values.length; index++) chunk[index].live = values[index].value !== null;
  }
}

// Returns the first height in the range that ends at `height` where the mapping exists.
// A program can add a mapping after its history starts, and a lookup below that height returns 404.
function firstHeight(program, mapping, key, start, height) {
  let low = start;
  let high = height;
  while (low < high) {
    const middle = Math.floor((low + high) / 2);
    if (get(batchUrl(program, mapping, [key], middle)).status === 200) high = middle;
    else low = middle + 1;
  }
  return low;
}

// Reads a whole mapping through the JWT-protected route and keeps an even sample of its keys.
function dump(program, mapping) {
  const url = `${API}/program/${program}/mapping/${mapping}?all=true`;
  const response = get(url, { headers: { Authorization: `Bearer ${JWT}` }, timeout: '600s' });
  if (response.status !== 200) {
    console.warn(`Dump of ${program}/${mapping} failed: ${response.status} ${response.body}`);
    return null;
  }
  const pairs = response.json();
  const step = Math.max(1, Math.floor(pairs.length / MAX_KEYS));
  const hits = [];
  for (let index = 0; index < pairs.length && hits.length < MAX_KEYS; index += step) {
    // The route returns composite keys on several lines. One line keeps the query string short.
    hits.push({ key: pairs[index][0].replace(/\s+/g, ' '), firstSeen: null, live: true });
  }
  return hits;
}

export function setup() {
  const tipResponse = get(heightUrl());
  if (tipResponse.status !== 200) exec.test.abort(`Cannot read the latest height: ${tipResponse.status}`);
  const tip = tipResponse.json();

  const programs = [];
  for (const id of PROGRAMS) {
    const response = get(rangesUrl(id));
    if (response.status !== 200) exec.test.abort(`Cannot read the history ranges of ${id}: ${response.status} ${response.body}`);
    const ranges = response.json();
    if (ranges.length === 0) {
      console.warn(`The node has no history for ${id}. Skipping it.`);
      continue;
    }
    const mappings = readMappings(id);
    const keyTypes = [...new Set(Object.values(mappings))].filter((type) => literalPattern(type) !== null);
    programs.push({ id, ranges, mappings, keyTypes });
  }
  if (programs.length === 0) exec.test.abort('The node has no history for any of the programs');

  const candidates = {};
  for (const program of programs) {
    candidates[program.id] = {};
    for (const type of program.keyTypes) candidates[program.id][type] = new Map();
  }
  sampleBlocks(programs, candidates);

  const corpus = { network: NETWORK, createdAt: new Date().toISOString(), tip, seed: SEED, programs: {} };
  for (const program of programs) {
    const lastRange = program.ranges[program.ranges.length - 1];
    const entry = { ranges: program.ranges, mappings: {} };
    for (const [mapping, keyType] of Object.entries(program.mappings)) {
      const found = candidates[program.id][keyType];
      const entries = found ? [...found.entries()] : [];
      for (const extra of (EXTRA[program.id] || {})[mapping] || []) entries.push([extra.key, extra.height]);

      let { hits, misses } = probe(program.id, mapping, entries);
      markLive(program.id, mapping, hits, lastRange[1]);
      if (JWT && DUMP_PROGRAMS.includes(program.id)) hits = dump(program.id, mapping) || hits;
      if (entries.length === 0 && hits.length === 0) {
        console.warn(`${program.id}/${mapping} has '${keyType}' keys, which sampling cannot find. Use EXTRA, or JWT and DUMP_PROGRAMS.`);
      }

      const known = hits.length > 0 ? hits[0].key : misses[0];
      const since = known === undefined ? lastRange[0] : firstHeight(program.id, mapping, known, lastRange[0], lastRange[1]);
      entry.mappings[mapping] = { keyType, since, hits, misses };
      console.log(`${program.id}/${mapping} (${keyType}): ${hits.length} keys, ${misses.length} absent keys, since block ${since}`);
    }
    corpus.programs[program.id] = entry;
  }
  return corpus;
}

export default function () {}

export function handleSummary(data) {
  const corpus = data.setup_data;
  if (!corpus) return { stdout: 'No corpus was built.\n' };
  const lines = [`Wrote ${OUT}`];
  for (const [program, entry] of Object.entries(corpus.programs)) {
    lines.push(`  ${program}  ranges ${JSON.stringify(entry.ranges)}`);
    for (const [mapping, { keyType, since, hits, misses }] of Object.entries(entry.mappings)) {
      const live = hits.filter((hit) => hit.live).length;
      lines.push(`    ${mapping} (${keyType}): ${hits.length} keys (${live} still present), ${misses.length} absent keys, since block ${since}`);
    }
  }
  return { [OUT]: JSON.stringify(corpus), stdout: lines.join('\n') + '\n' };
}
