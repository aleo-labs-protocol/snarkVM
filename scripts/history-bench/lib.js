// Shared helpers for the program mapping history benchmark.

export const BASE_URL = (__ENV.BASE_URL || '').replace(/\/+$/, '');
if (!BASE_URL) {
  throw new Error('Set BASE_URL to the REST address of the node, for example BASE_URL=http://10.0.0.5:3030');
}

export const NETWORK = __ENV.NETWORK || 'mainnet';
// The history routes return typed errors only under v2. The v1 routes turn every error into a 500.
export const API = `${BASE_URL}/v2/${NETWORK}`;

// The node rejects a batch request with more keys than this.
export const MAX_KEYS_PER_REQUEST = 128;

export function envInt(name, fallback) {
  const raw = __ENV[name];
  if (raw === undefined || raw === '') return fallback;
  const value = Number(raw);
  if (!Number.isFinite(value)) throw new Error(`${name} must be a number, got '${raw}'`);
  return Math.floor(value);
}

export function envList(name, fallback) {
  const raw = __ENV[name];
  const source = raw === undefined || raw === '' ? fallback : raw;
  return source.split(',').map((item) => item.trim()).filter((item) => item.length > 0);
}

// Returns whether a filter of `program/mapping` names selects the mapping. An empty filter selects all.
export function selects(filter, program, mapping) {
  return filter.length === 0 || filter.includes(`${program}/${mapping}`);
}

export function heightUrl() {
  return `${API}/block/height/latest`;
}

export function rangesUrl(program) {
  return `${API}/program/${program}/history/ranges`;
}

export function latestValueUrl(program, mapping, key) {
  return `${API}/program/${program}/mapping/${mapping}/${encodeURIComponent(key)}`;
}

export function pointUrl(program, mapping, key, height) {
  return `${API}/program/${program}/mapping/${mapping}/${encodeURIComponent(key)}/history/${height}`;
}

export function batchUrl(program, mapping, keys, height) {
  return `${API}/program/${program}/mapping/${mapping}/history/${height}?keys=${encodeURIComponent(keys.join(','))}`;
}

// Returns a deterministic generator of floats in [0, 1) (mulberry32). k6 cannot seed Math.random,
// and a repeatable request sequence is what separates a cold run from a warm one.
export function rng(seed) {
  let state = seed >>> 0;
  return () => {
    state = (state + 0x6d2b79f5) >>> 0;
    let t = state;
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

// Returns the number of heights the inclusive ranges cover.
export function coverage(ranges) {
  return ranges.reduce((total, [start, end]) => total + (end - start + 1), 0);
}

// Maps an offset in [0, coverage) to a covered height.
export function heightAt(ranges, offset) {
  let remaining = offset;
  for (const [start, end] of ranges) {
    const length = end - start + 1;
    if (remaining < length) return start + remaining;
    remaining -= length;
  }
  const last = ranges[ranges.length - 1];
  return last[1];
}

// Drops the part of each range above `maxHeight`.
export function clampRanges(ranges, maxHeight) {
  return ranges.filter(([start]) => start <= maxHeight).map(([start, end]) => [start, Math.min(end, maxHeight)]);
}

// Drops the part of each range below `minHeight`.
export function floorRanges(ranges, minHeight) {
  return ranges.filter(([, end]) => end >= minHeight).map(([start, end]) => [Math.max(start, minHeight), end]);
}

export function pad(value, width) {
  const text = String(value);
  return text.length >= width ? text : ' '.repeat(width - text.length) + text;
}

export function padEnd(value, width) {
  const text = String(value);
  return text.length >= width ? text : text + ' '.repeat(width - text.length);
}
