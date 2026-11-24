#!/bin/sh
# Runs bench.js once for each `program/mapping` argument, as separate k6 processes.
# Each run writes its own result and log to results/mappings/, so a failed run affects no other run.
#
#   BASE_URL=http://<node>:3030 JOBS=2 ./run-mappings.sh credits.aleo/account shield_swap.aleo/ticks
#
# JOBS is the number of runs at the same time. Other settings pass through to bench.js, for
# example DURATION and RATE.

set -u
cd "$(dirname "$0")" || exit 1
: "${BASE_URL:?Set BASE_URL to the REST address of the node}"
mkdir -p results/mappings

if [ "${1:-}" = "--one" ]; then
  name=$(printf '%s' "$2" | sed 's|/|__|')
  k6 run -q -e BASE_URL="$BASE_URL" -e MAPPINGS="$2" -e DURATION="${DURATION:-4m}" -e RATE="${RATE:-5}" \
    -e OUT="results/mappings/$name.json" bench.js > "results/mappings/$name.log" 2>&1
  echo "$2 exit=$? $(date +%T)"
  exit 0
fi

printf '%s\n' "$@" | xargs -P "${JOBS:-1}" -n 1 "$0" --one
