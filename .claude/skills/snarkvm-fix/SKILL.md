---
name: snarkvm-fix
description: |
  Fix GitHub issues or PR review feedback in snarkVM using TDD workflow.
  WHEN: User says "fix issue", "fix #123", "fix pr", "fix PR feedback",
  "address review comments", "resolve review threads", or wants to fix
  a bug/feature request from GitHub issues or address reviewer requests.
  WHEN NOT: Doing security review (use snarkvm-review), fetching context
  only (use snarkvm-github), or working on non-snarkVM code.
allowed-tools: Bash, Read, Write, Grep, Glob, Task, AskUserQuestion
---

# Fix Issue or PR Feedback

Fix snarkVM GitHub issues or PR review comments using test-driven development.

## Usage

```
/snarkvm-fix issue <number>
/snarkvm-fix pr <number>
```

## Setup

```bash
MODE="${ARGUMENTS%% *}"   # "issue" or "pr"
NUM="${ARGUMENTS#* }"     # the number
WS=".claude/workspace"
SKILL_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../snarkvm-github" && pwd)"
```

## 1. Load Context

**For issues:**
```bash
if [[ ! -f "$WS/state-issue-$NUM.md" ]]; then
  "$SKILL_DIR/scripts/fetch-issue.sh" "$NUM"
fi
```
Review: `$WS/state-issue-$NUM.md` and recent comments.

**For PRs:**
```bash
if [[ ! -f "$WS/state-pr-$NUM.md" ]]; then
  "$SKILL_DIR/scripts/fetch-pr.sh" "$NUM"
fi
"$SKILL_DIR/scripts/refresh-threads.sh" "$NUM"
```
Review: `$WS/state-pr-$NUM.md`, `$WS/unresolved-pr-$NUM.json`, and `$WS/handoff-pr-$NUM.md` if present.

## 2. Investigate

**For issues** — search for related code. Answer:
1. What is the expected vs actual behavior?
2. Where does the code path go wrong?
3. What are the edge cases?

**For PRs** — analyze each unresolved comment:

| # | Path:Line | Reviewer | Request | Type | Risk |
|---|-----------|----------|---------|------|------|

**Where to look:**
- Console type bugs -> `console/` (types, program, network)
- Circuit bugs -> `circuit/` (must stay in sync with console)
- Synthesizer bugs -> `synthesizer/` (program execution, VM, process)
- Crypto bugs -> `algorithms/` (Poseidon, Marlin, Polycommit)
- Serialization bugs -> check `ToBytes`/`FromBytes`/`Serialize`/`Deserialize` impls

**Think hard. Do not proceed until you understand the root cause or each request.**

## 3. Plan (APPROVAL REQUIRED)

Present a concrete plan:

| # | Location | Change | Test | Risk |
|---|----------|--------|------|------|

**Use AskUserQuestion to get explicit approval before proceeding.**

## 4. Implement (TDD)

For each change:
1. **Write failing test** that reproduces the bug or covers the new behavior
2. **Verify it fails**: `cargo test -p <crate> -- --include-ignored test_name --nocapture`
3. **Implement minimal fix** — match existing code style
4. **Verify it passes**: `cargo test -p <crate> -- --include-ignored test_name --nocapture`

For pure style/nit fixes (no behavioral change), batch them without tests.

## 5. Final Validation

Validate affected crates per AGENTS.md.

## 6. Report

```
**Target**: #NUM — [title]
**Root cause**: [brief explanation]
**Fix**: [what changed and why]
**Test**: [what the test verifies]
**Files changed**:
- path/to/file.rs — [change description]
```

**Do not commit unless explicitly asked.**

## Handling Disagreements (PR mode)

If you disagree with a review comment:
1. Explain your reasoning with evidence
2. Propose an alternative if applicable
3. **Use AskUserQuestion** to discuss before proceeding

Never silently ignore review feedback.
