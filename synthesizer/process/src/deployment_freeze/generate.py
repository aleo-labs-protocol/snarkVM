#!/usr/bin/env python3
# Copyright (c) 2019-2026 Provable Inc.
# This file is part of the snarkVM library.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at:
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""Generates `aleo_deployment_freeze.aleo`, the program behind the deployment freeze ARC.

Validators vote by signing a `freeze_vote` payload offline, for example with
`snarkos account sign --message '<literal>'`. Anyone submits signatures from
validators holding a quorum of stake in one `submit_votes` transaction and pays
its fee. The function checks every signature in the circuit; finalize checks the
committee list, tallies the signed stake and applies the action.

Aleo instructions have no loops, so the signature checks and the committee tally
are unrolled over all `COMMITTEE_LIST_LENGTH` slots. Every slot is processed. A
slot at index `i` is "active" when `i < count`; an inactive slot (padding)
contributes nothing and is not checked, except that its mask bit must be clear.
Branching cannot skip the padding, because a register written in skipped code
cannot be read after the jump.

Regenerate with:

    python3 synthesizer/process/src/deployment_freeze/generate.py \
        > synthesizer/process/src/deployment_freeze/aleo_deployment_freeze.aleo

The program is built into the protocol, like `credits.aleo`: nodes load it from this
file and are never sent a deployment of it. Its name contains "aleo", which every
deployment has been refused since `ConsensusVersion::V7`, so no one can deploy a
program under the same ID. Any change to the output changes the circuit, so the
committed verifying keys (`resources/`) must be regenerated with it:

    REGENERATE_DEPLOYMENT_FREEZE_KEYS=1 cargo test --release -p snarkvm-synthesizer-process \
        --lib test_verifying_keys_match_program -- --ignored

`test_verifying_keys_are_for_this_program` fails until they are.
"""

import sys

# The program parameters. Keep in sync with `mod.rs` (`test_constants_match_program` checks them).
COMMITTEE_LIST_LENGTH = 128
FREEZE_DELAY = 60
MAX_FREEZE_BLOCKS = 201_600
# The `credits.aleo/metadata` key that stores the number of committee members.
COMMITTEE_SIZE_KEY = "aleo1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq3ljyzc"
# The `action` of a vote.
ACTION_FREEZE = 1
ACTION_THAW = 2


class Body:
    """Allocates registers in order, as Aleo instructions require."""

    def __init__(self, first):
        self.lines = []
        self.next = first

    def reg(self):
        r = f"r{self.next}"
        self.next += 1
        return r

    def emit(self, line):
        self.lines.append(f"    {line}")

    def comment(self, text):
        self.lines.append(f"    // {text}")

    def blank(self):
        self.lines.append("")


def mask_bit(f, mask, i):
    """Emits bit `i` of the mask, as a u128 that is 0 or 1, and returns its register."""
    shifted = f.reg()
    f.emit(f"shr {mask} {i}u32 into {shifted};")
    bit = f.reg()
    f.emit(f"and {shifted} 1u128 into {bit};")
    return bit


def function_body(f, members, mask, signatures, vote):
    """Checks the domain tag, and the signature in every slot whose mask bit is set."""
    n = COMMITTEE_LIST_LENGTH
    f.comment("The payload is a deployment freeze vote.")
    f.emit(f"assert.eq {vote}.aleo_deployment_freeze true;")
    f.comment("For each slot i: if bit i of the mask is set, signatures[i] is members[i]'s signature over")
    f.comment("the vote. Unset slots carry any valid signature, which is checked and ignored.")
    for i in range(n):
        bit = mask_bit(f, mask, i)
        unset = f.reg()
        f.emit(f"is.eq {bit} 0u128 into {unset};")
        verified = f.reg()
        f.emit(f"sign.verify {signatures}[{i}u32] {members}[{i}u32] {vote} into {verified};")
        ok = f.reg()
        f.emit(f"or {unset} {verified} into {ok};")
        f.emit(f"assert.eq {ok} true;")


def finalize_body(f, members, count, mask, vote):
    """Checks the vote and the committee list, tallies the signed stake, and applies the action."""
    n = COMMITTEE_LIST_LENGTH

    f.comment("1. Check the vote: this network, not expired, the current nonce, and a valid action.")
    same_network = f.reg()
    f.emit(f"is.eq {vote}.network network.id into {same_network};")
    f.emit(f"assert.eq {same_network} true;")
    live = f.reg()
    f.emit(f"lt block.height {vote}.expires into {live};")
    f.emit(f"assert.eq {live} true;")
    nonce = f.reg()
    f.emit(f"get.or_use nonce[0u8] 0u64 into {nonce};")
    f.emit(f"assert.eq {vote}.nonce {nonce};")
    f.comment(f"A freeze has FREEZE_DELAY < duration <= MAX_FREEZE_BLOCKS; a thaw has duration 0.")
    is_freeze = f.reg()
    f.emit(f"is.eq {vote}.action {ACTION_FREEZE}u8 into {is_freeze};")
    long_enough = f.reg()
    f.emit(f"gt {vote}.duration {FREEZE_DELAY}u32 into {long_enough};")
    short_enough = f.reg()
    f.emit(f"lte {vote}.duration {MAX_FREEZE_BLOCKS}u32 into {short_enough};")
    duration_ok = f.reg()
    f.emit(f"and {long_enough} {short_enough} into {duration_ok};")
    freeze_ok = f.reg()
    f.emit(f"and {is_freeze} {duration_ok} into {freeze_ok};")
    is_thaw = f.reg()
    f.emit(f"is.eq {vote}.action {ACTION_THAW}u8 into {is_thaw};")
    no_duration = f.reg()
    f.emit(f"is.eq {vote}.duration 0u32 into {no_duration};")
    thaw_ok = f.reg()
    f.emit(f"and {is_thaw} {no_duration} into {thaw_ok};")
    action_ok = f.reg()
    f.emit(f"or {freeze_ok} {thaw_ok} into {action_ok};")
    f.emit(f"assert.eq {action_ok} true;")
    f.blank()

    f.comment("2. Check that the list is the whole committee.")
    f.comment("2.1. The count equals the committee size, and fits in the list.")
    committee_size = f.reg()
    f.emit(f"get credits.aleo/metadata[{COMMITTEE_SIZE_KEY}] into {committee_size};")
    f.emit(f"assert.eq {committee_size} {count};")
    fits = f.reg()
    f.emit(f"lte {count} {n}u32 into {fits};")
    f.emit(f"assert.eq {fits} true;")
    f.blank()

    f.comment("2.2, 2.3 and 3. For each active slot: the member is in the committee, the list is")
    f.comment("strictly increasing by field cast, and its stake counts toward the total, and toward")
    f.comment("the signed stake if its mask bit is set. An inactive slot (i >= count) must have its")
    f.comment("mask bit clear, and is otherwise ignored.")
    total = "0u64"
    signed = "0u64"
    previous_field = None
    for i in range(n):
        f.comment(f"Slot {i}.")
        member = f"{members}[{i}u32]"
        active = f.reg()
        f.emit(f"lt {i}u32 {count} into {active};")
        inactive = f.reg()
        f.emit(f"not {active} into {inactive};")
        # The mask bit.
        bit = mask_bit(f, mask, i)
        is_set = f.reg()
        f.emit(f"is.eq {bit} 1u128 into {is_set};")
        stray = f.reg()
        f.emit(f"and {is_set} {inactive} into {stray};")
        f.emit(f"assert.eq {stray} false;")
        # The member is in the committee.
        in_committee = f.reg()
        f.emit(f"contains credits.aleo/committee[{member}] into {in_committee};")
        member_ok = f.reg()
        f.emit(f"or {in_committee} {inactive} into {member_ok};")
        f.emit(f"assert.eq {member_ok} true;")
        # The list is strictly increasing.
        as_field = f.reg()
        f.emit(f"cast {member} into {as_field} as field;")
        if previous_field is not None:
            increasing = f.reg()
            f.emit(f"lt {previous_field} {as_field} into {increasing};")
            order_ok = f.reg()
            f.emit(f"or {increasing} {inactive} into {order_ok};")
            f.emit(f"assert.eq {order_ok} true;")
        previous_field = as_field
        # The member's stake, including its self-bond.
        stake = f.reg()
        f.emit(f"get.or_use credits.aleo/delegated[{member}] 0u64 into {stake};")
        counted = f.reg()
        f.emit(f"ternary {active} {stake} 0u64 into {counted};")
        new_total = f.reg()
        f.emit(f"add {total} {counted} into {new_total};")
        total = new_total
        # The member's stake counts as signed if its bit is set (only active slots can have one).
        backing = f.reg()
        f.emit(f"ternary {is_set} {stake} 0u64 into {backing};")
        new_signed = f.reg()
        f.emit(f"add {signed} {backing} into {new_signed};")
        signed = new_signed
    f.blank()

    f.comment("4. The signed stake must reach total * 2 / 3 + 1 (Committee::quorum_threshold).")
    doubled = f.reg()
    f.emit(f"mul {total} 2u64 into {doubled};")
    third = f.reg()
    f.emit(f"div {doubled} 3u64 into {third};")
    threshold = f.reg()
    f.emit(f"add {third} 1u64 into {threshold};")
    passed = f.reg()
    f.emit(f"gte {signed} {threshold} into {passed};")
    f.emit(f"assert.eq {passed} true;")
    f.blank()

    f.comment("5. Apply the action. A freeze that has not ended (in force, or passed and waiting for")
    f.comment("FREEZE_DELAY) keeps its start, so a renewal is continuous. A thaw sets {0, 0}.")
    empty = f.reg()
    f.emit(f"cast 0u32 0u32 into {empty} as freeze_window;")
    current = f.reg()
    f.emit(f"get.or_use freeze[0u8] {empty} into {current};")
    not_ended = f.reg()
    f.emit(f"lt block.height {current}.end into {not_ended};")
    end_freeze = f.reg()
    f.emit(f"add block.height {vote}.duration into {end_freeze};")
    delayed = f.reg()
    f.emit(f"add block.height {FREEZE_DELAY}u32 into {delayed};")
    start_freeze = f.reg()
    f.emit(f"ternary {not_ended} {current}.start {delayed} into {start_freeze};")
    start = f.reg()
    f.emit(f"ternary {is_freeze} {start_freeze} 0u32 into {start};")
    end = f.reg()
    f.emit(f"ternary {is_freeze} {end_freeze} 0u32 into {end};")
    window = f.reg()
    f.emit(f"cast {start} {end} into {window} as freeze_window;")
    f.emit(f"set {window} into freeze[0u8];")
    next_nonce = f.reg()
    f.emit(f"add {nonce} 1u64 into {next_nonce};")
    f.emit(f"set {next_nonce} into nonce[0u8];")


def generate():
    n = COMMITTEE_LIST_LENGTH
    out = []
    out.append("// Generated by generate.py. Do not edit by hand: regenerate, and regenerate the verifying key.")
    out.append("//")
    out.append("// The program behind the deployment freeze ARC. Consensus reads only `freeze[0u8]`:")
    out.append("// from the deployment freeze ConsensusVersion, deployments are frozen in every block")
    out.append("// with `start <= height < end`.")
    out.append("//")
    out.append("// Built into the protocol like credits.aleo: nodes load it from source, and it is never deployed.")
    out.append("//")
    out.append(f"// FREEZE_DELAY = {FREEZE_DELAY}, MAX_FREEZE_BLOCKS = {MAX_FREEZE_BLOCKS}, committee list length = {n}.")
    out.append("")
    out.append("import credits.aleo;")
    out.append("")
    out.append("program aleo_deployment_freeze.aleo;")
    out.append("")
    out.append("struct freeze_window:")
    out.append("    start as u32;")
    out.append("    end as u32;")
    out.append("")
    out.append("// The payload a validator signs, for example with")
    out.append("// `snarkos account sign --message '{ aleo_deployment_freeze: true, network: 0u16, action: 1u8,")
    out.append("// duration: 28800u32, nonce: 0u64, expires: 23500000u32 }'`. The member names are signed, so")
    out.append("// `aleo_deployment_freeze` (always true) ties the signature to this payload.")
    out.append(f"// `action` is {ACTION_FREEZE} (freeze for `duration` blocks) or {ACTION_THAW} (thaw, `duration` 0). `nonce` is")
    out.append("// `nonce[0u8]`. The vote counts while `block.height < expires`.")
    out.append("struct freeze_vote:")
    out.append("    aleo_deployment_freeze as boolean;")
    out.append("    network as u16;")
    out.append("    action as u8;")
    out.append("    duration as u32;")
    out.append("    nonce as u64;")
    out.append("    expires as u32;")
    out.append("")
    out.append("// Deployments are frozen in every block with `start <= height < end`. Absent, or `end = 0`, means not frozen.")
    out.append("mapping freeze:")
    out.append("    key as u8.public;")
    out.append("    value as freeze_window.public;")
    out.append("")
    out.append("// Increases by one each time a vote passes. Absent means 0.")
    out.append("mapping nonce:")
    out.append("    key as u8.public;")
    out.append("    value as u64.public;")
    out.append("")
    out.append("// Applies `vote` with signatures from validators holding a quorum of stake. Anyone can submit.")
    out.append(f"// `members` is the whole committee, sorted by field cast, padded to {n} with the zero address;")
    out.append("// `count` is the committee size; bit i of `signed_mask` marks `signatures[i]` as `members[i]`'s")
    out.append("// signature over `vote`.")
    out.append("function submit_votes:")
    out.append(f"    input r0 as [address; {n}u32].public;")
    out.append("    input r1 as u32.public;")
    out.append("    input r2 as u128.public;")
    out.append(f"    input r3 as [signature; {n}u32].public;")
    out.append("    input r4 as freeze_vote.public;")
    f = Body(5)
    function_body(f, "r0", "r2", "r3", "r4")
    out.extend(f.lines)
    future = f.reg()
    out.append(f"    async submit_votes r0 r1 r2 r4 into {future};")
    out.append(f"    output {future} as aleo_deployment_freeze.aleo/submit_votes.future;")
    out.append("")
    out.append("finalize submit_votes:")
    out.append(f"    input r0 as [address; {n}u32].public;")
    out.append("    input r1 as u32.public;")
    out.append("    input r2 as u128.public;")
    out.append("    input r3 as freeze_vote.public;")
    f = Body(4)
    finalize_body(f, "r0", "r1", "r2", "r3")
    out.extend(f.lines)
    return "\n".join(out) + "\n"


if __name__ == "__main__":
    sys.stdout.write(generate())
