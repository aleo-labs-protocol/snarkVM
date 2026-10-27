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

use super::*;

// https://testnet.explorer.provable.com/program/ldgbatcher_p28.aleo
pub const SRC_LDGBATCHER_P28_ALEO: &str = r#"
    import credits.aleo;

    program ldgbatcher_p28.aleo;

    function transfer_private_2:
        input r0 as credits.aleo/credits.record;
        input r1 as credits.aleo/credits.record;
        input r2 as address.private;
        input r3 as u64.private;
        call credits.aleo/join r0 r1 into r4;
        call credits.aleo/transfer_private r4 r2 r3 into r5 r6;
        output r5 as credits.aleo/credits.record;
        output r6 as credits.aleo/credits.record;

    function transfer_private_3:
        input r0 as credits.aleo/credits.record;
        input r1 as credits.aleo/credits.record;
        input r2 as credits.aleo/credits.record;
        input r3 as address.private;
        input r4 as u64.private;
        call credits.aleo/join r0 r1 into r5;
        call credits.aleo/join r2 r5 into r6;
        call credits.aleo/transfer_private r6 r3 r4 into r7 r8;
        output r7 as credits.aleo/credits.record;
        output r8 as credits.aleo/credits.record;

    function transfer_private_4:
        input r0 as credits.aleo/credits.record;
        input r1 as credits.aleo/credits.record;
        input r2 as credits.aleo/credits.record;
        input r3 as credits.aleo/credits.record;
        input r4 as address.private;
        input r5 as u64.private;
        call credits.aleo/join r0 r1 into r6;
        call credits.aleo/join r2 r6 into r7;
        call credits.aleo/join r3 r7 into r8;
        call credits.aleo/transfer_private r8 r4 r5 into r9 r10;
        output r9 as credits.aleo/credits.record;
        output r10 as credits.aleo/credits.record;

    function transfer_private_5:
        input r0 as credits.aleo/credits.record;
        input r1 as credits.aleo/credits.record;
        input r2 as credits.aleo/credits.record;
        input r3 as credits.aleo/credits.record;
        input r4 as credits.aleo/credits.record;
        input r5 as address.private;
        input r6 as u64.private;
        call credits.aleo/join r0 r1 into r7;
        call credits.aleo/join r2 r7 into r8;
        call credits.aleo/join r3 r8 into r9;
        call credits.aleo/join r4 r9 into r10;
        call credits.aleo/transfer_private r10 r5 r6 into r11 r12;
        output r11 as credits.aleo/credits.record;
        output r12 as credits.aleo/credits.record;

    function transfer_private_6:
        input r0 as credits.aleo/credits.record;
        input r1 as credits.aleo/credits.record;
        input r2 as credits.aleo/credits.record;
        input r3 as credits.aleo/credits.record;
        input r4 as credits.aleo/credits.record;
        input r5 as credits.aleo/credits.record;
        input r6 as address.private;
        input r7 as u64.private;
        call credits.aleo/join r0 r1 into r8;
        call credits.aleo/join r2 r8 into r9;
        call credits.aleo/join r3 r9 into r10;
        call credits.aleo/join r4 r10 into r11;
        call credits.aleo/join r5 r11 into r12;
        call credits.aleo/transfer_private r12 r6 r7 into r13 r14;
        output r13 as credits.aleo/credits.record;
        output r14 as credits.aleo/credits.record;

    function transfer_private_7:
        input r0 as credits.aleo/credits.record;
        input r1 as credits.aleo/credits.record;
        input r2 as credits.aleo/credits.record;
        input r3 as credits.aleo/credits.record;
        input r4 as credits.aleo/credits.record;
        input r5 as credits.aleo/credits.record;
        input r6 as credits.aleo/credits.record;
        input r7 as address.private;
        input r8 as u64.private;
        call credits.aleo/join r0 r1 into r9;
        call credits.aleo/join r2 r9 into r10;
        call credits.aleo/join r3 r10 into r11;
        call credits.aleo/join r4 r11 into r12;
        call credits.aleo/join r5 r12 into r13;
        call credits.aleo/join r6 r13 into r14;
        call credits.aleo/transfer_private r14 r7 r8 into r15 r16;
        output r15 as credits.aleo/credits.record;
        output r16 as credits.aleo/credits.record;

    function transfer_private_8:
        input r0 as credits.aleo/credits.record;
        input r1 as credits.aleo/credits.record;
        input r2 as credits.aleo/credits.record;
        input r3 as credits.aleo/credits.record;
        input r4 as credits.aleo/credits.record;
        input r5 as credits.aleo/credits.record;
        input r6 as credits.aleo/credits.record;
        input r7 as credits.aleo/credits.record;
        input r8 as address.private;
        input r9 as u64.private;
        call credits.aleo/join r0 r1 into r10;
        call credits.aleo/join r2 r10 into r11;
        call credits.aleo/join r3 r11 into r12;
        call credits.aleo/join r4 r12 into r13;
        call credits.aleo/join r5 r13 into r14;
        call credits.aleo/join r6 r14 into r15;
        call credits.aleo/join r7 r15 into r16;
        call credits.aleo/transfer_private r16 r8 r9 into r17 r18;
        output r17 as credits.aleo/credits.record;
        output r18 as credits.aleo/credits.record;

    constructor:
        assert.eq edition 0u16;
    "#;
