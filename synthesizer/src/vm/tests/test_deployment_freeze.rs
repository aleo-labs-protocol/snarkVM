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

//! Tests for the deployment freeze (`aleo_deployment_freeze.aleo` and the consensus rule from
//! `DEPLOYMENT_FREEZE_CONSENSUS_VERSION`).
//!
//! The test network has four validators with stakes `M+1, M+1, 2M+1, 2M` (where `M` is
//! `MIN_VALIDATOR_STAKE`), so the total is `6M+3` and the threshold `total * 2 / 3 + 1` is `4M+3`.
//! Validators 0, 1 and 3 together hold `4M+2`, one microcredit below it. Validators 0, 1 and 2
//! together hold exactly `4M+3`. Blocks carry no reward ratifications, so stakes never change.

use super::*;

use console::account::{Signature, ViewKey};
use snarkvm_ledger_block::{Header, Metadata, Transactions};
use snarkvm_ledger_committee::MIN_VALIDATOR_STAKE;
use snarkvm_synthesizer_process::{
    deployment_freeze::{
        ACTION_FREEZE,
        ACTION_THAW,
        DEPLOYMENT_FREEZE_CONSENSUS_VERSION,
        DEPLOYMENT_FREEZE_PROGRAM_ID,
        FREEZE_DELAY,
        FREEZE_MAPPING,
        FreezeVote,
        FreezeWindow,
        MAX_FREEZE_BLOCKS,
        MAX_FROZEN_DEPLOYMENTS_PER_BLOCK,
        NONCE_MAPPING,
        SUBMIT_VOTES_FUNCTION,
        committee_list,
        deployment_freeze_program,
        deployment_freeze_program_id,
        signed_slots,
        submit_votes_inputs,
        submit_votes_verifying_key,
    },
    frozen_deployment_minimum_cost,
};
use snarkvm_synthesizer_snark::VerifyingKey;

use std::sync::OnceLock;

/// The stakes of the four test validators.
fn stakes() -> [u64; 4] {
    let m = MIN_VALIDATOR_STAKE;
    [m + 1, m + 1, 2 * m + 1, 2 * m]
}

/// Returns the validator keys and the genesis block of the test network, shared across tests.
fn quorum_genesis(rng: &mut TestRng) -> (Vec<PrivateKey<CurrentNetwork>>, Block<CurrentNetwork>) {
    static INSTANCE: OnceLock<(Vec<PrivateKey<CurrentNetwork>>, Block<CurrentNetwork>)> = OnceLock::new();
    INSTANCE
        .get_or_init(|| {
            let keys: Vec<_> = (0..4).map(|_| PrivateKey::<CurrentNetwork>::new(rng).unwrap()).collect();
            let addresses: Vec<_> = keys.iter().map(|key| Address::try_from(key).unwrap()).collect();
            let stakes = stakes();
            let members: IndexMap<_, _> =
                addresses.iter().zip_eq(stakes).map(|(address, stake)| (*address, (stake, true, 0u8))).collect();
            let committee = Committee::<CurrentNetwork>::new_genesis(members).unwrap();
            let bonded_balances: IndexMap<_, _> = addresses
                .iter()
                .zip_eq(stakes)
                .map(|(address, stake)| (*address, (*address, *address, stake)))
                .collect();
            let remaining = CurrentNetwork::STARTING_SUPPLY - stakes.iter().sum::<u64>();
            let mut public_balances: IndexMap<_, _> =
                addresses.iter().map(|address| (*address, remaining / 4)).collect();
            // Give the remainder to the first validator, so that the total supply matches.
            *public_balances.get_mut(&addresses[0]).unwrap() += remaining % 4;
            let genesis =
                sample_vm().genesis_quorum(&keys[0], committee, public_balances, bonded_balances, rng).unwrap();
            (keys, genesis)
        })
        .clone()
}

/// A test network: a VM on the quorum genesis, and the validator keys.
struct Env {
    vm: VM<CurrentNetwork, LedgerType>,
    keys: Vec<PrivateKey<CurrentNetwork>>,
}

impl Env {
    fn new(rng: &mut TestRng) -> Self {
        let (keys, genesis) = quorum_genesis(rng);
        let vm = sample_vm();
        vm.add_next_block(&genesis).unwrap();
        Self { vm, keys }
    }

    fn address(&self, index: usize) -> Address<CurrentNetwork> {
        Address::try_from(&self.keys[index]).unwrap()
    }

    fn height(&self) -> u32 {
        self.vm.block_store().current_block_height()
    }

    /// Builds the next block, without reward ratifications, and returns it with its finalize state.
    fn next_block(
        &self,
        transactions: &[Transaction<CurrentNetwork>],
        rng: &mut TestRng,
    ) -> (Block<CurrentNetwork>, FinalizeGlobalState) {
        self.build_block(transactions, true, rng)
    }

    /// Builds the next block like `next_block`, but without the builder's `check_transaction` on each
    /// transaction, so a transaction whose execution has no proof reaches finalize. `check_speculate`
    /// verifies only the fee of a rejected execution, so such a block passes it if finalize rejects them.
    fn next_block_unverified(
        &self,
        transactions: &[Transaction<CurrentNetwork>],
        rng: &mut TestRng,
    ) -> (Block<CurrentNetwork>, FinalizeGlobalState) {
        self.build_block(transactions, false, rng)
    }

    fn build_block(
        &self,
        transactions: &[Transaction<CurrentNetwork>],
        verify: bool,
        rng: &mut TestRng,
    ) -> (Block<CurrentNetwork>, FinalizeGlobalState) {
        let vm = &self.vm;
        let block_hash = vm.block_store().get_block_hash(vm.block_store().max_height().unwrap()).unwrap().unwrap();
        let previous_block = vm.block_store().get_block(&block_hash).unwrap().unwrap();
        let height = previous_block.height() + 1;
        let time_since_last_block = CurrentNetwork::BLOCK_TIME as i64;
        let timestamp = previous_block.timestamp().saturating_add(time_since_last_block);
        let state = FinalizeGlobalState::from(height as u64, height, Some(timestamp), [0u8; 32], None, None);
        let (ratifications, transactions, aborted_transaction_ids, ratified_finalize_operations) = if verify {
            vm.speculate(state, time_since_last_block, None, vec![], &None.into(), transactions.iter(), rng).unwrap()
        } else {
            let deployments_frozen = vm.deployments_frozen_at(height).unwrap();
            let (ratifications, confirmed, aborted, operations) = vm
                .atomic_speculate(
                    state,
                    time_since_last_block,
                    None,
                    vec![],
                    None.into(),
                    transactions.to_vec(),
                    deployments_frozen,
                )
                .unwrap();
            let aborted = aborted.iter().map(|(transaction, _)| transaction.id()).collect();
            (ratifications, confirmed.into_iter().collect(), aborted, operations)
        };
        let metadata = Metadata::new(
            CurrentNetwork::ID,
            previous_block.round() + 1,
            height,
            0,
            0,
            CurrentNetwork::GENESIS_COINBASE_TARGET,
            CurrentNetwork::GENESIS_PROOF_TARGET,
            previous_block.last_coinbase_target(),
            previous_block.last_coinbase_timestamp(),
            timestamp,
        )
        .unwrap();
        let header = Header::from(
            vm.block_store().current_state_root(),
            transactions.to_transactions_root().unwrap(),
            transactions.to_finalize_root(ratified_finalize_operations).unwrap(),
            ratifications.to_ratifications_root().unwrap(),
            Field::zero(),
            Field::zero(),
            metadata,
        )
        .unwrap();
        let block = Block::new_beacon(
            &self.keys[0],
            previous_block.hash(),
            header,
            ratifications,
            None.into(),
            vec![],
            transactions,
            aborted_transaction_ids,
            rng,
        )
        .unwrap();
        (block, state)
    }

    /// Builds the next block, checks it with `check_speculate`, adds it, and returns it.
    fn add_block(&self, transactions: &[Transaction<CurrentNetwork>], rng: &mut TestRng) -> Block<CurrentNetwork> {
        self.add_built_block(self.next_block(transactions, rng), rng)
    }

    /// Builds the next block with `next_block_unverified` and adds it without `check_speculate`, which
    /// verifies the proof of every accepted execution. This serves for blocks that accept unproven
    /// submissions: those tests check what finalize does, and the proven path and the block checker
    /// are covered by `add_block` in the activation and threshold tests.
    fn add_block_unchecked(
        &self,
        transactions: &[Transaction<CurrentNetwork>],
        rng: &mut TestRng,
    ) -> Block<CurrentNetwork> {
        let (block, _) = self.next_block_unverified(transactions, rng);
        self.vm.add_next_block(&block).unwrap();
        block
    }

    /// Like `add_block`, but builds the block with `next_block_unverified`.
    fn add_block_unverified(
        &self,
        transactions: &[Transaction<CurrentNetwork>],
        rng: &mut TestRng,
    ) -> Block<CurrentNetwork> {
        self.add_built_block(self.next_block_unverified(transactions, rng), rng)
    }

    fn add_built_block(
        &self,
        (block, state): (Block<CurrentNetwork>, FinalizeGlobalState),
        rng: &mut TestRng,
    ) -> Block<CurrentNetwork> {
        self.vm
            .check_speculate(
                state,
                CurrentNetwork::BLOCK_TIME as i64,
                block.ratifications(),
                block.solutions(),
                block.transactions(),
                rng,
            )
            .unwrap();
        self.vm.add_next_block(&block).unwrap();
        block
    }

    /// Adds empty blocks until the tip is at `height`.
    fn advance_to(&self, height: u32, rng: &mut TestRng) {
        while self.height() < height {
            self.add_block(&[], rng);
        }
    }

    /// Returns the committed value of `{program}/{name}[key]`.
    fn mapping(&self, program: &str, name: &str, key: Plaintext<CurrentNetwork>) -> Option<Value<CurrentNetwork>> {
        self.vm
            .finalize_store()
            .get_value_confirmed(ProgramID::from_str(program).unwrap(), Identifier::from_str(name).unwrap(), &key)
            .unwrap()
    }

    fn public_balance(&self, address: Address<CurrentNetwork>) -> u64 {
        match self.mapping("credits.aleo", "account", Plaintext::from(Literal::Address(address))) {
            Some(Value::Plaintext(Plaintext::Literal(Literal::U64(balance), _))) => *balance,
            value => panic!("Unexpected balance {value:?}"),
        }
    }

    /// Returns the raw committed value of `freeze[0u8]`.
    fn freeze_value(&self) -> Option<FreezeWindow> {
        self.mapping(DEPLOYMENT_FREEZE_PROGRAM_ID, FREEZE_MAPPING, key_0u8())
            .map(|value| FreezeWindow::from_value(&value).unwrap())
    }

    /// Returns `nonce[0u8]`, which is 0 until a vote passes.
    fn nonce(&self) -> u64 {
        match self.mapping(DEPLOYMENT_FREEZE_PROGRAM_ID, NONCE_MAPPING, key_0u8()) {
            Some(Value::Plaintext(Plaintext::Literal(Literal::U64(nonce), _))) => *nonce,
            None => 0,
            value => panic!("Unexpected nonce {value:?}"),
        }
    }

    /// Writes `freeze[0u8]` directly into committed state, bypassing the program. The mapping exists
    /// from the activation block.
    fn write_freeze(&self, start: u32, end: u32) {
        let value = Value::from_str(&format!("{{ start: {start}u32, end: {end}u32 }}")).unwrap();
        self.vm
            .finalize_store()
            .insert_key_value(
                deployment_freeze_program_id::<CurrentNetwork>(),
                Identifier::from_str(FREEZE_MAPPING).unwrap(),
                key_0u8(),
                value,
            )
            .unwrap();
    }

    /// The committee members, sorted by field cast, without the padding.
    fn committee_list(&self) -> Vec<Address<CurrentNetwork>> {
        let (mut list, count) = committee_list((0..4).map(|index| self.address(index))).unwrap();
        list.truncate(count as usize);
        list
    }

    /// The payload of a vote on the current nonce that expires in 1,000 blocks. `action` is
    /// `Some(duration)` for a freeze and `None` for a thaw.
    fn vote_literal(&self, action: Option<u32>) -> String {
        let (action, duration) = match action {
            Some(duration) => (ACTION_FREEZE, duration),
            None => (ACTION_THAW, 0),
        };
        FreezeVote {
            network: CurrentNetwork::ID,
            action,
            duration,
            nonce: self.nonce(),
            expires: self.height() + 1_000,
        }
        .literal()
    }

    /// Returns the mask and the signature array for `literal` signed by the given validators, laid
    /// out against `list`. Slots not signed carry the dummy signature.
    fn sign_list(
        &self,
        list: &[Address<CurrentNetwork>],
        signers: &[usize],
        literal: &str,
        rng: &mut TestRng,
    ) -> (u128, Vec<Signature<CurrentNetwork>>) {
        signed_slots(list, |member| {
            let index = signers.iter().find(|index| self.address(**index) == *member)?;
            Some(sign_literal(&self.keys[*index], literal, rng))
        })
        .unwrap()
    }

    /// Builds a `submit_votes` transaction paid by `submitter`. The list is padded to the full length
    /// with the zero address, and the signatures with the dummy signature. Fails if the function
    /// fails, as it does for a bad signature in a set slot.
    #[allow(clippy::too_many_arguments)]
    fn try_submit_raw(
        &self,
        submitter: &PrivateKey<CurrentNetwork>,
        members: &[Address<CurrentNetwork>],
        count: u32,
        mask: u128,
        signatures: &[Signature<CurrentNetwork>],
        literal: &str,
        rng: &mut TestRng,
    ) -> Result<Transaction<CurrentNetwork>> {
        let inputs = submit_votes_inputs(members, count, mask, signatures, literal)?;
        self.vm
            .execute(submitter, (DEPLOYMENT_FREEZE_PROGRAM_ID, "submit_votes"), inputs.into_iter(), None, 0, None, rng)
            .map_err(|error| anyhow!("{error}"))
    }

    /// Builds a `submit_votes` transaction like `try_submit_raw`, but without proving the execution;
    /// the fee is proven. It serves for submissions that finalize rejects, in blocks built with
    /// `next_block_unverified`, and for those that `check_transaction` refuses before it verifies the
    /// proof. It saves a proof of a 1.37M-constraint circuit, tens of seconds, each.
    #[allow(clippy::too_many_arguments)]
    fn try_submit_unproven_raw(
        &self,
        submitter: &PrivateKey<CurrentNetwork>,
        members: &[Address<CurrentNetwork>],
        count: u32,
        mask: u128,
        signatures: &[Signature<CurrentNetwork>],
        literal: &str,
        rng: &mut TestRng,
    ) -> Result<Transaction<CurrentNetwork>> {
        let inputs = submit_votes_inputs(members, count, mask, signatures, literal)?;
        let authorization =
            self.vm.authorize(submitter, DEPLOYMENT_FREEZE_PROGRAM_ID, SUBMIT_VOTES_FUNCTION, inputs.iter(), rng)?;
        let execution = Execution::from(
            authorization.transitions().into_values(),
            self.vm.block_store().current_state_root(),
            None,
        )?;
        let consensus_version = CurrentNetwork::CONSENSUS_VERSION(self.height())?;
        let (cost, _) = execution_cost(self.vm.process(), &execution, consensus_version)?;
        let fee = self.vm.authorize_fee_public(submitter, cost, 0, execution.to_execution_id()?, rng)?;
        let fee = self.vm.execute_fee_authorization(fee, None, rng)?;
        Transaction::from_execution(execution, Some(fee))
    }

    /// Like `submit_with`, without proving the execution. See `try_submit_unproven_raw`.
    fn submit_unproven_with(
        &self,
        list: &[Address<CurrentNetwork>],
        count: u32,
        signers: &[usize],
        literal: &str,
        rng: &mut TestRng,
    ) -> Transaction<CurrentNetwork> {
        let (mask, signatures) = self.sign_list(list, signers, literal, rng);
        self.try_submit_unproven_raw(&self.keys[0].clone(), list, count, mask, &signatures, literal, rng).unwrap()
    }

    /// Builds a submission of `literal` signed by `signers` against `list`, paid by validator 0.
    fn submit_with(
        &self,
        list: &[Address<CurrentNetwork>],
        count: u32,
        signers: &[usize],
        literal: &str,
        rng: &mut TestRng,
    ) -> Transaction<CurrentNetwork> {
        let (mask, signatures) = self.sign_list(list, signers, literal, rng);
        self.try_submit_raw(&self.keys[0].clone(), list, count, mask, &signatures, literal, rng).unwrap()
    }

    /// Like `submit`, without proving the execution. See `try_submit_unproven_raw`.
    fn submit_unproven(
        &self,
        signers: &[usize],
        action: Option<u32>,
        rng: &mut TestRng,
    ) -> Transaction<CurrentNetwork> {
        let literal = self.vote_literal(action);
        self.submit_unproven_with(&self.committee_list(), 4, signers, &literal, rng)
    }

    /// Builds an honest submission of a vote on the current nonce, signed by `signers`, paid by validator 0.
    fn submit(&self, signers: &[usize], action: Option<u32>, rng: &mut TestRng) -> Transaction<CurrentNetwork> {
        let literal = self.vote_literal(action);
        self.submit_with(&self.committee_list(), 4, signers, &literal, rng)
    }

    /// Builds a deployment of a small program from validator `index`.
    fn deploy(&self, index: usize, name: &str, rng: &mut TestRng) -> Transaction<CurrentNetwork> {
        self.vm.deploy(&self.keys[index], &small_program(name), None, 0, None, rng).unwrap()
    }

    /// Builds a deploy transaction for `deployment` as it is signed, paying `base_fee` publicly from
    /// validator `index`. The fee is authorized for `fee_id`, which is normally the deployment ID.
    fn deploy_transaction(
        &self,
        index: usize,
        deployment: Deployment<CurrentNetwork>,
        base_fee: u64,
        fee_id: Field<CurrentNetwork>,
        rng: &mut TestRng,
    ) -> Transaction<CurrentNetwork> {
        let key = &self.keys[index];
        let owner = ProgramOwner::new(key, deployment.to_deployment_id().unwrap(), rng).unwrap();
        let authorization = self.vm.authorize_fee_public(key, base_fee, 0, fee_id, rng).unwrap();
        let fee = self.vm.execute_fee_authorization(authorization, None, rng).unwrap();
        Transaction::from_deployment(owner, deployment, fee).unwrap()
    }

    /// Builds a deploy transaction for `deployment`, signed as version 2 by validator `index`, which
    /// pays the frozen minimum privately from `credits`.
    fn deploy_private(
        &self,
        index: usize,
        deployment: Deployment<CurrentNetwork>,
        credits: Record<CurrentNetwork, Plaintext<CurrentNetwork>>,
        rng: &mut TestRng,
    ) -> Transaction<CurrentNetwork> {
        let key = &self.keys[index];
        let deployment = as_version_2(deployment, self.address(index));
        let base_fee = frozen_deployment_minimum_cost(&deployment).unwrap();
        let deployment_id = deployment.to_deployment_id().unwrap();
        let owner = ProgramOwner::new(key, deployment_id, rng).unwrap();
        let authorization = self.vm.authorize_fee_private(key, credits, base_fee, 0, deployment_id, rng).unwrap();
        let fee = self.vm.execute_fee_authorization(authorization, None, rng).unwrap();
        Transaction::from_deployment(owner, deployment, fee).unwrap()
    }

    /// Builds a `transfer_public_to_private` of 1,000 credits from validator `index` to itself.
    fn transfer_to_private(&self, index: usize, rng: &mut TestRng) -> Transaction<CurrentNetwork> {
        let inputs = [
            Value::<CurrentNetwork>::from_str(&self.address(index).to_string()).unwrap(),
            Value::from_str("1000000000u64").unwrap(),
        ];
        self.vm
            .execute(
                &self.keys[index],
                ("credits.aleo", "transfer_public_to_private"),
                inputs.iter(),
                None,
                0,
                None,
                rng,
            )
            .unwrap()
    }

    /// Returns the record that `transfer_to_private` from validator `index` created.
    fn private_credits(
        &self,
        index: usize,
        transfer: &Transaction<CurrentNetwork>,
    ) -> Record<CurrentNetwork, Plaintext<CurrentNetwork>> {
        let view_key = ViewKey::try_from(&self.keys[index]).unwrap();
        transfer.records().next().unwrap().1.decrypt(&view_key).unwrap()
    }

    /// Builds a deploy transaction for `deployment`, signed as version 2 by validator `index`, which
    /// pays `fee(frozen_min)` publicly, where `frozen_min` is the frozen minimum of the signed deployment.
    fn deploy_with(
        &self,
        index: usize,
        deployment: Deployment<CurrentNetwork>,
        fee: impl FnOnce(u64) -> u64,
        rng: &mut TestRng,
    ) -> Transaction<CurrentNetwork> {
        let deployment = as_version_2(deployment, self.address(index));
        let base_fee = fee(frozen_deployment_minimum_cost(&deployment).unwrap());
        let deployment_id = deployment.to_deployment_id().unwrap();
        self.deploy_transaction(index, deployment, base_fee, deployment_id, rng)
    }
}

/// Signs `literal` as `snarkos account sign --message '<literal>'` does.
fn sign_literal(key: &PrivateKey<CurrentNetwork>, literal: &str, rng: &mut TestRng) -> Signature<CurrentNetwork> {
    let fields = Value::<CurrentNetwork>::from_str(literal).unwrap().to_fields().unwrap();
    key.sign(&fields, rng).unwrap()
}

/// The key of the single entry in `freeze` and `nonce`.
fn key_0u8() -> Plaintext<CurrentNetwork> {
    Plaintext::from(Literal::U8(U8::new(0)))
}

/// Signs the deployment as deployment version 2 for `owner`: it records the program checksum and owner.
fn as_version_2(
    mut deployment: Deployment<CurrentNetwork>,
    owner: Address<CurrentNetwork>,
) -> Deployment<CurrentNetwork> {
    deployment.set_program_checksum_raw(Some(deployment.program().to_checksum()));
    deployment.set_program_owner_raw(Some(owner));
    deployment
}

/// The source of a small, valid program.
fn small_program_source(name: &str) -> String {
    format!(
        r"
program {name}.aleo;

function first:
    input r0 as u8.public;
    add r0 1u8 into r1;
    output r1 as u8.public;

function second:
    input r0 as u16.public;
    add r0 1u16 into r1;
    output r1 as u16.public;

constructor:
    assert.eq true true;
"
    )
}

/// A small, valid program.
fn small_program(name: &str) -> Program<CurrentNetwork> {
    Program::from_str(&small_program_source(name)).unwrap()
}

/// Returns a deployment of the freeze program at `edition`, with its committed verifying key and a
/// certificate borrowed from another program. It is well formed, so it reaches the VM's checks.
fn freeze_program_deployment(edition: u16, rng: &mut TestRng) -> Deployment<CurrentNetwork> {
    let other = sample_vm().process().deploy::<CurrentAleo, _>(&small_program("freeze_test_borrowed"), rng).unwrap();
    let certificate = other.verifying_keys()[0].1.1.clone();
    let program = deployment_freeze_program::<CurrentNetwork>().unwrap();
    let verifying_key = submit_votes_verifying_key::<CurrentNetwork>().unwrap();
    let name = Identifier::from_str(SUBMIT_VOTES_FUNCTION).unwrap();
    Deployment::new(edition, program, vec![(name, (verifying_key, certificate))], None, None).unwrap()
}

/// The source of a small program that imports the freeze program.
fn importing_program(name: &str) -> Program<CurrentNetwork> {
    Program::from_str(&format!(
        r"
import {DEPLOYMENT_FREEZE_PROGRAM_ID};

program {name}.aleo;

function noop:
    input r0 as u8.public;
    output r0 as u8.public;

constructor:
    assert.eq edition 0u16;
"
    ))
    .unwrap()
}

/// Returns an env whose tip is the activation block of the freeze version (height 26), in which the
/// VM initialized the freeze program's mappings.
fn env_at_activation(rng: &mut TestRng) -> Env {
    let env = Env::new(rng);
    env.advance_to(CurrentNetwork::CONSENSUS_HEIGHT(DEPLOYMENT_FREEZE_CONSENSUS_VERSION).unwrap(), rng);
    env
}

/// Returns `(accepted, rejected deploys, aborted)` for the given transaction in the block.
fn outcome(block: &Block<CurrentNetwork>, transaction: &Transaction<CurrentNetwork>) -> &'static str {
    if block.aborted_transaction_ids().contains(&transaction.id()) {
        return "aborted";
    }
    for confirmed in block.transactions().iter() {
        if confirmed.to_unconfirmed_transaction_id().unwrap() == transaction.id() {
            return match confirmed {
                ConfirmedTransaction::AcceptedDeploy(..) | ConfirmedTransaction::AcceptedExecute(..) => "accepted",
                ConfirmedTransaction::RejectedDeploy(..) | ConfirmedTransaction::RejectedExecute(..) => "rejected",
            };
        }
    }
    panic!("Transaction {} is not in block {}", transaction.id(), block.height());
}

/// Returns a program whose functions match `small_program`, but which imports a program that does
/// not exist, so its stack cannot be built.
fn unbuildable_program(name: &str) -> Program<CurrentNetwork> {
    Program::from_str(&format!("import missing_program.aleo;\n{}", small_program_source(name))).unwrap()
}

/// A deployment that fails `verify_deployment`: the two functions' certificates are swapped.
fn deployment_with_swapped_certificates(name: &str, rng: &mut TestRng) -> Deployment<CurrentNetwork> {
    let deployment = sample_vm().process().deploy::<CurrentAleo, _>(&small_program(name), rng).unwrap();
    let mut keys = deployment.verifying_keys().clone();
    let first_certificate = keys[0].1.1.clone();
    keys[0].1.1 = keys[1].1.1.clone();
    keys[1].1.1 = first_certificate;
    Deployment::new(0, deployment.program().clone(), keys, None, None).unwrap()
}

/// A deployment whose stack cannot be built (it imports a missing program), with verifying keys
/// borrowed from a valid program with the same functions.
fn deployment_without_stack(name: &str, rng: &mut TestRng) -> Deployment<CurrentNetwork> {
    let deployment = sample_vm().process().deploy::<CurrentAleo, _>(&small_program(name), rng).unwrap();
    Deployment::new(0, unbuildable_program(name), deployment.verifying_keys().clone(), None, None).unwrap()
}

#[test]
fn test_freeze_version_is_test_height_26() {
    // The test heights below assume V23 at 26.
    assert_eq!(DEPLOYMENT_FREEZE_CONSENSUS_VERSION, ConsensusVersion::V23);
    assert_eq!(CurrentNetwork::CONSENSUS_HEIGHT(ConsensusVersion::V23).unwrap(), 26);
}

/// The rule end to end, with a real signed vote in an unproven submission: the vote, FREEZE_DELAY, rejection without verification,
/// fee-only aborts, and the block checker. Renewal, expiry and thaw are in
/// `test_deployment_freeze_renewal_expiry_and_thaw`.
#[test]
fn test_deployment_freeze_consensus() {
    let rng = &mut TestRng::default();
    let env = env_at_activation(rng);
    assert_eq!(env.height(), 26);
    let duration = FREEZE_DELAY + 20;

    // Block 27: a deploy, a submission of the votes that pass a freeze, and another deploy. The rule
    // reads committed state, so both deploys are processed as usual, whatever their position.
    // The submission is unproven (see `add_block_unchecked`).
    let deploy_before = env.deploy(3, "freeze_test_before", rng);
    let submission = env.submit_unproven(&[0, 1, 2], Some(duration), rng);
    let deploy_after = env.deploy(1, "freeze_test_after", rng);
    let transactions = [deploy_before.clone(), submission.clone(), deploy_after.clone()];
    let block = env.add_block_unchecked(&transactions, rng);
    assert_eq!(outcome(&block, &deploy_before), "accepted");
    assert_eq!(outcome(&block, &deploy_after), "accepted");
    assert_eq!(outcome(&block, &submission), "accepted");
    let freeze = FreezeWindow { start: 27 + FREEZE_DELAY, end: 27 + duration };
    let start = freeze.start;
    assert_eq!(env.freeze_value(), Some(freeze));
    assert_eq!(env.nonce(), 1);
    // Node policy applies from the next block, though consensus freezes only from `start`.
    assert_eq!(env.vm.deployment_freeze_policy().unwrap(), Some(freeze));
    assert!(!env.vm.deployments_frozen_at(28).unwrap());
    assert!(!env.vm.deployments_frozen_at(start - 1).unwrap());
    assert!(env.vm.deployments_frozen_at(start).unwrap());

    // Block 28 (not frozen): the deployments that cannot be verified are aborted, as usual.
    let unverifiable = deployment_with_swapped_certificates("freeze_test_badcert_a", rng);
    let unbuildable = deployment_without_stack("freeze_test_nostack_a", rng);
    let bad_certificate = env.deploy_with(0, unverifiable, |frozen_min| frozen_min * 2, rng);
    let no_stack = env.deploy_with(1, unbuildable, |frozen_min| frozen_min * 2, rng);
    let block = env.add_block(&[bad_certificate.clone(), no_stack.clone()], rng);
    assert_eq!(outcome(&block, &bad_certificate), "aborted");
    assert_eq!(outcome(&block, &no_stack), "aborted");

    // Block `start - 1`, the last block of FREEZE_DELAY: deployments are processed as usual, though
    // node policy already turns them away.
    env.advance_to(start - 2, rng);
    assert_eq!(env.vm.deployment_freeze_policy().unwrap(), Some(freeze));
    let in_delay = env.deploy(2, "freeze_test_delay", rng);
    let block = env.add_block(std::slice::from_ref(&in_delay), rng);
    assert_eq!(block.height(), start - 1);
    assert_eq!(outcome(&block, &in_delay), "accepted");

    // Block `start`: a valid deployment is rejected, and its full fee is charged.
    let frozen = env.deploy(3, "freeze_test_frozen", rng);
    let fee = *frozen.fee_amount().unwrap();
    let balance_before = env.public_balance(env.address(3));
    let (block, state) = env.next_block(std::slice::from_ref(&frozen), rng);
    assert_eq!(block.height(), start);
    assert_eq!(outcome(&block, &frozen), "rejected");
    // The block checker accepts the frozen `RejectedDeploy`.
    env.vm
        .check_speculate(
            state,
            CurrentNetwork::BLOCK_TIME as i64,
            block.ratifications(),
            block.solutions(),
            block.transactions(),
            rng,
        )
        .unwrap();
    // A block that lists the frozen deployment as accepted fails `check_speculate`.
    let finalize = block.transactions().iter().next().unwrap().finalize_operations().clone();
    let forged = Transactions::from(&[ConfirmedTransaction::accepted_deploy(0, frozen.clone(), finalize).unwrap()]);
    let error = env
        .vm
        .check_speculate(
            state,
            CurrentNetwork::BLOCK_TIME as i64,
            block.ratifications(),
            block.solutions(),
            &forged,
            rng,
        )
        .unwrap_err();
    assert!(error.to_string().contains("while deployments are frozen"), "{error}");
    env.vm.add_next_block(&block).unwrap();
    assert_eq!(env.public_balance(env.address(3)), balance_before - fee);
    assert!(!env.vm.contains_program(&ProgramID::from_str("freeze_test_frozen.aleo").unwrap()));

    // The next two blocks: deployments that would fail verification, or whose stack cannot be built,
    // are rejected with their fee charged. They are never verified, and their stack is never built.
    // A block holds at most one frozen deployment, so each is in its own block.
    let unverifiable = deployment_with_swapped_certificates("freeze_test_badcert_b", rng);
    let unbuildable = deployment_without_stack("freeze_test_nostack_b", rng);
    let bad_certificate = env.deploy_with(0, unverifiable, |frozen_min| frozen_min, rng);
    let no_stack = env.deploy_with(1, unbuildable, |frozen_min| frozen_min, rng);
    let block = env.add_block(std::slice::from_ref(&bad_certificate), rng);
    assert_eq!(outcome(&block, &bad_certificate), "rejected");
    let balance_before = env.public_balance(env.address(1));
    let block = env.add_block(std::slice::from_ref(&no_stack), rng);
    assert_eq!(outcome(&block, &no_stack), "rejected");
    assert_eq!(env.public_balance(env.address(1)), balance_before - *no_stack.fee_amount().unwrap());

    // The next block: the fee-only checks. A fee below the frozen minimum, a fee bound to another
    // deployment, and a version 1 deployment are aborted. A fee of exactly the minimum is rejected.
    let mut make = |name: &str| sample_vm().process().deploy::<CurrentAleo, _>(&small_program(name), rng).unwrap();
    let (d0, d1, d2, d3) = (
        make("freeze_test_lowfee"),
        make("freeze_test_wrongid"),
        make("freeze_test_version1"),
        make("freeze_test_exactfee"),
    );
    let low_fee = env.deploy_with(0, d0, |frozen_min| frozen_min - 1, rng);
    let d1 = as_version_2(d1, env.address(1));
    let frozen_min = frozen_deployment_minimum_cost(&d1).unwrap();
    let wrong_id = env.deploy_transaction(1, d1, frozen_min, Field::rand(rng), rng);
    let mut d2 = d2;
    d2.set_program_checksum_raw(None);
    d2.set_program_owner_raw(None);
    let d2_id = d2.to_deployment_id().unwrap();
    let version_1 = env.deploy_transaction(2, d2, 10_000_000_000, d2_id, rng);
    let exact_fee = env.deploy_with(3, d3, |frozen_min| frozen_min, rng);
    let block = env.add_block(&[low_fee.clone(), wrong_id.clone(), version_1.clone(), exact_fee.clone()], rng);
    assert_eq!(outcome(&block, &low_fee), "aborted");
    assert_eq!(outcome(&block, &wrong_id), "aborted");
    assert_eq!(outcome(&block, &version_1), "aborted");
    assert_eq!(outcome(&block, &exact_fee), "rejected");
}

/// Renewal, expiry, a new freeze after expiry, and a thaw, with real signed votes in unproven
/// submissions (see `add_block_unchecked`). The first freeze is written directly into committed
/// state, in force from block 27.
#[test]
fn test_deployment_freeze_renewal_expiry_and_thaw() {
    let rng = &mut TestRng::default();
    let env = env_at_activation(rng);
    let start = 27;
    env.write_freeze(start, 1_000);

    // A renewal during the freeze keeps `start`.
    let submission = env.submit_unproven(&[0, 1, 2], Some(FREEZE_DELAY + 40), rng);
    let block = env.add_block_unchecked(&[submission], rng);
    assert_eq!(env.freeze_value(), Some(FreezeWindow { start, end: block.height() + FREEZE_DELAY + 40 }));
    // A renewal can shorten the freeze.
    let submission = env.submit_unproven(&[0, 1, 2], Some(FREEZE_DELAY + 2), rng);
    let block = env.add_block_unchecked(&[submission], rng);
    let end = block.height() + FREEZE_DELAY + 2;
    assert_eq!(env.freeze_value(), Some(FreezeWindow { start, end }));

    // Block `end - 1` is the last frozen block; the freeze expires at `end`.
    env.advance_to(end - 2, rng);
    let last_frozen = env.deploy(0, "freeze_test_lastfrozen", rng);
    let block = env.add_block(std::slice::from_ref(&last_frozen), rng);
    assert_eq!(outcome(&block, &last_frozen), "rejected");
    assert_eq!(env.vm.deployment_freeze_policy().unwrap(), None);
    let expired = env.deploy(0, "freeze_test_expired", rng);
    let block = env.add_block(std::slice::from_ref(&expired), rng);
    assert_eq!(block.height(), end);
    assert_eq!(outcome(&block, &expired), "accepted");

    // A new freeze, after the old one expired, starts after FREEZE_DELAY.
    let submission = env.submit_unproven(&[0, 1, 2], Some(FREEZE_DELAY + 20), rng);
    let block = env.add_block_unchecked(&[submission], rng);
    let start = block.height() + FREEZE_DELAY;
    assert_eq!(env.freeze_value(), Some(FreezeWindow { start, end: block.height() + FREEZE_DELAY + 20 }));

    // Block `start`: a thaw passes. A deploy in the same block is still frozen; one in the next block is not.
    env.advance_to(start - 1, rng);
    let thaw = env.submit_unproven(&[0, 1, 2], None, rng);
    let same_block = env.deploy(3, "freeze_test_thawblock", rng);
    let block = env.add_block_unchecked(&[thaw, same_block.clone()], rng);
    assert_eq!(block.height(), start);
    assert_eq!(outcome(&block, &same_block), "rejected");
    assert_eq!(env.freeze_value(), Some(FreezeWindow { start: 0, end: 0 }));
    let after_thaw = env.deploy(3, "freeze_test_afterthaw", rng);
    let block = env.add_block(std::slice::from_ref(&after_thaw), rng);
    assert_eq!(outcome(&block, &after_thaw), "accepted");
}

/// The per-block rules for frozen deployments. A frozen deployment does not count as a deployment of
/// its program, so an execution of that program in the same block is accepted. A block holds at most
/// `MAX_FROZEN_DEPLOYMENTS_PER_BLOCK` frozen deployments, whatever their fee payers, in both the block
/// builder and the block checker. A frozen deployment whose verifying keys claim circuit sizes that
/// overflow the frozen minimum is aborted. The freeze value is written directly into committed state.
#[test]
fn test_deployment_freeze_per_block_rules() {
    let rng = &mut TestRng::default();
    let env = env_at_activation(rng);
    assert_eq!(MAX_FROZEN_DEPLOYMENTS_PER_BLOCK, 1);

    // Deploy the program, and give validators 1 and 2 a credits record each.
    let deploy = env.deploy(0, "freeze_test_existing", rng);
    let transfers = [env.transfer_to_private(1, rng), env.transfer_to_private(2, rng)];
    let mut transactions = vec![deploy];
    transactions.extend(transfers.iter().cloned());
    let block = env.add_block(&transactions, rng);
    transactions.iter().for_each(|transaction| assert_eq!(outcome(&block, transaction), "accepted"));
    let credits_1 = env.private_credits(1, &transfers[0]);
    let credits_2 = env.private_credits(2, &transfers[1]);

    // Freeze deployments from the next block.
    env.write_freeze(28, 1_000);

    // A frozen deployment of the existing program, and an execution of it in the same block.
    let redeployment =
        sample_vm().process().deploy::<CurrentAleo, _>(&small_program("freeze_test_existing"), rng).unwrap();
    let frozen = env.deploy_with(3, redeployment, |frozen_min| frozen_min, rng);
    let input = Value::<CurrentNetwork>::from_str("1u8").unwrap();
    let execution = env
        .vm
        .execute(&env.keys[0], ("freeze_test_existing.aleo", "first"), [input].iter(), None, 0, None, rng)
        .unwrap();
    let block = env.add_block(&[frozen.clone(), execution.clone()], rng);
    assert_eq!(block.height(), 28);
    assert_eq!(outcome(&block, &frozen), "rejected");
    assert_eq!(outcome(&block, &execution), "accepted");

    // Two frozen deployments paid with private fees, from different validators.
    let first = sample_vm().process().deploy::<CurrentAleo, _>(&small_program("freeze_test_private_a"), rng).unwrap();
    let second = sample_vm().process().deploy::<CurrentAleo, _>(&small_program("freeze_test_private_b"), rng).unwrap();
    let first = env.deploy_private(1, first, credits_1, rng);
    let second = env.deploy_private(2, second, credits_2, rng);
    // The block checker refuses a block that rejects both: the second must be aborted. Each rejection
    // is taken from a block that holds it alone, and a private fee has no finalize operations.
    let (block_first, state) = env.next_block(std::slice::from_ref(&first), rng);
    let (block_second, _) = env.next_block(std::slice::from_ref(&second), rng);
    let first_rejected = block_first.transactions().iter().next().unwrap().clone();
    let ConfirmedTransaction::RejectedDeploy(_, fee_transaction, rejected, finalize) =
        block_second.transactions().iter().next().unwrap().clone()
    else {
        panic!("The second frozen deployment is not rejected");
    };
    assert!(finalize.is_empty());
    let second_rejected = ConfirmedTransaction::rejected_deploy(1, fee_transaction, rejected, finalize).unwrap();
    let forged = Transactions::from(&[first_rejected, second_rejected]);
    let error = env
        .vm
        .check_speculate(
            state,
            CurrentNetwork::BLOCK_TIME as i64,
            block_first.ratifications(),
            block_first.solutions(),
            &forged,
            rng,
        )
        .unwrap_err();
    assert!(error.to_string().contains("do not match"), "{error}");
    // The block builder aborts the second.
    let block = env.add_block(&[first.clone(), second.clone()], rng);
    assert_eq!(outcome(&block, &first), "rejected");
    assert_eq!(outcome(&block, &second), "aborted");

    // A frozen deployment whose verifying key claims `u64::MAX / 25` variables and constraints: the
    // frozen minimum overflows, and the deployment is aborted.
    let deployment =
        sample_vm().process().deploy::<CurrentAleo, _>(&small_program("freeze_test_overflow"), rng).unwrap();
    let mut keys = deployment.verifying_keys().clone();
    let mut circuit_key = (*keys[0].1.0).clone();
    circuit_key.circuit_info.num_constraints = usize::try_from(u64::MAX / 25).unwrap();
    keys[0].1.0 = VerifyingKey::new(Arc::new(circuit_key), u64::MAX / 25);
    let deployment =
        as_version_2(Deployment::new(0, deployment.program().clone(), keys, None, None).unwrap(), env.address(0));
    let deployment_id = deployment.to_deployment_id().unwrap();
    let overflowing = env.deploy_transaction(0, deployment, 10_000_000_000, deployment_id, rng);
    let error = env.vm.check_frozen_deployment_cheap(&overflowing, ConsensusVersion::latest()).unwrap_err();
    assert!(error.to_string().contains("synthesis cost computation overflowed"), "{error}");
    let block = env.add_block(std::slice::from_ref(&overflowing), rng);
    assert_eq!(outcome(&block, &overflowing), "aborted");
}

/// The built-in program before and at activation. Every process loads it, but before the freeze version a
/// node behaves as one without it: a transaction that executes it, or a deployment that imports it, is
/// refused, and its mappings do not exist. The activation block initializes the mappings, and the
/// program is usable from the next block. It can never be deployed, upgraded or amended.
#[test]
fn test_deployment_freeze_activation() {
    let rng = &mut TestRng::default();
    let env = Env::new(rng);
    let program_id = deployment_freeze_program_id::<CurrentNetwork>();
    let mappings = [FREEZE_MAPPING, NONCE_MAPPING].map(|name| Identifier::<CurrentNetwork>::from_str(name).unwrap());
    let mappings_exist = |env: &Env| {
        mappings
            .iter()
            .map(|name| env.vm.finalize_store().contains_mapping_confirmed(&program_id, name).unwrap())
            .collect::<Vec<_>>()
    };
    assert!(env.vm.contains_program(&program_id));

    // The program can never be deployed, upgraded or amended. The fee check builds the deployment's
    // stack first, and `Stack::new` refuses to replace a built-in program, as for `credits.aleo`.
    let lock = |env: &Env, rng: &mut TestRng| {
        for edition in [0, 1] {
            let deployment = freeze_program_deployment(edition, rng);
            let deployment_id = deployment.to_deployment_id().unwrap();
            let transaction = env.deploy_transaction(0, deployment, 1_000_000_000, deployment_id, rng);
            let error = env.vm.check_transaction(&transaction, None, rng).unwrap_err();
            assert!(error.to_string().contains(DEPLOYMENT_FREEZE_PROGRAM_ID), "{error}");
        }
    };
    lock(&env, rng);

    // Before the freeze version: the mappings do not exist, so no freeze is read, and a submission or
    // a deployment that imports the program is refused.
    env.advance_to(24, rng);
    assert_eq!(mappings_exist(&env), [false, false]);
    // The gate comes before proof verification, so the submission needs no proof.
    let literal = env.vote_literal(Some(FREEZE_DELAY + 20));
    let submission = env.submit_unproven_with(&env.committee_list(), 4, &[0, 1, 2], &literal, rng);
    let error = env.vm.check_transaction(&submission, None, rng).unwrap_err();
    assert!(error.to_string().contains("before it is active"), "{error}");
    let importer = env.vm.deploy(&env.keys[1], &importing_program("freeze_test_importer"), None, 0, None, rng).unwrap();
    let error = env.vm.check_transaction(&importer, None, rng).unwrap_err();
    assert!(error.to_string().contains("cannot be imported before it is active"), "{error}");

    // Block 25, the last block before the freeze version, and block 26, the activation block: the
    // transaction checks use the version at the previous tip, so a submission is refused until the
    // tip is at 26. The activation block initializes the mappings.
    env.advance_to(25, rng);
    assert_eq!(mappings_exist(&env), [false, false]);
    assert!(env.vm.check_transaction(&submission, None, rng).is_err());
    assert_eq!(env.vm.deployment_freeze(26).unwrap(), None);
    let block = env.add_block(&[], rng);
    assert_eq!(block.height(), 26);
    assert_eq!(mappings_exist(&env), [true, true]);
    assert_eq!(env.freeze_value(), None);
    assert_eq!(env.nonce(), 0);

    // A VM restarted on the same storage keeps the mappings and does not initialize them again.
    let restarted = VM::from(env.vm.store.clone()).unwrap();
    assert!(restarted.finalize_store().contains_mapping_confirmed(&program_id, &mappings[0]).unwrap());

    // From the next block, the program is usable and can be imported, and it is still locked.
    let submission = env.submit(&[0, 1, 2], Some(FREEZE_DELAY + 20), rng);
    let importer = env.vm.deploy(&env.keys[1], &importing_program("freeze_test_importer"), None, 0, None, rng).unwrap();
    let block = env.add_block(&[submission.clone(), importer.clone()], rng);
    assert_eq!(block.height(), 27);
    assert_eq!(outcome(&block, &submission), "accepted");
    assert_eq!(outcome(&block, &importer), "accepted");
    assert_eq!(env.freeze_value(), Some(FreezeWindow { start: 27 + FREEZE_DELAY, end: 27 + FREEZE_DELAY + 20 }));
    lock(&env, rng);
}

/// The validators whose stake reaches the threshold exactly.
const QUORUM: [usize; 3] = [0, 1, 2];

/// The setup the `submit_votes` tests share. Each proof of `submit_votes` takes tens of seconds, so the
/// program's checks are split across tests that each prove a few submissions, to stay well under CI's
/// per-test time limit.
struct SubmitVotes {
    env: Env,
    /// The committee members, sorted by field cast.
    list: Vec<Address<CurrentNetwork>>,
    /// The height of the activation block, which is the tip.
    height: u32,
}

impl SubmitVotes {
    fn new(rng: &mut TestRng) -> Self {
        let env = env_at_activation(rng);
        assert_eq!(env.nonce(), 0);
        let list = env.committee_list();
        let height = env.height();
        Self { env, list, height }
    }

    /// The payload for this network.
    fn literal(&self, action: u8, duration: u32, nonce: u64, expires: u32) -> String {
        FreezeVote { network: CurrentNetwork::ID, action, duration, nonce, expires }.literal()
    }

    /// A valid freeze payload on nonce 0.
    fn good(&self) -> String {
        self.literal(ACTION_FREEZE, 200, 0, self.height + 1_000)
    }

    /// Adds the submissions, which may be unproven, in one block, and checks that each is rejected and
    /// nothing changed.
    fn assert_rejected(&self, submissions: &[Transaction<CurrentNetwork>], rng: &mut TestRng) -> Block<CurrentNetwork> {
        let block = self.env.add_block_unverified(submissions, rng);
        for (index, submission) in submissions.iter().enumerate() {
            assert_eq!(outcome(&block, submission), "rejected", "submission {index} was not rejected");
        }
        assert_eq!(self.env.freeze_value(), None);
        assert_eq!(self.env.nonce(), 0);
        block
    }
}

/// The circuit and its cost; one microcredit below the threshold fails; at the threshold, anyone can
/// submit; the same signatures cannot be used again once the nonce moves; a thaw on the new nonce passes.
#[test]
fn test_deployment_freeze_submit_votes_threshold_and_replay() {
    let rng = &mut TestRng::default();
    let setup = SubmitVotes::new(rng);
    let (env, list, good) = (&setup.env, &setup.list, setup.good());

    // The circuit and its cost.
    let verifying_key = submit_votes_verifying_key::<CurrentNetwork>().unwrap();
    println!(
        "submit_votes circuit: {} constraints, {} variables (deployment limit {})",
        verifying_key.circuit_info.num_constraints,
        verifying_key.num_variables(),
        CurrentNetwork::MAX_DEPLOYMENT_CONSTRAINTS_V2
    );
    // Validators 0, 1 and 3 hold 4M+2, one microcredit below the threshold.
    let short = env.submit_unproven_with(list, 4, &[0, 1, 3], &good, rng);
    let spend =
        transaction_compute_spend_in_microcredits(env.vm.process(), &short, ConsensusVersion::latest()).unwrap();
    let limit = consensus_config_value_by_version!(CurrentNetwork, TRANSACTION_SPEND_LIMIT, ConsensusVersion::latest())
        .unwrap();
    println!(
        "submit_votes: compute spend {spend} microcredits (limit {limit}), fee {} microcredits",
        *short.fee_amount().unwrap()
    );
    assert!(spend <= limit);
    setup.assert_rejected(&[short], rng);

    // Validators 0, 1 and 2 hold exactly the threshold, and an outsider submits their votes.
    let outsider = PrivateKey::<CurrentNetwork>::new(rng).unwrap();
    let outsider_address = Address::try_from(&outsider).unwrap();
    let funding = env
        .vm
        .execute(
            &env.keys[0],
            ("credits.aleo", "transfer_public"),
            [
                Value::<CurrentNetwork>::from_str(&outsider_address.to_string()).unwrap(),
                Value::from_str("10000000000u64").unwrap(),
            ]
            .into_iter(),
            None,
            0,
            None,
            rng,
        )
        .unwrap();
    env.add_block(&[funding], rng);
    // This is the first proof, so it also synthesizes the proving key. `check_speculate` verifies it.
    let (mask, signatures) = env.sign_list(list, &QUORUM, &good, rng);
    let passing = env.try_submit_raw(&outsider, list, 4, mask, &signatures, &good, rng).unwrap();
    println!("submit_votes transaction: {} bytes", passing.to_bytes_le().unwrap().len());
    let block = env.add_block(std::slice::from_ref(&passing), rng);
    assert_eq!(outcome(&block, &passing), "accepted");
    let passed_at = block.height();
    let freeze = FreezeWindow { start: passed_at + FREEZE_DELAY, end: passed_at + 200 };
    assert_eq!(env.freeze_value(), Some(freeze));
    assert_eq!(env.nonce(), 1);

    // The same signatures cannot be used again: the nonce moved on.
    let replay = env.try_submit_unproven_raw(&env.keys[0], list, 4, mask, &signatures, &good, rng).unwrap();
    let block = env.add_block_unverified(std::slice::from_ref(&replay), rng);
    assert_eq!(outcome(&block, &replay), "rejected");
    assert_eq!(env.freeze_value(), Some(freeze));
    assert_eq!(env.nonce(), 1);

    // A thaw on the new nonce passes. It is unproven (see `add_block_unchecked`).
    let thaw = env.submit_unproven(&QUORUM, None, rng);
    let block = env.add_block_unchecked(std::slice::from_ref(&thaw), rng);
    assert_eq!(outcome(&block, &thaw), "accepted");
    assert_eq!(env.freeze_value(), Some(FreezeWindow { start: 0, end: 0 }));
    assert_eq!(env.nonce(), 2);
}

/// A bad signature in a set slot, or a payload that is not a freeze vote, fails in the function, so
/// no transaction can be built. The wrong nonce, the wrong network, or an expired vote fails in finalize.
#[test]
fn test_deployment_freeze_submit_votes_signatures_and_vote() {
    let rng = &mut TestRng::default();
    let setup = SubmitVotes::new(rng);
    let (env, list, good, height) = (&setup.env, &setup.list, setup.good(), setup.height);

    let (mask, mut signatures) = env.sign_list(list, &QUORUM, &good, rng);
    let slot = list.iter().position(|address| *address == env.address(2)).unwrap();
    signatures[slot] = sign_literal(&env.keys[3], &good, rng);
    assert!(env.try_submit_raw(&env.keys[0], list, 4, mask, &signatures, &good, rng).is_err());
    let other_payload = setup.literal(ACTION_FREEZE, 201, 0, height + 1_000);
    signatures[slot] = sign_literal(&env.keys[2], &other_payload, rng);
    assert!(env.try_submit_raw(&env.keys[0], list, 4, mask, &signatures, &good, rng).is_err());
    let untagged = good.replace("aleo_deployment_freeze: true", "aleo_deployment_freeze: false");
    let (mask, signatures) = env.sign_list(list, &QUORUM, &untagged, rng);
    assert!(env.try_submit_raw(&env.keys[0], list, 4, mask, &signatures, &untagged, rng).is_err());

    // A control: the same builders, for a valid vote at the threshold, are accepted, so the unproven
    // submissions below reach finalize, and are rejected there. The control is not added.
    let control = env.submit_unproven_with(list, 4, &QUORUM, &good, rng);
    let (block, _) = env.next_block_unverified(std::slice::from_ref(&control), rng);
    assert_eq!(outcome(&block, &control), "accepted");

    // The wrong nonce, the wrong network, and a vote that expires at the block it is in.
    let next = height + 1;
    let wrong_network = FreezeVote {
        network: CurrentNetwork::ID + 1,
        action: ACTION_FREEZE,
        duration: 200,
        nonce: 0,
        expires: height + 1_000,
    };
    let failing = [
        env.submit_unproven_with(list, 4, &QUORUM, &setup.literal(ACTION_FREEZE, 200, 1, height + 1_000), rng),
        env.submit_unproven_with(list, 4, &QUORUM, &wrong_network.literal(), rng),
        env.submit_unproven_with(list, 4, &QUORUM, &setup.literal(ACTION_FREEZE, 200, 0, next), rng),
    ];
    let block = setup.assert_rejected(&failing, rng);
    assert_eq!(block.height(), next);
}

/// An invalid action, a freeze no longer than FREEZE_DELAY or longer than MAX_FREEZE_BLOCKS, and a
/// thaw with a duration, each fail in finalize.
#[test]
fn test_deployment_freeze_submit_votes_action_and_duration() {
    let rng = &mut TestRng::default();
    let setup = SubmitVotes::new(rng);
    let (env, list, expires) = (&setup.env, &setup.list, setup.height + 1_000);
    let failing = [
        env.submit_unproven_with(list, 4, &QUORUM, &setup.literal(3, 200, 0, expires), rng),
        env.submit_unproven_with(list, 4, &QUORUM, &setup.literal(ACTION_FREEZE, FREEZE_DELAY, 0, expires), rng),
        env.submit_unproven_with(
            list,
            4,
            &QUORUM,
            &setup.literal(ACTION_FREEZE, MAX_FREEZE_BLOCKS + 1, 0, expires),
            rng,
        ),
        env.submit_unproven_with(list, 4, &QUORUM, &setup.literal(ACTION_THAW, 1, 0, expires), rng),
    ];
    setup.assert_rejected(&failing, rng);
}

/// Forged committee lists, each signed by a quorum of its members, fail in finalize: a missing member
/// (with either count), a duplicate, and an unsorted list.
#[test]
fn test_deployment_freeze_submit_votes_forged_lists() {
    let rng = &mut TestRng::default();
    let setup = SubmitVotes::new(rng);
    let (env, list, good) = (&setup.env, &setup.list, setup.good());
    let mut missing = list.clone();
    missing.retain(|address| *address != env.address(3));
    let mut duplicate = list.clone();
    let slot_2 = duplicate.iter().position(|address| *address == env.address(2)).unwrap();
    duplicate.insert(slot_2, env.address(2));
    duplicate.retain(|address| *address != env.address(3));
    let mut unsorted = list.clone();
    unsorted.swap(0, 1);
    let failing = [(&missing, 3), (&missing, 4), (&duplicate, 4), (&unsorted, 4)]
        .map(|(members, count)| env.submit_unproven_with(members, count, &QUORUM, &good, rng));
    setup.assert_rejected(&failing, rng);
}

/// A wrong count, a non-member in the list, and a set mask bit at or above `count` each fail in
/// finalize. Counting a validator twice by setting its bit twice is impossible: the list is strictly
/// increasing, so each validator has one slot and one bit.
#[test]
fn test_deployment_freeze_submit_votes_count_and_members() {
    let rng = &mut TestRng::default();
    let setup = SubmitVotes::new(rng);
    let (env, list, good) = (&setup.env, &setup.list, setup.good());
    let mut failing = vec![
        env.submit_unproven_with(list, 3, &QUORUM, &good, rng),
        env.submit_unproven_with(list, 5, &QUORUM, &good, rng),
    ];
    // A non-member in the list. The outsider's own signature is valid, but it is not in the committee.
    let outsider = PrivateKey::<CurrentNetwork>::new(rng).unwrap();
    let outsider_address = Address::try_from(&outsider).unwrap();
    let mut non_member = list.clone();
    non_member.retain(|address| *address != env.address(3));
    non_member.push(outsider_address);
    non_member.sort_by_key(|address| address.to_field().unwrap());
    let (mut mask, mut signatures) = env.sign_list(&non_member, &QUORUM, &good, rng);
    let outsider_slot = non_member.iter().position(|address| *address == outsider_address).unwrap();
    mask |= 1 << outsider_slot;
    signatures[outsider_slot] = sign_literal(&outsider, &good, rng);
    failing.push(env.try_submit_unproven_raw(&env.keys[0], &non_member, 4, mask, &signatures, &good, rng).unwrap());
    // A set mask bit at or above `count`: validator 2 again, in padding slot 4, would count twice.
    let mut padded = list.clone();
    padded.push(env.address(2));
    let (mask, signatures) = env.sign_list(&padded, &QUORUM, &good, rng);
    assert_ne!(mask & (1 << 4), 0);
    failing.push(env.try_submit_unproven_raw(&env.keys[0], &padded, 4, mask, &signatures, &good, rng).unwrap());
    setup.assert_rejected(&failing, rng);
}
