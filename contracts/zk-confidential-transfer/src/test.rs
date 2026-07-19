#![cfg(test)]
extern crate std;

use ark_bls12_381::{Fq, Fq2, Fr as ArkFr};
use ark_ec::AffineRepr;
use ark_serialize::CanonicalSerialize;
use core::str::FromStr;
use serde_json::Value;
use soroban_sdk::{
    crypto::bls12_381::{Fr, G1Affine, G2Affine, G1_SERIALIZED_SIZE, G2_SERIALIZED_SIZE},
    testutils::Address as _,
    token, Bytes, BytesN, Env, Vec, U256,
};
use std::fs;

use crate::{Error, Proof, VerificationKey, ZkConfidentialTransfer, ZkConfidentialTransferClient};

// --- snarkjs JSON (decimal coords) -> Soroban BLS12-381 types -----------------
// Shared verbatim with the sibling groth16-verifier / zk-verified-payment test
// harnesses.

fn g1_from_coords(env: &Env, x: &str, y: &str) -> G1Affine {
    let g = ark_bls12_381::G1Affine::new(Fq::from_str(x).unwrap(), Fq::from_str(y).unwrap());
    let mut buf = [0u8; G1_SERIALIZED_SIZE];
    g.serialize_uncompressed(&mut buf[..]).unwrap();
    G1Affine::from_array(env, &buf)
}

fn g2_from_coords(env: &Env, x1: &str, x2: &str, y1: &str, y2: &str) -> G2Affine {
    let x = Fq2::new(Fq::from_str(x1).unwrap(), Fq::from_str(x2).unwrap());
    let y = Fq2::new(Fq::from_str(y1).unwrap(), Fq::from_str(y2).unwrap());
    let g = ark_bls12_381::G2Affine::new(x, y);
    let mut buf = [0u8; G2_SERIALIZED_SIZE];
    g.serialize_uncompressed(&mut buf[..]).unwrap();
    G2Affine::from_array(env, &buf)
}

fn fr_from_decimal(env: &Env, s: &str) -> Fr {
    let n = ArkFr::from_str(s).unwrap();
    let mut le = [0u8; 32];
    n.serialize_uncompressed(&mut le[..]).unwrap();
    le.reverse();
    Fr::from_u256(U256::from_be_bytes(env, &Bytes::from_array(env, &le)))
}

fn load(file: &str) -> Value {
    let path = std::format!("{}/data/{}", env!("CARGO_MANIFEST_DIR"), file);
    serde_json::from_str(&fs::read_to_string(path).unwrap()).unwrap()
}
fn cs(v: &Value) -> &str {
    v.as_str().unwrap()
}
fn g1(env: &Env, p: &Value) -> G1Affine {
    g1_from_coords(env, cs(&p[0]), cs(&p[1]))
}
fn g2(env: &Env, p: &Value) -> G2Affine {
    g2_from_coords(env, cs(&p[0][0]), cs(&p[0][1]), cs(&p[1][0]), cs(&p[1][1]))
}

// VK loader (by file). data/verification_key.json is the DEV confidential_transfer
// VK; data/withdraw_verification_key.json is the DEV confidential_withdraw VK. Both
// are single-participant setups (NON-PRODUCTION); each ships with a real
// proof/public fixture so the happy-path tests run a REAL pairing against the
// embedded VK.
fn build_vk_from(env: &Env, file: &str) -> VerificationKey {
    let v = load(file);
    let mut ic = Vec::new(env);
    for point in v["IC"].as_array().unwrap() {
        ic.push_back(g1(env, point));
    }
    VerificationKey {
        alpha: g1(env, &v["vk_alpha_1"]),
        beta: g2(env, &v["vk_beta_2"]),
        gamma: g2(env, &v["vk_gamma_2"]),
        delta: g2(env, &v["vk_delta_2"]),
        ic,
    }
}
fn build_vk(env: &Env) -> VerificationKey {
    build_vk_from(env, "verification_key.json")
}
// confidential_withdraw VK (2 public signals) — injected at initialize() alongside
// the transfer VK; the withdraw happy-path runs a real pairing against it.
fn build_withdraw_vk(env: &Env) -> VerificationKey {
    build_vk_from(env, "withdraw_verification_key.json")
}

// Real proof/public fixture loaders (by file). The confidential_transfer fixture is
// data/{proof,public}.json (4 commitments); the confidential_withdraw fixtures are
// data/withdraw_{proof,public}.json ([commitment, amount=100000000]) and the zero
// edge data/withdraw_zero_{proof,public}.json ([commitment, amount=0]).
fn build_proof_from(env: &Env, file: &str) -> Proof {
    let p = load(file);
    Proof {
        a: g1(env, &p["pi_a"]),
        b: g2(env, &p["pi_b"]),
        c: g1(env, &p["pi_c"]),
    }
}
fn build_public_from(env: &Env, file: &str) -> Vec<Fr> {
    let p = load(file);
    let mut out = Vec::new(env);
    for sig in p.as_array().unwrap() {
        out.push_back(fr_from_decimal(env, cs(sig)));
    }
    out
}
fn build_proof(env: &Env) -> Proof {
    build_proof_from(env, "proof.json")
}
fn build_public(env: &Env) -> Vec<Fr> {
    build_public_from(env, "public.json")
}
// C0 fold-in fixture (v2): a REAL conservative-transfer proof whose recipient_old
// opens the EMPTY balance (0, 0) — i.e. pub_signals[2] == C0 = Poseidon(0,0) —
// so the recipient can start ABSENT on-chain (sender 150->100, recipient 0->50,
// t=50). data/c0_{proof,public}.json.
fn build_c0_proof(env: &Env) -> Proof {
    build_proof_from(env, "c0_proof.json")
}
fn build_c0_public(env: &Env) -> Vec<Fr> {
    build_public_from(env, "c0_public.json")
}

// The confidential_withdraw fixture amount (= pub_signals[1], the field element the
// proof opens the burned commitment to). The real i128 token move must equal this.
const WITHDRAW_AMOUNT: i128 = 100_000_000;
fn build_withdraw_proof(env: &Env) -> Proof {
    build_proof_from(env, "withdraw_proof.json")
}
fn build_withdraw_public(env: &Env) -> Vec<Fr> {
    build_public_from(env, "withdraw_public.json")
}
fn build_withdraw_zero_proof(env: &Env) -> Proof {
    build_proof_from(env, "withdraw_zero_proof.json")
}
fn build_withdraw_zero_public(env: &Env) -> Vec<Fr> {
    build_public_from(env, "withdraw_zero_public.json")
}

// A syntactically valid but cryptographically meaningless proof: the BLS12-381
// group generators (prime-order subgroup, so the host accepts them) that do NOT
// satisfy the verification equation -> pairing_check returns false -> ProofInvalid.
// Lets the rejection-path tests run without touching the real proof fixtures.
fn dummy_proof(env: &Env) -> Proof {
    let g1g = ark_bls12_381::G1Affine::generator();
    let mut b1 = [0u8; G1_SERIALIZED_SIZE];
    g1g.serialize_uncompressed(&mut b1[..]).unwrap();
    let g2g = ark_bls12_381::G2Affine::generator();
    let mut b2 = [0u8; G2_SERIALIZED_SIZE];
    g2g.serialize_uncompressed(&mut b2[..]).unwrap();
    Proof {
        a: G1Affine::from_array(env, &b1),
        b: G2Affine::from_array(env, &b2),
        c: G1Affine::from_array(env, &b1),
    }
}

// commitment bytes for a chosen field element (matches the contract's
// pub_signals.get(i).to_bytes()).
fn commitment(env: &Env, s: &str) -> BytesN<32> {
    fr_from_decimal(env, s).to_bytes()
}

// v2 confidential_transfer takes an X25519 ephemeral pubkey + a sealed note (both
// OPAQUE to the contract — event-echoed for off-chain note delivery). The unit
// tests exercise the money path, so a zero key + empty note suffice.
fn zero_ephemeral(env: &Env) -> BytesN<32> {
    BytesN::from_array(env, &[0u8; 32])
}
fn empty_note(env: &Env) -> Bytes {
    Bytes::new(env)
}

// Returns (env, contract_id, token, admin, alice); alice pre-funded. mock_all_auths.
fn setup() -> (
    Env,
    soroban_sdk::Address,
    soroban_sdk::Address,
    soroban_sdk::Address,
    soroban_sdk::Address,
) {
    let env = Env::default();
    env.mock_all_auths();

    let token_admin = soroban_sdk::Address::generate(&env);
    let sac = env.register_stellar_asset_contract_v2(token_admin);
    let token = sac.address();

    let admin = soroban_sdk::Address::generate(&env);
    let id = env.register(ZkConfidentialTransfer, ());
    let client = ZkConfidentialTransferClient::new(&env, &id);
    client.initialize(&admin, &token, &build_vk(&env), &build_withdraw_vk(&env));

    let alice = soroban_sdk::Address::generate(&env);
    token::StellarAssetClient::new(&env, &token).mint(&alice, &1_000_000_000);

    (env, id, token, admin, alice)
}

#[test]
fn deposit_registers_commitment_and_custodies_funds() {
    let (env, id, token, _admin, alice) = setup();
    let client = ZkConfidentialTransferClient::new(&env, &id);
    let token_client = token::Client::new(&env, &token);

    assert_eq!(client.has_balance(&alice), false);
    let c = commitment(&env, "12345"); // = Poseidon(amount, blinding) client-side
    client.deposit(&alice, &100, &c);

    // Boundary: the deposit amount IS visible (arg + real token move). The pool
    // custodies the funds; alice is debited; her commitment is registered.
    assert_eq!(token_client.balance(&id), 100);
    assert_eq!(token_client.balance(&alice), 1_000_000_000 - 100);
    assert_eq!(client.get_commitment(&alice), Some(c));
}

#[test]
fn deposit_rejects_double_seed() {
    let (env, id, _token, _admin, alice) = setup();
    let client = ZkConfidentialTransferClient::new(&env, &id);
    client.deposit(&alice, &100, &commitment(&env, "1"));

    // A second deposit cannot top up an existing confidential balance (Poseidon is
    // not homomorphic -> no on-chain add). Documented first-deposit-only PoC limit.
    let res = client.try_deposit(&alice, &50, &commitment(&env, "2"));
    assert_eq!(res, Err(Ok(Error::BalanceExists)));
}

#[test]
fn confidential_transfer_rejects_bad_arity() {
    let (env, id, _token, _admin, alice) = setup();
    let client = ZkConfidentialTransferClient::new(&env, &id);
    let bob = soroban_sdk::Address::generate(&env);

    // pub_signals MUST be exactly the 4 commitments. A 3-element vector is rejected
    // BEFORE any commitment read or pairing work.
    let mut three = Vec::new(&env);
    three.push_back(fr_from_decimal(&env, "1"));
    three.push_back(fr_from_decimal(&env, "2"));
    three.push_back(fr_from_decimal(&env, "3"));
    let res = client.try_confidential_transfer(&alice, &bob, &dummy_proof(&env), &three, &zero_ephemeral(&env), &empty_note(&env));
    assert_eq!(res, Err(Ok(Error::BadPublicSignals)));
}

#[test]
fn confidential_transfer_rejects_stale_sender_old() {
    // Replay / double-spend guard: the per-account commitment is a compare-and-swap.
    // A proof whose sender_old does not byte-match the CURRENT stored commitment is
    // rejected (a consumed old commitment can never match again once advanced).
    let (env, id, _token, _admin, alice) = setup();
    let client = ZkConfidentialTransferClient::new(&env, &id);
    let bob = soroban_sdk::Address::generate(&env);

    client.deposit(&alice, &100, &commitment(&env, "1000")); // stored sender = 1000
    client.deposit(&bob, &0, &commitment(&env, "2000")); // stored recipient = 2000

    // sender_old (index 0) = 9999 != stored 1000 -> CommitmentMismatch.
    let mut ps = Vec::new(&env);
    ps.push_back(fr_from_decimal(&env, "9999")); // STALE sender_old
    ps.push_back(fr_from_decimal(&env, "1001")); // sender_new
    ps.push_back(fr_from_decimal(&env, "2000")); // recipient_old (matches)
    ps.push_back(fr_from_decimal(&env, "2099")); // recipient_new
    let res = client.try_confidential_transfer(&alice, &bob, &dummy_proof(&env), &ps, &zero_ephemeral(&env), &empty_note(&env));
    assert_eq!(res, Err(Ok(Error::CommitmentMismatch)));

    // Stored commitments are untouched — no double-spend occurred.
    assert_eq!(client.get_commitment(&alice), Some(commitment(&env, "1000")));
    assert_eq!(client.get_commitment(&bob), Some(commitment(&env, "2000")));
}

#[test]
fn confidential_transfer_rejects_tampered_proof() {
    // Both commitments match the stored state (compare-and-swap passes), so the
    // flow reaches the pairing check; a tampered/garbage proof fails it.
    let (env, id, token, _admin, alice) = setup();
    let client = ZkConfidentialTransferClient::new(&env, &id);
    let bob = soroban_sdk::Address::generate(&env);

    client.deposit(&alice, &100, &commitment(&env, "1000"));
    client.deposit(&bob, &0, &commitment(&env, "2000"));

    let mut ps = Vec::new(&env);
    ps.push_back(fr_from_decimal(&env, "1000")); // sender_old (matches stored)
    ps.push_back(fr_from_decimal(&env, "1001")); // sender_new
    ps.push_back(fr_from_decimal(&env, "2000")); // recipient_old (matches stored)
    ps.push_back(fr_from_decimal(&env, "2099")); // recipient_new
    let res = client.try_confidential_transfer(&alice, &bob, &dummy_proof(&env), &ps, &zero_ephemeral(&env), &empty_note(&env));
    assert_eq!(res, Err(Ok(Error::ProofInvalid)));

    // Commitments unchanged and NO token moved (confidential_transfer never calls
    // token::transfer — the pool float is constant across it).
    assert_eq!(client.get_commitment(&alice), Some(commitment(&env, "1000")));
    assert_eq!(client.get_commitment(&bob), Some(commitment(&env, "2000")));
    assert_eq!(token::Client::new(&env, &token).balance(&id), 100);
}

#[test]
fn confidential_transfer_rejects_unauthorized() {
    // No mock_all_auths: sender.require_auth() must reject an unauthorized swap of
    // the sender's balance before anything mutates.
    let env = Env::default();
    let id = env.register(ZkConfidentialTransfer, ());
    let client = ZkConfidentialTransferClient::new(&env, &id);
    let sender = soroban_sdk::Address::generate(&env);
    let recipient = soroban_sdk::Address::generate(&env);

    let mut ps = Vec::new(&env);
    for s in ["1", "2", "3", "4"] {
        ps.push_back(fr_from_decimal(&env, s));
    }
    let res = client.try_confidential_transfer(&sender, &recipient, &dummy_proof(&env), &ps, &zero_ephemeral(&env), &empty_note(&env));
    assert!(res.is_err(), "unauthorized confidential_transfer must fail at require_auth");
}

// TRUSTLESS WITHDRAW HAPPY PATH — runs a REAL Groth16/BLS12-381 pairing against the
// confidential_withdraw fixture (data/withdraw_{proof,public}.json: [commitment,
// amount=100000000]). This is the money-path acceptance test for the open-to-amount
// proof: the embedded withdraw VK ACCEPTS a valid proof that the burned commitment
// opens to EXACTLY the amount the pool pays out — replacing the v1 operator
// attestation. Asserts payout + burn, then replay rejection.
#[test]
fn withdraw_pays_out_and_burns_commitment() {
    let (env, id, token, _admin, alice) = setup();
    let client = ZkConfidentialTransferClient::new(&env, &id);
    let token_client = token::Client::new(&env, &token);

    // Seed alice's confidential balance at the fixture's commitment. The boundary
    // deposit amount is visible and funds the pool the withdraw pays back out.
    let public = build_withdraw_public(&env); // [commitment, amount=100000000]
    let c_burn = public.get(0).unwrap().to_bytes();
    client.deposit(&alice, &WITHDRAW_AMOUNT, &c_burn);
    assert_eq!(token_client.balance(&id), WITHDRAW_AMOUNT);

    // Boundary exit (amount visible) — but now the proof binds the visible amount to
    // the burned commitment, so no operator attestation is needed.
    client.withdraw(&alice, &WITHDRAW_AMOUNT, &build_withdraw_proof(&env), &public);
    assert_eq!(token_client.balance(&id), 0, "pool paid out");
    assert_eq!(token_client.balance(&alice), 1_000_000_000, "alice made whole");
    assert_eq!(client.has_balance(&alice), false, "commitment burned");

    // REPLAY: re-submitting the SAME proof now finds the commitment burned -> the
    // stored-commitment read returns NoBalance (compare-and-swap replay guard, the
    // exact discipline confidential_transfer uses).
    let res = client.try_withdraw(&alice, &WITHDRAW_AMOUNT, &build_withdraw_proof(&env), &public);
    assert_eq!(res, Err(Ok(Error::NoBalance)));
}

// THE KEY NEW MONEY-PATH TEST — a withdraw proof for the WRONG amount is REJECTED.
// alice holds a commitment that opens (provably) to 100000000. She submits that REAL
// valid proof but asks the contract to move out a DIFFERENT i128 amount. The
// open-to-amount bind (pub_signals[1] == the real token amount) rejects it with
// AmountMismatch BEFORE any token moves: a commitment-to-X can never be cashed for Y.
#[test]
fn withdraw_wrong_amount_rejected() {
    let (env, id, token, _admin, alice) = setup();
    let client = ZkConfidentialTransferClient::new(&env, &id);
    let token_client = token::Client::new(&env, &token);

    let public = build_withdraw_public(&env); // proves commitment opens to 100000000
    let c_burn = public.get(0).unwrap().to_bytes();
    client.deposit(&alice, &WITHDRAW_AMOUNT, &c_burn);
    assert_eq!(token_client.balance(&id), WITHDRAW_AMOUNT);

    // Steal-more: a real proof for 100000000, but request a 999000000 payout. The
    // i128 amount no longer equals pub_signals[1] -> AmountMismatch.
    let res = client.try_withdraw(&alice, &999_000_000, &build_withdraw_proof(&env), &public);
    assert_eq!(res, Err(Ok(Error::AmountMismatch)));

    // Under-report (1) is rejected the same way — the bind is exact in both directions.
    let res_low = client.try_withdraw(&alice, &1, &build_withdraw_proof(&env), &public);
    assert_eq!(res_low, Err(Ok(Error::AmountMismatch)));

    // A negative payout request can never match a non-negative proven amount.
    let res_neg = client.try_withdraw(&alice, &-100_000_000, &build_withdraw_proof(&env), &public);
    assert_eq!(res_neg, Err(Ok(Error::AmountMismatch)));

    // Nothing moved and the commitment is still alive (not burned).
    assert_eq!(token_client.balance(&id), WITHDRAW_AMOUNT, "no tokens moved");
    assert_eq!(token_client.balance(&alice), 1_000_000_000 - WITHDRAW_AMOUNT, "alice not paid");
    assert_eq!(client.has_balance(&alice), true, "commitment NOT burned on a rejected withdraw");
}

// Money-path sibling: forging the public AMOUNT signal (claim 999000000 with a
// matching i128 so the bind passes) does NOT help — no valid proof exists for the
// real commitment opening to 999000000, so the pairing fails -> ProofInvalid. The
// circuit forge-gate proves such a proof is unsatisfiable; here the contract rejects
// the only thing an attacker could submit (a garbage proof) at the pairing.
#[test]
fn withdraw_forged_amount_signal_rejected() {
    let (env, id, token, _admin, alice) = setup();
    let client = ZkConfidentialTransferClient::new(&env, &id);
    let token_client = token::Client::new(&env, &token);

    let public = build_withdraw_public(&env);
    let c_burn = public.get(0).unwrap().to_bytes();
    client.deposit(&alice, &WITHDRAW_AMOUNT, &c_burn);

    // Tampered public signals: SAME real commitment, but amount overwritten to
    // 999000000. The i128 request matches the forged signal (bind passes), so the
    // rejection must come from the proof verification itself.
    let mut forged = Vec::new(&env);
    forged.push_back(public.get(0).unwrap()); // real commitment
    forged.push_back(fr_from_decimal(&env, "999000000")); // forged amount
    let res = client.try_withdraw(&alice, &999_000_000, &build_withdraw_proof(&env), &forged);
    assert_eq!(res, Err(Ok(Error::ProofInvalid)));

    assert_eq!(token_client.balance(&id), WITHDRAW_AMOUNT, "no tokens moved");
    assert_eq!(client.has_balance(&alice), true, "commitment NOT burned");
}

// Arity guard: withdraw pub_signals MUST be exactly 2 ([commitment, amount]). Any
// other length is rejected BEFORE the stored-commitment read or any pairing work.
#[test]
fn withdraw_rejects_bad_arity() {
    let (env, id, _token, _admin, alice) = setup();
    let client = ZkConfidentialTransferClient::new(&env, &id);
    client.deposit(&alice, &WITHDRAW_AMOUNT, &commitment(&env, "777"));

    for n in [0u32, 1, 3, 4] {
        let mut ps = Vec::new(&env);
        for i in 0..n {
            ps.push_back(fr_from_decimal(&env, &std::format!("{}", i + 1)));
        }
        let res = client.try_withdraw(&alice, &WITHDRAW_AMOUNT, &dummy_proof(&env), &ps);
        assert_eq!(
            res,
            Err(Ok(Error::BadPublicSignals)),
            "withdraw pub_signals.len()={} must be rejected as BadPublicSignals",
            n
        );
    }
}

// Compare-and-swap guard: a proof whose commitment (pub_signals[0]) does not byte-
// match the account's CURRENT stored commitment is rejected with CommitmentMismatch
// (before the pairing). Sibling of the confidential_transfer stale-old tests.
#[test]
fn withdraw_rejects_commitment_mismatch() {
    let (env, id, _token, _admin, alice) = setup();
    let client = ZkConfidentialTransferClient::new(&env, &id);

    // alice's stored commitment is "5555"; the withdraw fixture's commitment is the
    // golden Poseidon opening -> they differ.
    client.deposit(&alice, &WITHDRAW_AMOUNT, &commitment(&env, "5555"));
    let public = build_withdraw_public(&env);
    let res = client.try_withdraw(&alice, &WITHDRAW_AMOUNT, &build_withdraw_proof(&env), &public);
    assert_eq!(res, Err(Ok(Error::CommitmentMismatch)));
    assert_eq!(client.get_commitment(&alice), Some(commitment(&env, "5555")), "untouched");
}

// AUTH GATE on the money-EXIT path. withdraw() moves REAL tokens OUT, so its
// `to.require_auth()` is the load-bearing authorization. No mock_all_auths: an
// unauthorized withdraw must be rejected at require_auth — the FIRST statement in
// withdraw(), before any arity check, stored-commitment read, or pairing. Sibling
// of confidential_transfer_rejects_unauthorized (which guards the swap path); this
// closes the same gap on the boundary exit, where the financial impact is direct.
// A real [commitment, amount] fixture + the matching i128 are supplied so the ONLY
// thing standing between the caller and a payout is the auth gate.
#[test]
fn withdraw_rejects_unauthorized() {
    let env = Env::default();
    let id = env.register(ZkConfidentialTransfer, ());
    let client = ZkConfidentialTransferClient::new(&env, &id);
    let mallory = soroban_sdk::Address::generate(&env);

    let public = build_withdraw_public(&env); // real [commitment, amount=100000000]
    let res = client.try_withdraw(&mallory, &WITHDRAW_AMOUNT, &build_withdraw_proof(&env), &public);
    assert!(res.is_err(), "unauthorized withdraw must fail at require_auth");
}

#[test]
fn read_only_accessors_initial_state() {
    let env = Env::default();
    let id = env.register(ZkConfidentialTransfer, ());
    let bare = ZkConfidentialTransferClient::new(&env, &id);
    assert_eq!(bare.get_token(), None);
    let nobody = soroban_sdk::Address::generate(&env);
    assert_eq!(bare.has_balance(&nobody), false);
    assert_eq!(bare.get_commitment(&nobody), None);

    let (env2, id2, token, _admin, _alice) = setup();
    let client = ZkConfidentialTransferClient::new(&env2, &id2);
    assert_eq!(client.get_token(), Some(token));
}

// HAPPY PATH — runs a REAL Groth16/BLS12-381 pairing against the dev-ceremony
// confidential_transfer proof fixture (data/proof.json + data/public.json: the 4
// commitments of a real conservative transfer — sender 150->100, recipient 30->80,
// t=50). This is the money-path acceptance test: it exercises the embedded VK
// ACCEPTING a valid proof. The rejection-path tests above use a dummy proof that
// fails the pairing regardless of VK, so only this test catches a wrong VK.
//
// Asserts: a valid proof advances BOTH commitments to their *_new values AND moves
// NO tokens (the pool float is unchanged — the amount stayed confidential).
#[test]
fn valid_confidential_transfer_updates_both_commitments() {
    let (env, id, token, _admin, alice) = setup();
    let client = ZkConfidentialTransferClient::new(&env, &id);
    let bob = soroban_sdk::Address::generate(&env);
    let token_client = token::Client::new(&env, &token);

    let public = build_public(&env); // [sender_old, sender_new, recipient_old, recipient_new]
    let c_sender_old = public.get(0).unwrap().to_bytes();
    let c_sender_new = public.get(1).unwrap().to_bytes();
    let c_recipient_old = public.get(2).unwrap().to_bytes();
    let c_recipient_new = public.get(3).unwrap().to_bytes();

    // Seed both accounts at the fixture's *_old commitments (deposits expose their
    // amounts — boundary). The pool float after both deposits is what we assert is
    // CONSTANT across the confidential transfer. setup() funds only alice, so bob
    // must be minted real tokens before his boundary deposit can move them in.
    token::StellarAssetClient::new(&env, &token).mint(&bob, &1_000_000_000);
    client.deposit(&alice, &100, &c_sender_old);
    client.deposit(&bob, &50, &c_recipient_old);
    let pool_float = token_client.balance(&id);

    client.confidential_transfer(&alice, &bob, &build_proof(&env), &public, &zero_ephemeral(&env), &empty_note(&env));

    assert_eq!(client.get_commitment(&alice), Some(c_sender_new), "sender advanced");
    assert_eq!(client.get_commitment(&bob), Some(c_recipient_new), "recipient advanced");
    assert_eq!(
        token_client.balance(&id),
        pool_float,
        "confidential_transfer moves NO tokens — amount stays pooled/confidential"
    );

    // Replay the same proof: sender_old is now stale -> CommitmentMismatch.
    let res = client.try_confidential_transfer(&alice, &bob, &build_proof(&env), &public, &zero_ephemeral(&env), &empty_note(&env));
    assert_eq!(res, Err(Ok(Error::CommitmentMismatch)));
}

// C0 FOLD-IN HAPPY PATH (v2) — a REAL pairing against the c0 fixture, whose
// recipient_old is the canonical empty balance C0 = Poseidon(0,0). The recipient
// NEVER deposits: the contract substitutes C0 for the absent slot, the proof
// verifies, and the `.set()` CREATES the recipient's commitment — a stranger is
// credited confidentially in ONE sender-signed transaction. Also pins the C0
// constant itself: pub_signals[2].to_bytes() MUST byte-equal crate::C0.
#[test]
fn valid_c0_fold_in_creates_recipient_slot() {
    let (env, id, token, _admin, alice) = setup();
    let client = ZkConfidentialTransferClient::new(&env, &id);
    let token_client = token::Client::new(&env, &token);
    let bob = soroban_sdk::Address::generate(&env);

    let public = build_c0_public(&env);
    let c_sender_old = public.get(0).unwrap().to_bytes();
    let c_sender_new = public.get(1).unwrap().to_bytes();
    let c_recipient_old = public.get(2).unwrap().to_bytes();
    let c_recipient_new = public.get(3).unwrap().to_bytes();

    // The fixture's recipient_old IS the on-chain C0 constant (Poseidon(0,0)).
    assert_eq!(c_recipient_old, BytesN::from_array(&env, &crate::C0), "fixture opens C0");

    // Only the SENDER deposits; bob has NO on-chain slot at transfer time.
    client.deposit(&alice, &150, &c_sender_old);
    assert_eq!(client.has_balance(&bob), false, "recipient absent before fold-in");
    let pool_float = token_client.balance(&id);

    client.confidential_transfer(&alice, &bob, &build_c0_proof(&env), &public, &zero_ephemeral(&env), &empty_note(&env));

    assert_eq!(client.get_commitment(&alice), Some(c_sender_new), "sender advanced");
    assert_eq!(
        client.get_commitment(&bob),
        Some(c_recipient_new),
        "fold-in CREATED the recipient slot at recipient_new"
    );
    assert_eq!(token_client.balance(&id), pool_float, "fold-in moved no tokens");

    // Replay: alice's sender_old is consumed -> CommitmentMismatch, bob keeps his slot.
    let res = client.try_confidential_transfer(&alice, &bob, &build_c0_proof(&env), &public, &zero_ephemeral(&env), &empty_note(&env));
    assert_eq!(res, Err(Ok(Error::CommitmentMismatch)));
}

// Writes the testnet `stellar contract invoke` arguments to the OS temp dir so a
// REAL deploy+cycle can consume them. Same hex-encoding the proven
// zk-verified-payment `dump_invoke_args` uses (uncompressed ark G1/G2 == exactly
// the bytes the contract decodes) — shared verbatim, only the data dir + output
// paths differ. Run with:
//   cargo test dump_invoke_args --target <host> -- --nocapture
//
// Emits (under std::env::temp_dir()):
//   cinv_vk.json      -> initialize --vk-file-path
//   cinv_proof.json   -> confidential_transfer --proof-file-path
//   cinv_pub.json     -> confidential_transfer --pub_signals-file-path
// and PRINTS the four commitment byte-strings (= pub_signals[i].to_bytes(), the
// BytesN<32> the contract stores) so deposit(...) can register the *_old
// commitments the confidential_transfer compare-and-swap will then advance.
#[test]
fn dump_invoke_args() {
    use std::string::String;
    let vk = load("verification_key.json");
    let pr = load("proof.json");
    let pubj = load("public.json");

    let hexb = |bytes: &[u8]| -> String {
        let mut s = String::new();
        for b in bytes {
            s.push_str(&std::format!("{:02x}", b));
        }
        s
    };
    let g1h = |p: &Value| -> String {
        let g = ark_bls12_381::G1Affine::new(
            Fq::from_str(cs(&p[0])).unwrap(),
            Fq::from_str(cs(&p[1])).unwrap(),
        );
        let mut buf = [0u8; G1_SERIALIZED_SIZE];
        g.serialize_uncompressed(&mut buf[..]).unwrap();
        hexb(&buf)
    };
    let g2h = |p: &Value| -> String {
        let x = Fq2::new(
            Fq::from_str(cs(&p[0][0])).unwrap(),
            Fq::from_str(cs(&p[0][1])).unwrap(),
        );
        let y = Fq2::new(
            Fq::from_str(cs(&p[1][0])).unwrap(),
            Fq::from_str(cs(&p[1][1])).unwrap(),
        );
        let g = ark_bls12_381::G2Affine::new(x, y);
        let mut buf = [0u8; G2_SERIALIZED_SIZE];
        g.serialize_uncompressed(&mut buf[..]).unwrap();
        hexb(&buf)
    };

    let ic: std::vec::Vec<String> = vk["IC"]
        .as_array()
        .unwrap()
        .iter()
        .map(|p| std::format!("\"{}\"", g1h(p)))
        .collect();
    let vk_json = std::format!(
        "{{ \"alpha\": \"{}\", \"beta\": \"{}\", \"gamma\": \"{}\", \"delta\": \"{}\", \"ic\": [{}] }}",
        g1h(&vk["vk_alpha_1"]),
        g2h(&vk["vk_beta_2"]),
        g2h(&vk["vk_gamma_2"]),
        g2h(&vk["vk_delta_2"]),
        ic.join(",")
    );
    let proof_json = std::format!(
        "{{ \"a\": \"{}\", \"b\": \"{}\", \"c\": \"{}\" }}",
        g1h(&pr["pi_a"]),
        g2h(&pr["pi_b"]),
        g1h(&pr["pi_c"])
    );
    let sigs: std::vec::Vec<String> = pubj
        .as_array()
        .unwrap()
        .iter()
        .map(|s| std::format!("\"{}\"", cs(s)))
        .collect();
    let pub_json = std::format!("[{}]", sigs.join(","));

    let tmp = std::env::temp_dir();
    fs::write(tmp.join("cinv_vk.json"), &vk_json).unwrap();
    fs::write(tmp.join("cinv_proof.json"), &proof_json).unwrap();
    fs::write(tmp.join("cinv_pub.json"), &pub_json).unwrap();

    // The deposit commitment is the byte-image of the field element the contract
    // compares: deposit --commitment <hex> must equal pub_signals[i].to_bytes().
    let env = Env::default();
    let labels = ["sender_old", "sender_new", "recipient_old", "recipient_new"];
    std::println!("WROTE {}/cinv_{{vk,proof,pub}}.json", tmp.display());
    for (i, sig) in pubj.as_array().unwrap().iter().enumerate() {
        let bytes = fr_from_decimal(&env, cs(sig)).to_bytes();
        std::println!("COMMITMENT[{}] {} = {}", i, labels[i], hexb(&bytes.to_array()));
    }
}

// Sibling of dump_invoke_args for the WITHDRAW verifying key (the runbook's S2(c)
// step — its absence is exactly how the deployed WithdrawVk drifted from every
// live zkey). Reads data/withdraw_verification_key.json and writes the
// contract-ready `initialize --withdraw_vk-file-path` arg:
//   cargo test dump_withdraw_invoke_args --target <host> -- --nocapture
// Emits (under std::env::temp_dir()): cinv_withdraw_vk.json
#[test]
fn dump_withdraw_invoke_args() {
    use std::string::String;
    let vk = load("withdraw_verification_key.json");

    let hexb = |bytes: &[u8]| -> String {
        let mut s = String::new();
        for b in bytes {
            s.push_str(&std::format!("{:02x}", b));
        }
        s
    };
    let g1h = |p: &Value| -> String {
        let g = ark_bls12_381::G1Affine::new(
            Fq::from_str(cs(&p[0])).unwrap(),
            Fq::from_str(cs(&p[1])).unwrap(),
        );
        let mut buf = [0u8; G1_SERIALIZED_SIZE];
        g.serialize_uncompressed(&mut buf[..]).unwrap();
        hexb(&buf)
    };
    let g2h = |p: &Value| -> String {
        let x = Fq2::new(
            Fq::from_str(cs(&p[0][0])).unwrap(),
            Fq::from_str(cs(&p[0][1])).unwrap(),
        );
        let y = Fq2::new(
            Fq::from_str(cs(&p[1][0])).unwrap(),
            Fq::from_str(cs(&p[1][1])).unwrap(),
        );
        let g = ark_bls12_381::G2Affine::new(x, y);
        let mut buf = [0u8; G2_SERIALIZED_SIZE];
        g.serialize_uncompressed(&mut buf[..]).unwrap();
        hexb(&buf)
    };

    let ic: std::vec::Vec<String> = vk["IC"]
        .as_array()
        .unwrap()
        .iter()
        .map(|p| std::format!("\"{}\"", g1h(p)))
        .collect();
    let vk_json = std::format!(
        "{{ \"alpha\": \"{}\", \"beta\": \"{}\", \"gamma\": \"{}\", \"delta\": \"{}\", \"ic\": [{}] }}",
        g1h(&vk["vk_alpha_1"]),
        g2h(&vk["vk_beta_2"]),
        g2h(&vk["vk_gamma_2"]),
        g2h(&vk["vk_delta_2"]),
        ic.join(",")
    );

    let tmp = std::env::temp_dir();
    fs::write(tmp.join("cinv_withdraw_vk.json"), &vk_json).unwrap();
    std::println!("WROTE {}/cinv_withdraw_vk.json", tmp.display());
}

// ===========================================================================
// Additive coverage — NoBalance / AlreadyInitialized / zero-amount boundaries /
// asymmetric mismatch / full arity sweep / pool conservation / cross-recipient
// double-spend. All reuse the existing helpers + the single real proof fixture; no
// money-path logic is exercised differently from the suite above.
// ===========================================================================

#[test]
fn confidential_transfer_rejects_unregistered_sender() {
    // Sender never deposited -> the compare-and-swap's FIRST storage read returns
    // NoBalance (before the recipient read or any pairing work). The recipient IS
    // registered here, so the failure is unambiguously the sender branch.
    let (env, id, _token, _admin, alice) = setup();
    let client = ZkConfidentialTransferClient::new(&env, &id);
    let bob = soroban_sdk::Address::generate(&env);
    client.deposit(&bob, &0, &commitment(&env, "2000")); // only the recipient registered

    let mut ps = Vec::new(&env);
    for s in ["1", "2", "2000", "2099"] {
        ps.push_back(fr_from_decimal(&env, s));
    }
    let res = client.try_confidential_transfer(&alice, &bob, &dummy_proof(&env), &ps, &zero_ephemeral(&env), &empty_note(&env));
    assert_eq!(res, Err(Ok(Error::NoBalance)));
}

#[test]
fn confidential_transfer_absent_recipient_defaults_to_c0() {
    // C0 FOLD-IN (v2): an ABSENT recipient no longer short-circuits to NoBalance —
    // the contract substitutes C0 = Poseidon(0,0) as the recipient's old commitment,
    // so a sender can credit a not-yet-registered account in ONE signed tx. The
    // compare-and-swap therefore REJECTS any recipient_old that is NOT C0 (here
    // "2000") with CommitmentMismatch, and the recipient slot is never created.
    let (env, id, _token, _admin, alice) = setup();
    let client = ZkConfidentialTransferClient::new(&env, &id);
    let bob = soroban_sdk::Address::generate(&env);
    client.deposit(&alice, &100, &commitment(&env, "1000")); // sender registered; bob is NOT

    let mut ps = Vec::new(&env);
    ps.push_back(fr_from_decimal(&env, "1000")); // sender_old MATCHES stored
    ps.push_back(fr_from_decimal(&env, "1001")); // sender_new
    ps.push_back(fr_from_decimal(&env, "2000")); // recipient_old != C0
    ps.push_back(fr_from_decimal(&env, "2099")); // recipient_new
    let res = client.try_confidential_transfer(&alice, &bob, &dummy_proof(&env), &ps, &zero_ephemeral(&env), &empty_note(&env));
    assert_eq!(res, Err(Ok(Error::CommitmentMismatch)));
    assert_eq!(client.has_balance(&bob), false, "no slot created on a rejected fold-in");
}

#[test]
fn confidential_transfer_absent_recipient_c0_reaches_pairing() {
    // C0 FOLD-IN acceptance of the CAS precondition: with recipient_old == C0 the
    // compare-and-swap PASSES for an absent recipient and the flow reaches the
    // pairing check — a garbage proof then fails there (ProofInvalid, NOT
    // NoBalance/CommitmentMismatch). Proves the C0 default is what unlocks the
    // one-tx credit of an unregistered account. (The REAL-proof happy path for the
    // fold-in is valid_c0_fold_in_creates_recipient_slot below.)
    let (env, id, _token, _admin, alice) = setup();
    let client = ZkConfidentialTransferClient::new(&env, &id);
    let bob = soroban_sdk::Address::generate(&env);
    client.deposit(&alice, &100, &commitment(&env, "1000"));

    let c0 = Fr::from_u256(U256::from_be_bytes(&env, &Bytes::from_array(&env, &crate::C0)));
    let mut ps = Vec::new(&env);
    ps.push_back(fr_from_decimal(&env, "1000")); // sender_old MATCHES stored
    ps.push_back(fr_from_decimal(&env, "1001")); // sender_new
    ps.push_back(c0); // recipient_old == C0 -> CAS passes for the ABSENT recipient
    ps.push_back(fr_from_decimal(&env, "2099")); // recipient_new
    let res = client.try_confidential_transfer(&alice, &bob, &dummy_proof(&env), &ps, &zero_ephemeral(&env), &empty_note(&env));
    assert_eq!(res, Err(Ok(Error::ProofInvalid)));
    assert_eq!(client.has_balance(&bob), false, "no slot created on a rejected proof");
}

#[test]
fn initialize_twice_rejected() {
    // setup() already initialized once; a second initialize must be rejected by the
    // AlreadyInitialized guard (checked BEFORE admin.require_auth()).
    let (env, id, token, admin, _alice) = setup();
    let client = ZkConfidentialTransferClient::new(&env, &id);
    let res = client.try_initialize(&admin, &token, &build_vk(&env), &build_withdraw_vk(&env));
    assert_eq!(res, Err(Ok(Error::AlreadyInitialized)));
}

#[test]
fn deposit_zero_amount_registers_commitment() {
    // Boundary: depositing amount = 0 still registers the confidential commitment
    // (e.g. seeding a fresh recipient before they receive). token::transfer(0) is a
    // valid no-op move; the pool float stays 0 and the depositor is not debited.
    let (env, id, token, _admin, alice) = setup();
    let client = ZkConfidentialTransferClient::new(&env, &id);
    let token_client = token::Client::new(&env, &token);

    let c = commitment(&env, "55555");
    client.deposit(&alice, &0, &c);
    assert_eq!(client.has_balance(&alice), true);
    assert_eq!(client.get_commitment(&alice), Some(c));
    assert_eq!(token_client.balance(&id), 0, "pool float unchanged by a zero deposit");
    assert_eq!(token_client.balance(&alice), 1_000_000_000, "depositor not debited");
}

#[test]
fn withdraw_zero_amount_still_burns_commitment() {
    // Boundary edge: a TRUSTLESS withdraw of amount = 0 still needs a REAL proof that
    // the burned commitment opens to 0 (data/withdraw_zero_*). It burns the
    // commitment (exit the pool) WITHOUT moving tokens. Num2Bits(64) accepts 0, so
    // the zero opening is a valid proof.
    let (env, id, token, _admin, alice) = setup();
    let client = ZkConfidentialTransferClient::new(&env, &id);
    let token_client = token::Client::new(&env, &token);

    let zero_public = build_withdraw_zero_public(&env); // [commitment, amount=0]
    let c_zero = zero_public.get(0).unwrap().to_bytes();
    client.deposit(&alice, &0, &c_zero); // zero deposit registers the commitment, debits nothing
    assert_eq!(token_client.balance(&id), 0, "zero deposit funds nothing");

    client.withdraw(&alice, &0, &build_withdraw_zero_proof(&env), &zero_public);
    assert_eq!(client.has_balance(&alice), false, "commitment burned even on a zero withdraw");
    assert_eq!(token_client.balance(&id), 0, "no tokens moved by a zero withdraw");
    assert_eq!(token_client.balance(&alice), 1_000_000_000, "depositor balance unchanged");
}

#[test]
fn withdraw_without_deposit_rejected() {
    // Direct withdraw against an account that never registered a commitment -> the
    // stored-commitment read returns NoBalance (after the arity guard, before any
    // pairing). Distinct from the post-burn replay path in
    // withdraw_pays_out_and_burns_commitment (this account never deposited). A valid
    // arity + real proof is supplied to prove NoBalance short-circuits first.
    let (env, id, _token, _admin, alice) = setup();
    let client = ZkConfidentialTransferClient::new(&env, &id);
    let public = build_withdraw_public(&env);

    let carol = soroban_sdk::Address::generate(&env); // never deposited
    assert_eq!(
        client.try_withdraw(&carol, &WITHDRAW_AMOUNT, &build_withdraw_proof(&env), &public),
        Err(Ok(Error::NoBalance))
    );
    // alice is funded but likewise never deposited INTO the pool -> also NoBalance.
    assert_eq!(
        client.try_withdraw(&alice, &WITHDRAW_AMOUNT, &build_withdraw_proof(&env), &public),
        Err(Ok(Error::NoBalance))
    );
}

#[test]
fn confidential_transfer_rejects_stale_recipient_old() {
    // Asymmetric mismatch: sender_old MATCHES the stored commitment but recipient_old
    // is stale -> CommitmentMismatch from the RECIPIENT branch. Sibling of
    // confidential_transfer_rejects_stale_sender_old (which exercises the SENDER
    // branch). No stored commitment changes.
    let (env, id, _token, _admin, alice) = setup();
    let client = ZkConfidentialTransferClient::new(&env, &id);
    let bob = soroban_sdk::Address::generate(&env);

    client.deposit(&alice, &100, &commitment(&env, "1000")); // stored sender = 1000
    client.deposit(&bob, &0, &commitment(&env, "2000")); // stored recipient = 2000

    let mut ps = Vec::new(&env);
    ps.push_back(fr_from_decimal(&env, "1000")); // sender_old MATCHES
    ps.push_back(fr_from_decimal(&env, "1001")); // sender_new
    ps.push_back(fr_from_decimal(&env, "9999")); // STALE recipient_old (!= 2000)
    ps.push_back(fr_from_decimal(&env, "2099")); // recipient_new
    let res = client.try_confidential_transfer(&alice, &bob, &dummy_proof(&env), &ps, &zero_ephemeral(&env), &empty_note(&env));
    assert_eq!(res, Err(Ok(Error::CommitmentMismatch)));

    assert_eq!(client.get_commitment(&alice), Some(commitment(&env, "1000")));
    assert_eq!(client.get_commitment(&bob), Some(commitment(&env, "2000")));
}

#[test]
fn confidential_transfer_rejects_all_bad_arities() {
    // pub_signals MUST be exactly 4. Every other length (empty, under, over, large)
    // is rejected by the arity guard BEFORE any storage read or pairing work. Extends
    // confidential_transfer_rejects_bad_arity (which only covers len = 3). len = 100
    // would otherwise reach the MalformedVerifyingKey check inside verify_groth16, so
    // returning BadPublicSignals proves the arity guard short-circuits first.
    let (env, id, _token, _admin, alice) = setup();
    let client = ZkConfidentialTransferClient::new(&env, &id);
    let bob = soroban_sdk::Address::generate(&env);

    for n in [0u32, 1, 2, 3, 5, 100] {
        let mut ps = Vec::new(&env);
        for i in 0..n {
            ps.push_back(fr_from_decimal(&env, &std::format!("{}", i + 1)));
        }
        let res = client.try_confidential_transfer(&alice, &bob, &dummy_proof(&env), &ps, &zero_ephemeral(&env), &empty_note(&env));
        assert_eq!(
            res,
            Err(Ok(Error::BadPublicSignals)),
            "pub_signals.len()={} must be rejected as BadPublicSignals before pairing",
            n
        );
    }
}

#[test]
fn pool_balance_equals_deposits_minus_withdrawals() {
    // Pool invariant at the BOUNDARY: the pool float is exactly sum(deposits) -
    // sum(withdrawals). Each withdraw runs a REAL open-to-amount proof (the trustless
    // boundary), so the amount paid out is provably the commitment's opening. (The
    // pool-neutrality of confidential_transfer itself — it moves no tokens — is
    // covered by valid_confidential_transfer_updates_both_commitments. We cannot
    // withdraw a POST-transfer commitment here because the test does not hold its
    // opening; the boundary conservation below uses commitments whose openings the
    // withdraw fixtures DO prove.)
    let (env, id, token, _admin, alice) = setup();
    let client = ZkConfidentialTransferClient::new(&env, &id);
    let bob = soroban_sdk::Address::generate(&env);
    let token_client = token::Client::new(&env, &token);
    token::StellarAssetClient::new(&env, &token).mint(&bob, &1_000_000_000);

    let public = build_withdraw_public(&env); // alice: commitment opens to 100000000
    let zero_public = build_withdraw_zero_public(&env); // bob: commitment opens to 0
    client.deposit(&alice, &WITHDRAW_AMOUNT, &public.get(0).unwrap().to_bytes()); // +100000000
    client.deposit(&bob, &0, &zero_public.get(0).unwrap().to_bytes()); // +0 -> pool 100000000
    assert_eq!(token_client.balance(&id), WITHDRAW_AMOUNT);

    client.withdraw(&bob, &0, &build_withdraw_zero_proof(&env), &zero_public); // -0
    assert_eq!(token_client.balance(&id), WITHDRAW_AMOUNT, "zero withdraw moves nothing");

    client.withdraw(&alice, &WITHDRAW_AMOUNT, &build_withdraw_proof(&env), &public); // -100000000
    assert_eq!(
        token_client.balance(&id),
        WITHDRAW_AMOUNT - WITHDRAW_AMOUNT,
        "pool == sum(deposits) - sum(withdrawals)"
    );
    assert_eq!(token_client.balance(&id), 0);
}

#[test]
fn confidential_transfer_double_spend_same_sender_old_rejected() {
    // Concurrency / double-spend safety: once a valid transfer advances the sender's
    // commitment, the consumed sender_old can NEVER be reused -- not even toward a
    // DIFFERENT recipient. The compare-and-swap rejects the stale sender_old with
    // CommitmentMismatch (before any pairing) and no second advance occurs. (The
    // same-(sender, recipient, proof) replay is already covered by
    // valid_confidential_transfer_updates_both_commitments; this adds the
    // different-recipient angle of the same guard.)
    let (env, id, token, _admin, alice) = setup();
    let client = ZkConfidentialTransferClient::new(&env, &id);
    let bob = soroban_sdk::Address::generate(&env);
    let carol = soroban_sdk::Address::generate(&env);

    let public = build_public(&env);
    let c_sender_old = public.get(0).unwrap().to_bytes();
    let c_sender_new = public.get(1).unwrap().to_bytes();
    let c_recipient_old = public.get(2).unwrap().to_bytes();

    token::StellarAssetClient::new(&env, &token).mint(&bob, &1_000_000_000);
    client.deposit(&alice, &100, &c_sender_old);
    client.deposit(&bob, &50, &c_recipient_old);

    // First (valid) transfer advances alice to c_sender_new.
    client.confidential_transfer(&alice, &bob, &build_proof(&env), &public, &zero_ephemeral(&env), &empty_note(&env));
    assert_eq!(client.get_commitment(&alice), Some(c_sender_new.clone()), "sender advanced once");

    // Attempt to re-spend the now-stale sender_old, this time toward carol.
    client.deposit(&carol, &0, &commitment(&env, "8888"));
    let mut ps2 = Vec::new(&env);
    ps2.push_back(public.get(0).unwrap()); // STALE sender_old (already consumed)
    ps2.push_back(fr_from_decimal(&env, "123")); // arbitrary sender_new
    ps2.push_back(fr_from_decimal(&env, "8888")); // carol recipient_old (matches stored)
    ps2.push_back(fr_from_decimal(&env, "9001")); // carol recipient_new
    let res = client.try_confidential_transfer(&alice, &carol, &dummy_proof(&env), &ps2, &zero_ephemeral(&env), &empty_note(&env));
    assert_eq!(res, Err(Ok(Error::CommitmentMismatch)));

    // No second advance: alice still at c_sender_new, carol untouched.
    assert_eq!(client.get_commitment(&alice), Some(c_sender_new));
    assert_eq!(client.get_commitment(&carol), Some(commitment(&env, "8888")));
}

// ===========================================================================
// Additive SCENARIO coverage — multi-step chains, interleaving, mid-chain replay,
// before/after deposit, pre-initialize, and double-withdraw. All reuse the existing
// helpers + the SAME single real transfer proof and withdraw fixtures; no money-path
// logic is exercised differently. Two scenario harness facts make these honest:
//   * The Groth16 proof binds to the 4 commitment VALUES (the public signals) and
//     the VK — NOT to the sender/recipient ADDRESSES. So the one real conservative-
//     transfer proof can drive a SECOND independent per-account compare-and-swap on a
//     different pair (a test-harness reuse, NOT a claim two users share a commitment).
//   * The transfer fixture's *_new commitments and the withdraw fixture's commitment
//     are unrelated Poseidon outputs (no on-chain homomorphism), so a chain's exit
//     leg withdraws a SEPARATELY-seeded account holding the withdraw fixture's opening.
// ===========================================================================

// MULTI-STEP CHAIN: deposit -> transfer -> transfer -> withdraw on a shared pool.
// Two confidential transfers (REAL proof, reused across two pairs) move value with
// ZERO token motion, and a trustless withdraw exits a third balance. The asserted
// invariant: the pool float is CONSTANT across BOTH confidential ops and changes ONLY
// at the boundary deposit/withdraw — and by EXACTLY the proven withdraw amount.
#[test]
fn multi_step_chain_deposit_transfer_transfer_withdraw() {
    let (env, id, token, _admin, alice) = setup();
    let client = ZkConfidentialTransferClient::new(&env, &id);
    let token_client = token::Client::new(&env, &token);
    let bob = soroban_sdk::Address::generate(&env);
    let carol = soroban_sdk::Address::generate(&env);
    let dave = soroban_sdk::Address::generate(&env);
    let erin = soroban_sdk::Address::generate(&env);

    // setup() funds only alice; the other boundary depositors need real tokens.
    let sac = token::StellarAssetClient::new(&env, &token);
    for a in [&bob, &carol, &dave, &erin] {
        sac.mint(a, &1_000_000_000);
    }

    let public = build_public(&env); // [sender_old, sender_new, recipient_old, recipient_new]
    let c_sender_old = public.get(0).unwrap().to_bytes();
    let c_sender_new = public.get(1).unwrap().to_bytes();
    let c_recipient_old = public.get(2).unwrap().to_bytes();
    let c_recipient_new = public.get(3).unwrap().to_bytes();
    let wpublic = build_withdraw_public(&env); // [commitment, amount=100000000]
    let c_withdraw = wpublic.get(0).unwrap().to_bytes();

    // STEP 1 (boundary, amounts visible): seed two transfer pairs + one exit balance.
    // The two pairs reuse the fixture commitment VALUES under DISTINCT per-account keys.
    client.deposit(&alice, &100, &c_sender_old);
    client.deposit(&bob, &50, &c_recipient_old);
    client.deposit(&carol, &100, &c_sender_old);
    client.deposit(&dave, &50, &c_recipient_old);
    client.deposit(&erin, &WITHDRAW_AMOUNT, &c_withdraw);
    let pool_after_deposits = token_client.balance(&id);
    assert_eq!(pool_after_deposits, 100 + 50 + 100 + 50 + WITHDRAW_AMOUNT);

    // STEP 2 (confidential): pair A advances; NO token moves.
    client.confidential_transfer(&alice, &bob, &build_proof(&env), &public, &zero_ephemeral(&env), &empty_note(&env));
    assert_eq!(client.get_commitment(&alice), Some(c_sender_new.clone()), "A sender advanced");
    assert_eq!(client.get_commitment(&bob), Some(c_recipient_new.clone()), "A recipient advanced");
    assert_eq!(token_client.balance(&id), pool_after_deposits, "confidential op #1 moved no tokens");

    // STEP 3 (confidential): pair B advances with the SAME real proof; STILL no motion.
    client.confidential_transfer(&carol, &dave, &build_proof(&env), &public, &zero_ephemeral(&env), &empty_note(&env));
    assert_eq!(client.get_commitment(&carol), Some(c_sender_new.clone()), "B sender advanced");
    assert_eq!(client.get_commitment(&dave), Some(c_recipient_new.clone()), "B recipient advanced");
    assert_eq!(
        token_client.balance(&id),
        pool_after_deposits,
        "pool float CONSTANT across BOTH confidential transfers"
    );

    // STEP 4 (boundary exit): trustless open-to-amount withdraw burns erin's commitment
    // and pays out EXACTLY the proven amount — the only float change after the deposits.
    client.withdraw(&erin, &WITHDRAW_AMOUNT, &build_withdraw_proof(&env), &wpublic);
    assert_eq!(client.has_balance(&erin), false, "exited commitment burned");
    assert_eq!(token_client.balance(&erin), 1_000_000_000, "withdrawer made whole");
    assert_eq!(
        token_client.balance(&id),
        pool_after_deposits - WITHDRAW_AMOUNT,
        "pool dropped by EXACTLY the proven withdraw amount; confidential legs were float-neutral"
    );

    // The two transferred pairs remain at their advanced commitments (chain end-state).
    assert_eq!(client.get_commitment(&alice), Some(c_sender_new.clone()));
    assert_eq!(client.get_commitment(&bob), Some(c_recipient_new.clone()));
    assert_eq!(client.get_commitment(&carol), Some(c_sender_new));
    assert_eq!(client.get_commitment(&dave), Some(c_recipient_new));
}

// CONCURRENT / INTERLEAVED transfers on two account pairs. The Soroban test host is
// single-threaded, so "concurrent" is modelled as INTERLEAVED sequential ops; the
// real safety property under test is per-account `DataKey::Balance(Address)` ISOLATION
// — advancing one pair must leave the other pair's stored commitments byte-untouched,
// and the pool float must stay constant across both confidential ops.
#[test]
fn interleaved_transfers_two_pairs_isolated() {
    let (env, id, token, _admin, alice) = setup();
    let client = ZkConfidentialTransferClient::new(&env, &id);
    let token_client = token::Client::new(&env, &token);
    let bob = soroban_sdk::Address::generate(&env);
    let carol = soroban_sdk::Address::generate(&env);
    let dave = soroban_sdk::Address::generate(&env);
    let sac = token::StellarAssetClient::new(&env, &token);
    for a in [&bob, &carol, &dave] {
        sac.mint(a, &1_000_000_000);
    }

    let public = build_public(&env);
    let c_sender_old = public.get(0).unwrap().to_bytes();
    let c_sender_new = public.get(1).unwrap().to_bytes();
    let c_recipient_old = public.get(2).unwrap().to_bytes();
    let c_recipient_new = public.get(3).unwrap().to_bytes();

    // Interleave the two pairs' boundary deposits (A-sender, B-sender, A-recip, B-recip).
    client.deposit(&alice, &100, &c_sender_old); // pair A sender
    client.deposit(&carol, &100, &c_sender_old); // pair B sender
    client.deposit(&bob, &50, &c_recipient_old); // pair A recipient
    client.deposit(&dave, &50, &c_recipient_old); // pair B recipient
    let pool = token_client.balance(&id);

    // Advance pair A. Pair B MUST be byte-untouched (storage isolation).
    client.confidential_transfer(&alice, &bob, &build_proof(&env), &public, &zero_ephemeral(&env), &empty_note(&env));
    assert_eq!(client.get_commitment(&alice), Some(c_sender_new.clone()), "A sender advanced");
    assert_eq!(client.get_commitment(&bob), Some(c_recipient_new.clone()), "A recipient advanced");
    assert_eq!(client.get_commitment(&carol), Some(c_sender_old.clone()), "B sender untouched by A");
    assert_eq!(client.get_commitment(&dave), Some(c_recipient_old.clone()), "B recipient untouched by A");
    assert_eq!(token_client.balance(&id), pool, "no token move on A's confidential op");

    // Now advance pair B. Pair A stays at its final commitments.
    client.confidential_transfer(&carol, &dave, &build_proof(&env), &public, &zero_ephemeral(&env), &empty_note(&env));
    assert_eq!(client.get_commitment(&carol), Some(c_sender_new.clone()), "B sender advanced");
    assert_eq!(client.get_commitment(&dave), Some(c_recipient_new.clone()), "B recipient advanced");
    assert_eq!(client.get_commitment(&alice), Some(c_sender_new), "A sender unchanged by B");
    assert_eq!(client.get_commitment(&bob), Some(c_recipient_new), "A recipient unchanged by B");
    assert_eq!(token_client.balance(&id), pool, "pool float constant across both interleaved ops");
}

// MID-CHAIN REPLAY of an already-consumed proof. After alice -> bob (step 1) and a
// further chain step carol -> dave (step 2), re-submitting alice's ORIGINAL proof is
// rejected with CommitmentMismatch: alice's stored commitment has advanced past
// sender_old, so the compare-and-swap fails BEFORE the pairing — even though the proof
// is itself cryptographically valid. No commitment moves and the float is unchanged.
#[test]
fn replay_old_proof_rejected_mid_chain() {
    let (env, id, token, _admin, alice) = setup();
    let client = ZkConfidentialTransferClient::new(&env, &id);
    let token_client = token::Client::new(&env, &token);
    let bob = soroban_sdk::Address::generate(&env);
    let carol = soroban_sdk::Address::generate(&env);
    let dave = soroban_sdk::Address::generate(&env);
    let sac = token::StellarAssetClient::new(&env, &token);
    for a in [&bob, &carol, &dave] {
        sac.mint(a, &1_000_000_000);
    }

    let public = build_public(&env);
    let c_sender_old = public.get(0).unwrap().to_bytes();
    let c_sender_new = public.get(1).unwrap().to_bytes();
    let c_recipient_old = public.get(2).unwrap().to_bytes();
    let c_recipient_new = public.get(3).unwrap().to_bytes();

    client.deposit(&alice, &100, &c_sender_old);
    client.deposit(&bob, &50, &c_recipient_old);
    client.deposit(&carol, &100, &c_sender_old);
    client.deposit(&dave, &50, &c_recipient_old);
    let pool = token_client.balance(&id);

    // Step 1: alice -> bob (consumes alice's sender_old).
    client.confidential_transfer(&alice, &bob, &build_proof(&env), &public, &zero_ephemeral(&env), &empty_note(&env));
    // Step 2: carol -> dave (chain advances further).
    client.confidential_transfer(&carol, &dave, &build_proof(&env), &public, &zero_ephemeral(&env), &empty_note(&env));

    // REPLAY the step-1 proof: alice is now at sender_new != sender_old -> CommitmentMismatch.
    let res = client.try_confidential_transfer(&alice, &bob, &build_proof(&env), &public, &zero_ephemeral(&env), &empty_note(&env));
    assert_eq!(res, Err(Ok(Error::CommitmentMismatch)));

    // No side effects: every commitment is at its post-step value; float untouched.
    assert_eq!(client.get_commitment(&alice), Some(c_sender_new.clone()));
    assert_eq!(client.get_commitment(&bob), Some(c_recipient_new.clone()));
    assert_eq!(client.get_commitment(&carol), Some(c_sender_new));
    assert_eq!(client.get_commitment(&dave), Some(c_recipient_new));
    assert_eq!(token_client.balance(&id), pool, "rejected replay moved no tokens");
}

// WITHDRAW BEFORE DEPOSIT then AFTER. The SAME account + SAME real open-to-amount
// proof: rejected NoBalance before any deposit (no stored commitment to burn), then
// accepted once the boundary deposit registers the withdrawable commitment. Exercises
// the before/after transition on ONE account (sibling to withdraw_without_deposit_rejected,
// which only covers the "before" on never-deposited accounts).
#[test]
fn withdraw_before_deposit_then_after_deposit_succeeds() {
    let (env, id, token, _admin, alice) = setup();
    let client = ZkConfidentialTransferClient::new(&env, &id);
    let token_client = token::Client::new(&env, &token);

    let public = build_withdraw_public(&env);
    let c = public.get(0).unwrap().to_bytes();

    // BEFORE: alice never deposited -> NoBalance (after arity guard, before pairing).
    // A REAL proof is supplied to prove NoBalance short-circuits first.
    assert_eq!(
        client.try_withdraw(&alice, &WITHDRAW_AMOUNT, &build_withdraw_proof(&env), &public),
        Err(Ok(Error::NoBalance))
    );
    assert_eq!(token_client.balance(&id), 0, "pool not funded yet");

    // Boundary deposit seeds the exact withdrawable commitment.
    client.deposit(&alice, &WITHDRAW_AMOUNT, &c);
    assert_eq!(token_client.balance(&id), WITHDRAW_AMOUNT);

    // AFTER: the identical withdraw now succeeds.
    client.withdraw(&alice, &WITHDRAW_AMOUNT, &build_withdraw_proof(&env), &public);
    assert_eq!(client.has_balance(&alice), false, "commitment burned on exit");
    assert_eq!(token_client.balance(&id), 0, "pool paid out");
    assert_eq!(token_client.balance(&alice), 1_000_000_000, "alice made whole");
}

// TRANSFER BEFORE INITIALIZE. On a BARE (registered-but-never-initialized) contract,
// confidential_transfer is rejected. The exact code is NoBalance, not NotInitialized,
// and the test proves WHY that is the only reachable pre-init outcome: a balance can
// only exist via deposit(), which itself requires Token (set at initialize) and so
// returns NotInitialized pre-init. No account can hold a commitment before init, so the
// sender-commitment read short-circuits to NoBalance before the VK/NotInitialized branch.
#[test]
fn confidential_transfer_before_initialize_rejected() {
    let env = Env::default();
    env.mock_all_auths(); // get PAST require_auth to the storage reads
    let id = env.register(ZkConfidentialTransfer, ());
    let client = ZkConfidentialTransferClient::new(&env, &id);
    let alice = soroban_sdk::Address::generate(&env);
    let bob = soroban_sdk::Address::generate(&env);
    assert_eq!(client.get_token(), None, "contract is uninitialized");

    // You cannot seed a balance pre-init: deposit reads Token -> NotInitialized.
    assert_eq!(
        client.try_deposit(&alice, &100, &commitment(&env, "1")),
        Err(Ok(Error::NotInitialized))
    );

    // Therefore the transfer's FIRST storage read (sender commitment) returns NoBalance.
    let mut ps = Vec::new(&env);
    for s in ["1", "2", "3", "4"] {
        ps.push_back(fr_from_decimal(&env, s));
    }
    let res = client.try_confidential_transfer(&alice, &bob, &dummy_proof(&env), &ps, &zero_ephemeral(&env), &empty_note(&env));
    assert_eq!(res, Err(Ok(Error::NoBalance)));
}

// DOUBLE-WITHDRAW. A successful withdraw burns the commitment; a second withdraw with
// the SAME real proof finds nothing to burn (NoBalance) and — crucially — moves NO
// additional tokens (no double-payout). A third attempt is equally inert (idempotent
// rejection). Sibling to withdraw_pays_out_and_burns_commitment's single replay, here
// asserting the rejection is also FINANCIALLY inert across repeated attempts.
#[test]
fn double_withdraw_rejected_and_financially_inert() {
    let (env, id, token, _admin, alice) = setup();
    let client = ZkConfidentialTransferClient::new(&env, &id);
    let token_client = token::Client::new(&env, &token);

    let public = build_withdraw_public(&env);
    let c = public.get(0).unwrap().to_bytes();
    client.deposit(&alice, &WITHDRAW_AMOUNT, &c);

    // First withdraw: real proof pays out + burns.
    client.withdraw(&alice, &WITHDRAW_AMOUNT, &build_withdraw_proof(&env), &public);
    assert_eq!(token_client.balance(&id), 0, "pool paid out");
    assert_eq!(token_client.balance(&alice), 1_000_000_000, "alice made whole");
    assert_eq!(client.has_balance(&alice), false, "commitment burned");

    // Second withdraw (double-spend): commitment gone -> NoBalance, no second payout.
    assert_eq!(
        client.try_withdraw(&alice, &WITHDRAW_AMOUNT, &build_withdraw_proof(&env), &public),
        Err(Ok(Error::NoBalance))
    );
    assert_eq!(token_client.balance(&id), 0, "double-withdraw moved NO additional tokens");
    assert_eq!(token_client.balance(&alice), 1_000_000_000, "alice not double-paid");

    // Third attempt: still inert.
    assert_eq!(
        client.try_withdraw(&alice, &WITHDRAW_AMOUNT, &build_withdraw_proof(&env), &public),
        Err(Ok(Error::NoBalance))
    );
    assert_eq!(token_client.balance(&id), 0, "triple-withdraw still inert");
}
