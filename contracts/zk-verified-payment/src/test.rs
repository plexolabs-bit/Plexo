// StellarHub ZK reference · https://stellarhub.io
#![cfg(test)]
extern crate std;

use ark_bls12_381::{Fq, Fq2, Fr as ArkFr};
use ark_serialize::CanonicalSerialize;
use core::str::FromStr;
use serde_json::Value;
use soroban_sdk::{
    crypto::bls12_381::{Fr, G1Affine, G2Affine, G1_SERIALIZED_SIZE, G2_SERIALIZED_SIZE},
    testutils::Address as _,
    token, Bytes, BytesN, Env, Vec, U256,
};
use std::fs;

use crate::{Error, Proof, VerificationKey, ZkVerifiedPayment, ZkVerifiedPaymentClient};

// --- snarkjs JSON (decimal coords) -> Soroban BLS12-381 types (shared with the
//     standalone verifier crate's test harness). ---

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

fn build_vk(env: &Env) -> VerificationKey {
    let v = load("verification_key.json");
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
fn build_proof(env: &Env) -> Proof {
    let p = load("proof.json");
    Proof {
        a: g1(env, &p["pi_a"]),
        b: g2(env, &p["pi_b"]),
        c: g1(env, &p["pi_c"]),
    }
}
fn build_public(env: &Env) -> Vec<Fr> {
    let p = load("public.json");
    let mut out = Vec::new(env);
    for sig in p.as_array().unwrap() {
        out.push_back(fr_from_decimal(env, cs(sig)));
    }
    out
}

// Returns (env, contract_id, token_address, alice, bob); alice pre-funded.
// Clients are built inside each test to avoid a self-referential struct.
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

    let contract_id = env.register(ZkVerifiedPayment, ());
    let client = ZkVerifiedPaymentClient::new(&env, &contract_id);
    client.initialize(&token, &build_vk(&env));

    let alice = soroban_sdk::Address::generate(&env);
    let bob = soroban_sdk::Address::generate(&env);
    token::StellarAssetClient::new(&env, &token).mint(&alice, &1_000_000_000);

    (env, contract_id, token, alice, bob)
}

#[test]
fn verified_payment_transfers_on_valid_proof() {
    let (env, contract_id, token, alice, bob) = setup();
    let client = ZkVerifiedPaymentClient::new(&env, &contract_id);
    let proof = build_proof(&env);
    let public = build_public(&env);

    let token_client = token::Client::new(&env, &token);
    assert_eq!(token_client.balance(&bob), 0);

    client.pay_verified(&alice, &bob, &100, &proof, &public);

    assert_eq!(token_client.balance(&bob), 100, "recipient received funds");
    assert_eq!(token_client.balance(&alice), 1_000_000_000 - 100);

    let nullifier = public.get(1).unwrap().to_bytes();
    assert!(client.is_nullifier_used(&nullifier));
}

#[test]
fn rejects_tampered_proof() {
    let (env, contract_id, token, alice, bob) = setup();
    let client = ZkVerifiedPaymentClient::new(&env, &contract_id);
    let proof = build_proof(&env);

    let mut tampered = Vec::new(&env);
    tampered.push_back(fr_from_decimal(&env, "1"));
    tampered.push_back(build_public(&env).get(1).unwrap());

    let res = client.try_pay_verified(&alice, &bob, &100, &proof, &tampered);
    assert_eq!(res, Err(Ok(Error::ProofInvalid)));

    let token_client = token::Client::new(&env, &token);
    assert_eq!(token_client.balance(&bob), 0);
}

#[test]
fn rejects_replayed_nullifier() {
    let (env, contract_id, token, alice, bob) = setup();
    let client = ZkVerifiedPaymentClient::new(&env, &contract_id);
    let proof = build_proof(&env);
    let public = build_public(&env);

    client.pay_verified(&alice, &bob, &100, &proof, &public);

    let res = client.try_pay_verified(&alice, &bob, &100, &proof, &public);
    assert_eq!(res, Err(Ok(Error::NullifierUsed)));

    let token_client = token::Client::new(&env, &token);
    assert_eq!(token_client.balance(&bob), 100);
}

#[test]
fn rejects_wrong_pub_signals_arity() {
    let (env, contract_id, token, alice, bob) = setup();
    let client = ZkVerifiedPaymentClient::new(&env, &contract_id);
    let proof = build_proof(&env);

    // pub_signals must be exactly [commitment, nullifier] (len 2). A 1- or
    // 3-element vector is rejected with BadPublicSignals BEFORE the nullifier is
    // read or any funds move (lib.rs:69).
    let mut one = Vec::new(&env);
    one.push_back(fr_from_decimal(&env, "1"));
    assert_eq!(
        client.try_pay_verified(&alice, &bob, &100, &proof, &one),
        Err(Ok(Error::BadPublicSignals)),
    );

    let mut three = build_public(&env);
    three.push_back(fr_from_decimal(&env, "1"));
    assert_eq!(
        client.try_pay_verified(&alice, &bob, &100, &proof, &three),
        Err(Ok(Error::BadPublicSignals)),
    );

    let token_client = token::Client::new(&env, &token);
    assert_eq!(token_client.balance(&bob), 0, "no transfer on malformed signals");
}

#[test]
fn rejects_payment_before_initialize() {
    // A registered-but-uninitialized contract has no stored VK. With well-formed
    // (len 2) signals + a fresh nullifier, the flow reaches the VK load, which
    // ok_or's NotInitialized (lib.rs:82) — no panic, no transfer.
    let env = Env::default();
    env.mock_all_auths();
    let contract_id = env.register(ZkVerifiedPayment, ());
    let client = ZkVerifiedPaymentClient::new(&env, &contract_id);

    let alice = soroban_sdk::Address::generate(&env);
    let bob = soroban_sdk::Address::generate(&env);
    let proof = build_proof(&env);
    let public = build_public(&env); // len 2

    assert_eq!(
        client.try_pay_verified(&alice, &bob, &100, &proof, &public),
        Err(Ok(Error::NotInitialized)),
    );
}

#[test]
fn read_only_accessors_initial_state() {
    // Uninitialized: get_token returns None.
    let env = Env::default();
    let contract_id = env.register(ZkVerifiedPayment, ());
    let bare = ZkVerifiedPaymentClient::new(&env, &contract_id);
    assert_eq!(bare.get_token(), None);

    // Initialized: token present, an arbitrary nullifier is unspent.
    let (env2, contract_id2, token, _alice, _bob) = setup();
    let client = ZkVerifiedPaymentClient::new(&env2, &contract_id2);
    assert_eq!(client.get_token(), Some(token));
    let never = BytesN::from_array(&env2, &[7u8; 32]);
    assert_eq!(client.is_nullifier_used(&never), false);
}
