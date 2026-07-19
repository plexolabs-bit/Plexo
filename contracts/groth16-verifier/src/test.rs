// StellarHub ZK reference · https://stellarhub.io
#![cfg(test)]
extern crate std;

use ark_bls12_381::{Fq, Fq2, Fr as ArkFr};
use ark_serialize::CanonicalSerialize;
use core::str::FromStr;
use serde_json::Value;
use soroban_sdk::{
    crypto::bls12_381::{Fr, G1Affine, G2Affine, G1_SERIALIZED_SIZE, G2_SERIALIZED_SIZE},
    Bytes, Env, Vec, U256,
};
use std::fs;

use crate::{Groth16Error, Groth16Verifier, Groth16VerifierClient, Proof, VerificationKey};

// --- snarkjs JSON (decimal-string coords) -> Soroban BLS12-381 types ----------
// g1/g2 conversions are the upstream soroban-examples logic; fr_from_decimal is
// added so big (255-bit) public signals (our Poseidon commitment + nullifier)
// load correctly, where the upstream example only handled a small u32 output.

fn g1_from_coords(env: &Env, x: &str, y: &str) -> G1Affine {
    let ark_g1 = ark_bls12_381::G1Affine::new(Fq::from_str(x).unwrap(), Fq::from_str(y).unwrap());
    let mut buf = [0u8; G1_SERIALIZED_SIZE];
    ark_g1.serialize_uncompressed(&mut buf[..]).unwrap();
    G1Affine::from_array(env, &buf)
}

fn g2_from_coords(env: &Env, x1: &str, x2: &str, y1: &str, y2: &str) -> G2Affine {
    let x = Fq2::new(Fq::from_str(x1).unwrap(), Fq::from_str(x2).unwrap());
    let y = Fq2::new(Fq::from_str(y1).unwrap(), Fq::from_str(y2).unwrap());
    let ark_g2 = ark_bls12_381::G2Affine::new(x, y);
    let mut buf = [0u8; G2_SERIALIZED_SIZE];
    ark_g2.serialize_uncompressed(&mut buf[..]).unwrap();
    G2Affine::from_array(env, &buf)
}

fn fr_from_decimal(env: &Env, s: &str) -> Fr {
    // ark Fr serialises 32 bytes little-endian; Soroban U256 wants big-endian.
    let n = ArkFr::from_str(s).unwrap();
    let mut le = [0u8; 32];
    n.serialize_uncompressed(&mut le[..]).unwrap();
    le.reverse();
    Fr::from_u256(U256::from_be_bytes(env, &Bytes::from_array(env, &le)))
}

fn data_path(file: &str) -> std::string::String {
    std::format!("{}/data/{}", env!("CARGO_MANIFEST_DIR"), file)
}

fn load(file: &str) -> Value {
    serde_json::from_str(&fs::read_to_string(data_path(file)).unwrap()).unwrap()
}

fn cs(v: &Value) -> &str {
    v.as_str().unwrap()
}

fn g1(env: &Env, p: &Value) -> G1Affine {
    g1_from_coords(env, cs(&p[0]), cs(&p[1]))
}

fn g2(env: &Env, p: &Value) -> G2Affine {
    // snarkjs G2 = [[x.c0, x.c1], [y.c0, y.c1], [..]]
    g2_from_coords(env, cs(&p[0][0]), cs(&p[0][1]), cs(&p[1][0]), cs(&p[1][1]))
}

fn build_vk(env: &Env) -> VerificationKey {
    let v = load("verification_key.json");
    let ic_json = v["IC"].as_array().unwrap();
    let mut ic = Vec::new(env);
    for point in ic_json {
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

fn create_client(e: &Env) -> Groth16VerifierClient<'_> {
    Groth16VerifierClient::new(e, &e.register(Groth16Verifier {}, ()))
}

#[test]
fn verifies_our_private_transfer_proof() {
    let env = Env::default();
    let client = create_client(&env);

    let vk = build_vk(&env);
    let proof = build_proof(&env);
    let public = build_public(&env);

    // public.json carries 2 signals (commitment, nullifier) -> IC must have 3 points.
    assert_eq!(public.len(), 2);
    assert_eq!(vk.ic.len(), 3);

    // Valid proof verifies on-chain (real BLS12-381 host functions).
    let ok = client.verify_proof(&vk, &proof, &public);
    assert_eq!(ok, true, "valid Groth16 proof must verify");
}

// Writes the CLI invoke arguments (hex-encoded G1/G2 + decimal pub signals) to
// /tmp so a real testnet `stellar contract invoke` can consume them via
// --vk-file-path / --proof-file-path / --pub_signals-file-path. Run with:
//   cargo test dump_invoke_args --target aarch64-apple-darwin -- --nocapture
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

    fs::write("/tmp/inv_vk.json", &vk_json).unwrap();
    fs::write("/tmp/inv_proof.json", &proof_json).unwrap();
    fs::write("/tmp/inv_pub.json", &pub_json).unwrap();
    std::println!("WROTE /tmp/inv_vk.json /tmp/inv_proof.json /tmp/inv_pub.json");
}

#[test]
fn rejects_tampered_public_signal() {
    let env = Env::default();
    let client = create_client(&env);

    let vk = build_vk(&env);
    let proof = build_proof(&env);

    // Flip the commitment public signal -> proof must be rejected.
    let mut tampered = Vec::new(&env);
    tampered.push_back(fr_from_decimal(&env, "1"));
    tampered.push_back(build_public(&env).get(1).unwrap());

    let ok = client.verify_proof(&vk, &proof, &tampered);
    assert_eq!(ok, false, "tampered public signal must be rejected");
}

#[test]
fn rejects_malformed_pub_signals_length() {
    // The VK's IC has 3 points, so a well-formed call needs exactly 2 public
    // signals (pub_signals.len() + 1 == ic.len()). Any other length must short
    // -circuit to MalformedVerifyingKey BEFORE any BLS pairing work (lib.rs:48).
    let env = Env::default();
    let client = create_client(&env);
    let vk = build_vk(&env);
    let proof = build_proof(&env);

    // Too few: 1 signal.
    let mut one = Vec::new(&env);
    one.push_back(fr_from_decimal(&env, "1"));
    assert_eq!(
        client.try_verify_proof(&vk, &proof, &one),
        Err(Ok(Groth16Error::MalformedVerifyingKey)),
        "1 public signal against a 3-point IC must be rejected as malformed",
    );

    // Too many: the valid 2 signals plus 1 extra.
    let mut three = build_public(&env);
    three.push_back(fr_from_decimal(&env, "1"));
    assert_eq!(
        client.try_verify_proof(&vk, &proof, &three),
        Err(Ok(Groth16Error::MalformedVerifyingKey)),
        "3 public signals against a 3-point IC must be rejected as malformed",
    );
}

#[test]
fn accepts_empty_signals_single_ic_then_fails_pairing() {
    // Boundary: a length-CONSISTENT VK whose IC has a single point. With zero
    // public signals, pub_signals.len() + 1 == 1 == ic.len(), so the length guard
    // (lib.rs:48) PASSES, the Σ-loop runs zero iterations, and vk_x is just ic[0].
    // Verification reaches the real BLS pairing, which returns Ok(false) for this
    // truncated/mismatched VK — NOT Err(MalformedVerifyingKey).
    let env = Env::default();
    let client = create_client(&env);
    let full = build_vk(&env);
    let proof = build_proof(&env);

    let mut single_ic = Vec::new(&env);
    single_ic.push_back(full.ic.get(0).unwrap());
    let vk = VerificationKey {
        alpha: full.alpha,
        beta: full.beta,
        gamma: full.gamma,
        delta: full.delta,
        ic: single_ic,
    };
    assert_eq!(vk.ic.len(), 1);

    let empty: Vec<Fr> = Vec::new(&env);
    assert_eq!(empty.len(), 0);

    // bool IS PartialEq, so the whole try_ result compares cleanly against Ok(Ok(false)).
    assert_eq!(
        client.try_verify_proof(&vk, &proof, &empty),
        Ok(Ok(false)),
        "0 signals + single-point IC pass the length guard and fail the pairing as Ok(false)",
    );
}
