// StellarHub ZK reference · https://stellarhub.io
#![no_std]
use soroban_sdk::{
    contract, contracterror, contractimpl, contracttype,
    crypto::bls12_381::{Fr, G1Affine, G2Affine},
    token, vec, Address, BytesN, Env, Vec,
};

#[contracterror]
#[derive(Copy, Clone, Debug, Eq, PartialEq, PartialOrd, Ord)]
#[repr(u32)]
pub enum Error {
    NotInitialized = 1,
    MalformedVerifyingKey = 2,
    ProofInvalid = 3,
    NullifierUsed = 4,
    BadPublicSignals = 5,
}

#[derive(Clone)]
#[contracttype]
pub struct VerificationKey {
    pub alpha: G1Affine,
    pub beta: G2Affine,
    pub gamma: G2Affine,
    pub delta: G2Affine,
    pub ic: Vec<G1Affine>,
}

#[derive(Clone)]
#[contracttype]
pub struct Proof {
    pub a: G1Affine,
    pub b: G2Affine,
    pub c: G1Affine,
}

#[contracttype]
pub enum DataKey {
    Token,
    Vk,
    Nullifier(BytesN<32>),
}

#[contract]
pub struct ZkVerifiedPayment;

#[contractimpl]
impl ZkVerifiedPayment {
    /// One-time setup: store the SAC token to move and the Groth16 verifying key.
    pub fn initialize(env: Env, token: Address, vk: VerificationKey) {
        env.storage().instance().set(&DataKey::Token, &token);
        env.storage().instance().set(&DataKey::Vk, &vk);
    }

    /// Execute a payment ONLY if `proof` verifies against the stored VK and the
    /// proof's nullifier has not been spent. `pub_signals` are the circuit's
    /// public outputs `[commitment, nullifier]`; the nullifier (index 1) is the
    /// one-time spend marker, so a single proof can drive at most one payment.
    pub fn pay_verified(
        env: Env,
        from: Address,
        to: Address,
        amount: i128,
        proof: Proof,
        pub_signals: Vec<Fr>,
    ) -> Result<(), Error> {
        from.require_auth();

        if pub_signals.len() != 2 {
            return Err(Error::BadPublicSignals);
        }
        let nullifier = pub_signals.get(1).unwrap().to_bytes();
        let null_key = DataKey::Nullifier(nullifier);
        if env.storage().persistent().has(&null_key) {
            return Err(Error::NullifierUsed);
        }

        let vk: VerificationKey = env
            .storage()
            .instance()
            .get(&DataKey::Vk)
            .ok_or(Error::NotInitialized)?;

        if !verify_groth16(&env, &vk, &proof, &pub_signals)? {
            return Err(Error::ProofInvalid);
        }

        // Mark the nullifier spent BEFORE moving funds (no re-entrancy window).
        env.storage().persistent().set(&null_key, &true);

        let token: Address = env
            .storage()
            .instance()
            .get(&DataKey::Token)
            .ok_or(Error::NotInitialized)?;
        token::Client::new(&env, &token).transfer(&from, &to, &amount);

        Ok(())
    }

    pub fn is_nullifier_used(env: Env, nullifier: BytesN<32>) -> bool {
        env.storage()
            .persistent()
            .has(&DataKey::Nullifier(nullifier))
    }

    pub fn get_token(env: Env) -> Option<Address> {
        env.storage().instance().get(&DataKey::Token)
    }
}

/// Groth16 verify over BLS12-381 host functions — identical math to the
/// standalone groth16-verifier crate (forked from soroban-examples/groth16_verifier).
/// e(-A, B) * e(alpha, beta) * e(vk_x, gamma) * e(C, delta) == 1, where
/// vk_x = ic[0] + Σ pub_signals[i] * ic[i+1].
fn verify_groth16(
    env: &Env,
    vk: &VerificationKey,
    proof: &Proof,
    pub_signals: &Vec<Fr>,
) -> Result<bool, Error> {
    let bls = env.crypto().bls12_381();
    if pub_signals.len() + 1 != vk.ic.len() {
        return Err(Error::MalformedVerifyingKey);
    }
    let mut vk_x = vk.ic.get(0).unwrap();
    for (s, v) in pub_signals.iter().zip(vk.ic.iter().skip(1)) {
        let prod = bls.g1_mul(&v, &s);
        vk_x = bls.g1_add(&vk_x, &prod);
    }
    let neg_a = -proof.a.clone();
    let vp1 = vec![env, neg_a, vk.alpha.clone(), vk_x, proof.c.clone()];
    let vp2 = vec![
        env,
        proof.b.clone(),
        vk.beta.clone(),
        vk.gamma.clone(),
        vk.delta.clone(),
    ];
    Ok(bls.pairing_check(vp1, vp2))
}

mod test;
