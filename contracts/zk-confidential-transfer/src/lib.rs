#![no_std]
use soroban_sdk::{
    contract, contracterror, contractimpl, contracttype,
    crypto::bls12_381::{Fr, G1Affine, G2Affine},
    symbol_short, token, vec, Address, Bytes, BytesN, Env, Vec, U256,
};

/// C0 = Poseidon(0,0) over BLS12-381 — the canonical "empty confidential balance"
/// commitment (matches the client `commit({amount:'0',blinding:'0'})`). An ABSENT
/// recipient defaults to this so a sender can credit a not-yet-registered recipient in
/// ONE signed tx (the C0 fold-in): the compare-and-swap then forces the prover to
/// have opened `c_recipient_old == C0` (a genuine zero balance — Poseidon is binding),
/// and the `.set()` creates the slot. C0 is a FIXED constant; any caller-supplied value
/// is ignored, which removes the "pre-register B with an unopenable commitment" brick.
const C0: [u8; 32] = [
    0x6c, 0x2b, 0xac, 0x92, 0xf1, 0xff, 0xd5, 0x3e, 0xa9, 0xc3, 0x16, 0x64, 0x80, 0xd2, 0x21, 0xf6,
    0xd8, 0xb7, 0x16, 0xce, 0x67, 0xba, 0x22, 0xb7, 0x51, 0x78, 0x1c, 0xbd, 0x30, 0x5b, 0xfc, 0x7b,
];

// EXPERIMENTAL testnet PoC — confidential-AMOUNT transfer on Soroban.
//
// HONEST SCOPE (read before believing anything): the ONLY truthful privacy claim
// is that the transfer AMOUNT lives on-chain solely as a Poseidon balance
// commitment — never a tx argument, never an event field. A Groth16/BLS12-381
// proof enforces value conservation in zero-knowledge. NOTHING ELSE is hidden:
//   * sender and recipient identities ARE visible (this op names both accounts);
//   * the boundary deposit()/withdraw() that move real tokens expose their
//     amounts in the clear (separate ops);
//   * in a small pool a global observer can often infer amounts by differencing;
//   * dev trusted setup is single-participant (NOT an MPC ceremony);
//   * UNAUDITED, testnet only, NOT production / NOT mainnet-ready.
// This is NOT a "private payment", NOT "anonymous", NOT a confidential-balances
// product, and amounts are NOT "impossible to recover".
//
// WHY conservation is proven INSIDE the circuit: Poseidon is NOT additively
// homomorphic, so the contract CANNOT subtract commitments on-chain. The circuit
// opens all four balance commitments and proves, over the scalar field,
//   amount_sender_old    == amount_sender_new    + t   (sender debited by t)
//   amount_recipient_new == amount_recipient_old + t   (recipient credited by t)
// for the SAME t; adding the two cancels t and yields
// (sender_new + recipient_new) == (sender_old + recipient_old). This op performs
// NO token::transfer — it only swaps the two commitments atomically — so the
// amount t never appears in any event.

#[contracterror]
#[derive(Copy, Clone, Debug, Eq, PartialEq, PartialOrd, Ord)]
#[repr(u32)]
pub enum Error {
    NotInitialized = 1,
    AlreadyInitialized = 2,
    MalformedVerifyingKey = 3,
    ProofInvalid = 4,
    BadPublicSignals = 5,
    /// A public-signal `*_old` does not byte-match the account's stored
    /// commitment. This is the replay / double-spend guard: a consumed `*_old`
    /// can never match again once the compare-and-swap advances it to `*_new`.
    CommitmentMismatch = 6,
    /// deposit() into an account that already has a confidential commitment.
    BalanceExists = 7,
    /// transfer/withdraw against an account that never registered a commitment.
    NoBalance = 8,
    /// withdraw(): the real token `amount` being moved out does NOT equal the
    /// amount the proof opens the burned commitment to (pub_signals[1]). This is
    /// the open-to-amount money-path guard — a commitment to X can never be cashed
    /// out for Y != X.
    AmountMismatch = 9,
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
    Admin,
    Token,
    /// confidential_transfer Groth16 verifying key (4 public signals).
    Vk,
    /// confidential_withdraw Groth16 verifying key (2 public signals:
    /// [commitment, amount]). Separate circuit ⇒ separate VK, injected at
    /// initialize() exactly like `Vk`.
    WithdrawVk,
    /// Per-account confidential balance commitment = Poseidon(amount, blinding),
    /// computed client-side (the amount + blinding NEVER leave the owner). ABSENT
    /// ⇒ the account has no confidential balance.
    Balance(Address),
}

// The confidential_transfer circuit declares exactly 4 public signals:
//   [commitment_sender_old, commitment_sender_new,
//    commitment_recipient_old, commitment_recipient_new]
// (see circuits/confidential_transfer.circom, nPublic = 4).
const PUBLIC_SIGNALS: u32 = 4;

// The confidential_withdraw circuit declares exactly 2 public signals:
//   [commitment, amount]
// (see circuits/confidential_withdraw.circom, nPublic = 2).
const PUBLIC_SIGNALS_WITHDRAW: u32 = 2;

#[contract]
pub struct ZkConfidentialTransfer;

#[contractimpl]
impl ZkConfidentialTransfer {
    /// One-time setup: the admin key, the SAC token the pool holds, and
    /// the TWO Groth16 verifying keys — `vk` for the confidential_transfer circuit
    /// (4 public signals) and `withdraw_vk` for the confidential_withdraw circuit
    /// (2 public signals, the trustless open-to-amount proof).
    ///
    /// DEV VKs: both keys injected here are single-participant DEV verifying keys
    /// built alongside their circuits (data/verification_key.json +
    /// data/withdraw_verification_key.json). A production deployment re-runs the
    /// setup as a proper MPC ceremony and injects THOSE keys instead — do NOT treat
    /// the current VKs as ceremony-final. They are injected (not baked byte
    /// constants) to copy the proven zk-verified-payment layout verbatim.
    pub fn initialize(
        env: Env,
        admin: Address,
        token: Address,
        vk: VerificationKey,
        withdraw_vk: VerificationKey,
    ) -> Result<(), Error> {
        if env.storage().instance().has(&DataKey::Vk) {
            return Err(Error::AlreadyInitialized);
        }
        admin.require_auth();
        env.storage().instance().set(&DataKey::Admin, &admin);
        env.storage().instance().set(&DataKey::Token, &token);
        env.storage().instance().set(&DataKey::Vk, &vk);
        env.storage().instance().set(&DataKey::WithdrawVk, &withdraw_vk);
        Ok(())
    }

    /// BOUNDARY (amount visible). Move `amount` of the real token INTO the pool and
    /// register the account's INITIAL confidential commitment (= Poseidon(amount,
    /// blinding), computed client-side). To register a fresh recipient before they
    /// receive, deposit with `amount = 0` and a commitment to a zero balance.
    ///
    /// First deposit only: topping up an existing confidential balance would need a
    /// conservation proof (Poseidon is not homomorphic, so the contract cannot add
    /// the new deposit to the stored commitment) — that is a documented follow-on.
    pub fn deposit(
        env: Env,
        from: Address,
        amount: i128,
        commitment: BytesN<32>,
    ) -> Result<(), Error> {
        from.require_auth();
        if env.storage().persistent().has(&DataKey::Balance(from.clone())) {
            return Err(Error::BalanceExists);
        }
        let token: Address = env
            .storage()
            .instance()
            .get(&DataKey::Token)
            .ok_or(Error::NotInitialized)?;
        let pool = env.current_contract_address();
        token::Client::new(&env, &token).transfer(&from, &pool, &amount);

        env.storage()
            .persistent()
            .set(&DataKey::Balance(from.clone()), &commitment);
        env.events()
            .publish((symbol_short!("deposit"), from), (commitment, amount));
        Ok(())
    }

    /// Confidential transfer — the amount-hiding op. Verifies the Groth16 proof of
    /// value conservation, byte-checks that the proof's `*_old` commitments equal
    /// the accounts' CURRENT stored commitments, then ATOMICALLY swaps both to the
    /// `*_new` commitments. Performs NO token::transfer (value stays pooled) and
    /// emits an event WITHOUT the amount.
    ///
    /// `pub_signals = [commitment_sender_old, commitment_sender_new,
    ///                 commitment_recipient_old, commitment_recipient_new]`.
    ///
    /// REPLAY / DOUBLE-SPEND GUARD: the per-account commitment is the account's
    /// sequence state; this function is a compare-and-swap (require stored ==
    /// `*_old`, then set `*_new`). A replayed proof references a stale `*_old`
    /// that no longer matches the advanced commitment ⇒ CommitmentMismatch. A
    /// separate global nullifier set is therefore unnecessary here: the spender's
    /// identity is public and their old commitment can never become acceptable again.
    pub fn confidential_transfer(
        env: Env,
        sender: Address,
        recipient: Address,
        proof: Proof,
        pub_signals: Vec<Fr>,
        // Sealed-note delivery — OPAQUE to the contract (not validated, not part of the
        // proof). Echoed into the conf_xfer event so the recipient can ECDH-open the amount
        // and re-derive their new-commitment blinding (classic ephemeral-key echo pattern).
        ephemeral_pubkey: BytesN<32>,
        note: Bytes,
    ) -> Result<(), Error> {
        // Only the debited account authorises the swap of its own balance.
        sender.require_auth();

        if pub_signals.len() != PUBLIC_SIGNALS {
            return Err(Error::BadPublicSignals);
        }
        let c_sender_old = pub_signals.get(0).unwrap().to_bytes();
        let c_sender_new = pub_signals.get(1).unwrap().to_bytes();
        let c_recipient_old = pub_signals.get(2).unwrap().to_bytes();
        let c_recipient_new = pub_signals.get(3).unwrap().to_bytes();

        // Compare-and-swap precondition (cheap byte work BEFORE the pairing): the
        // proof must transition the accounts' CURRENT on-chain commitments.
        let sender_key = DataKey::Balance(sender.clone());
        let stored_sender: BytesN<32> = env
            .storage()
            .persistent()
            .get(&sender_key)
            .ok_or(Error::NoBalance)?;
        if stored_sender != c_sender_old {
            return Err(Error::CommitmentMismatch);
        }
        let recipient_key = DataKey::Balance(recipient.clone());
        // C0 fold-in: an ABSENT recipient defaults to C0 = Poseidon(0,0) (NOT NoBalance), so
        // the sender credits a not-yet-registered recipient here. The CAS forces the prover
        // to have supplied c_recipient_old == C0; the set() below creates the slot.
        let stored_recipient: BytesN<32> = env
            .storage()
            .persistent()
            .get(&recipient_key)
            .unwrap_or_else(|| BytesN::from_array(&env, &C0));
        if stored_recipient != c_recipient_old {
            return Err(Error::CommitmentMismatch);
        }

        let vk: VerificationKey = env
            .storage()
            .instance()
            .get(&DataKey::Vk)
            .ok_or(Error::NotInitialized)?;
        if !verify_groth16(&env, &vk, &proof, &pub_signals)? {
            return Err(Error::ProofInvalid);
        }

        // Atomic 2-commitment swap. No token::transfer — the amount stays pooled
        // and never appears in any event (the new commitments hide it).
        env.storage().persistent().set(&sender_key, &c_sender_new);
        env.storage()
            .persistent()
            .set(&recipient_key, &c_recipient_new);
        env.events().publish(
            (symbol_short!("conf_xfer"), sender, recipient),
            (c_sender_new, c_recipient_new, ephemeral_pubkey, note),
        );
        Ok(())
    }

    /// BOUNDARY (amount visible) — TRUSTLESS exit. Burn the caller's commitment and
    /// move `amount` of the real token OUT to `to`, but ONLY after a Groth16 proof
    /// shows the burned commitment opens to EXACTLY `amount`.
    ///
    /// `pub_signals = [commitment, amount]` (the confidential_withdraw circuit's 2
    /// public signals): the prover knows the secret `blinding` s.t.
    /// commitment == Poseidon(amount, blinding), and `amount` is range-bound to
    /// [0, 2^64) inside the circuit. The contract pins both ends:
    ///   * pub_signals[0] MUST byte-match the account's CURRENT stored commitment
    ///     (the commitment being burned), and
    ///   * pub_signals[1] MUST equal the real i128 `amount` being transferred out.
    /// Verifying the proof against the embedded `WithdrawVk` then cryptographically
    /// binds the visible boundary amount to the destroyed commitment.
    ///
    /// This REPLACES the v1 operator-attested trust note: there is no longer any
    /// off-chain attestation that the commitment opens to `amount` — the proof
    /// proves it. Poseidon is still not a Soroban host function, so the opening is
    /// proven IN ZERO-KNOWLEDGE in the circuit, not recomputed on-chain. A prover
    /// cannot burn a commitment-to-X and cash out Y != X: the i128/pub_signals[1]
    /// bind rejects a lied amount (AmountMismatch), and re-opening the commitment to
    /// a different amount is a Poseidon second-preimage (the proof would not verify).
    /// `amount` is VISIBLE here by construction (a real token move).
    ///
    /// REPLAY GUARD: the commitment is the account's spend state. A successful
    /// withdraw removes it, so replaying the same proof finds no stored commitment
    /// (NoBalance) — same compare-and-swap discipline as confidential_transfer.
    pub fn withdraw(
        env: Env,
        to: Address,
        amount: i128,
        proof: Proof,
        pub_signals: Vec<Fr>,
    ) -> Result<(), Error> {
        to.require_auth();

        if pub_signals.len() != PUBLIC_SIGNALS_WITHDRAW {
            return Err(Error::BadPublicSignals);
        }
        let c_burn = pub_signals.get(0).unwrap().to_bytes();
        let proven_amount = pub_signals.get(1).unwrap().to_bytes();

        // Compare-and-swap precondition + replay guard (cheap byte work BEFORE the
        // pairing): the proof must burn the account's CURRENT on-chain commitment.
        let key = DataKey::Balance(to.clone());
        let stored: BytesN<32> = env
            .storage()
            .persistent()
            .get(&key)
            .ok_or(Error::NoBalance)?;
        if stored != c_burn {
            return Err(Error::CommitmentMismatch);
        }

        // Open-to-amount bind: the real token amount moved out MUST equal the field
        // element the proof opens the commitment to. A withdraw cannot move negative
        // value; a valid proof's amount is in [0, 2^64) so a negative request can
        // never match.
        if amount < 0 {
            return Err(Error::AmountMismatch);
        }
        let amount_fr = Fr::from_u256(U256::from_u128(&env, amount as u128)).to_bytes();
        if proven_amount != amount_fr {
            return Err(Error::AmountMismatch);
        }

        // Verify the open-to-amount Groth16 proof against the embedded withdraw VK.
        let vk: VerificationKey = env
            .storage()
            .instance()
            .get(&DataKey::WithdrawVk)
            .ok_or(Error::NotInitialized)?;
        if !verify_groth16(&env, &vk, &proof, &pub_signals)? {
            return Err(Error::ProofInvalid);
        }

        // Burn the commitment FIRST (no re-entrancy window), then move real tokens out.
        env.storage().persistent().remove(&key);
        let token: Address = env
            .storage()
            .instance()
            .get(&DataKey::Token)
            .ok_or(Error::NotInitialized)?;
        let pool = env.current_contract_address();
        token::Client::new(&env, &token).transfer(&pool, &to, &amount);
        env.events()
            .publish((symbol_short!("withdraw"), to), amount);
        Ok(())
    }

    pub fn get_commitment(env: Env, account: Address) -> Option<BytesN<32>> {
        env.storage().persistent().get(&DataKey::Balance(account))
    }

    pub fn has_balance(env: Env, account: Address) -> bool {
        env.storage().persistent().has(&DataKey::Balance(account))
    }

    pub fn get_token(env: Env) -> Option<Address> {
        env.storage().instance().get(&DataKey::Token)
    }
}

/// Groth16 verify over BLS12-381 host functions — identical math to the sibling
/// contracts/groth16-verifier (forked from soroban-examples/groth16_verifier).
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
