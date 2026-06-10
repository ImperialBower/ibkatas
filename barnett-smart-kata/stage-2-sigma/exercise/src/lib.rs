//! Stage 2 — Non-interactive sigma proofs (Fiat–Shamir).
//!
//! Two building blocks, both over the Pallas group with the standard generator
//! `G`:
//!
//! - [`SchnorrProof`] — proof of knowledge of a discrete log `w` such that
//!   `P = w·G`. Proves a player knows the secret behind a published key share
//!   (stops rogue-key attacks) without revealing the secret.
//! - [`DleqProof`] — Chaum–Pedersen proof that two points share a discrete log:
//!   `P1 = w·G1` and `P2 = w·G2` for the *same* `w`. Used later for reveal
//!   tokens and re-mask randomness.
//!
//! The [`Transcript`] (Fiat–Shamir) machinery is **provided**. Your job is the
//! prover and verifier for both proofs. Implement every `todo!()`, run
//! `cargo test`.

// The stubs below leave parameters and the provided helpers unused until you
// implement them. This keeps `cargo test` output focused on the failing tests;
// delete it once everything is wired up.
#![allow(unused_variables, unused_imports, dead_code)]

use ark_ec::PrimeGroup;
use ark_ff::PrimeField;
use ark_pallas::{Fr, Projective};
use ark_serialize::CanonicalSerialize;
use ark_std::UniformRand;
use rand::RngCore;
use sha2::{Digest, Sha512};

/// The fixed Pallas generator `G`.
pub fn generator() -> Projective {
    Projective::generator()
}

/// Absorb points into a Fiat–Shamir transcript and squeeze a scalar challenge.
///
/// Provided for you. This is the heart of the **Fiat–Shamir transform**: instead
/// of a live verifier sending a random challenge, the prover derives it by
/// hashing the statement and its own commitments. `absorb` feeds a point in;
/// `challenge` finalizes the hash into a field element.
struct Transcript(Sha512);

impl Transcript {
    fn new(label: &[u8]) -> Self {
        let mut h = Sha512::new();
        h.update(label);
        Self(h)
    }

    fn absorb(&mut self, p: &Projective) {
        let mut bytes = Vec::new();
        p.serialize_compressed(&mut bytes)
            .expect("Pallas point serialization is infallible");
        self.0.update(&bytes);
    }

    fn challenge(self) -> Fr {
        Fr::from_le_bytes_mod_order(&self.0.finalize())
    }
}

/// A Schnorr proof of knowledge of `w` with `P = w·G`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SchnorrProof {
    r: Projective,
    s: Fr,
}

impl SchnorrProof {
    /// Prove knowledge of `w` such that `point = w·G`.
    ///
    /// TODO(you): the Schnorr protocol, made non-interactive.
    /// 1. Pick a random nonce `k` (`Fr::rand(rng)`) and commit `r = k·G`.
    /// 2. Derive the challenge `e` by absorbing `G`, `point`, and `r` into a
    ///    `Transcript::new(b"pkmental/schnorr")`, then `challenge()`.
    /// 3. Respond with `s = k + e·w`. Return `Self { r, s }`.
    pub fn prove(w: Fr, point: Projective, rng: &mut impl RngCore) -> Self {
        todo!("Schnorr prover: commit k·G, challenge, respond k + e·w")
    }

    /// Verify the proof against the claimed `point = w·G`.
    ///
    /// TODO(you): recompute the same challenge `e` (absorb `G`, `point`, and
    /// `self.r`), then check the verification equation `s·G == r + e·point`.
    #[must_use]
    pub fn verify(&self, point: Projective) -> bool {
        todo!("Schnorr verifier: check s·G == r + e·point")
    }
}

/// A Chaum–Pedersen proof that `p1 = w·g1` and `p2 = w·g2` for one `w`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DleqProof {
    r1: Projective,
    r2: Projective,
    s: Fr,
}

impl DleqProof {
    /// Prove `p1 = w·g1` and `p2 = w·g2` share the witness `w`.
    ///
    /// TODO(you): the same idea as Schnorr, but with *two* bases sharing one
    /// nonce `k`.
    /// 1. Pick `k`, commit `r1 = k·g1` and `r2 = k·g2`.
    /// 2. `e = Self::challenge(g1, p1, g2, p2, r1, r2)`.
    /// 3. `s = k + e·w`. Return `Self { r1, r2, s }`.
    pub fn prove(
        w: Fr,
        g1: Projective,
        p1: Projective,
        g2: Projective,
        p2: Projective,
        rng: &mut impl RngCore,
    ) -> Self {
        todo!("DLEQ prover: one nonce k, two commitments k·g1 and k·g2")
    }

    /// Verify the equality-of-discrete-logs proof.
    ///
    /// TODO(you): recompute `e` and check *both* equations:
    /// `s·g1 == r1 + e·p1` **and** `s·g2 == r2 + e·p2`.
    #[must_use]
    pub fn verify(&self, g1: Projective, p1: Projective, g2: Projective, p2: Projective) -> bool {
        todo!("DLEQ verifier: check both bases with the same s")
    }

    /// Fiat–Shamir challenge binding the full statement and both commitments.
    ///
    /// TODO(you): build a `Transcript::new(b"pkmental/dleq")`, absorb all six
    /// points in order (`g1, p1, g2, p2, r1, r2`), and return `challenge()`.
    fn challenge(
        g1: Projective,
        p1: Projective,
        g2: Projective,
        p2: Projective,
        r1: Projective,
        r2: Projective,
    ) -> Fr {
        todo!("absorb g1, p1, g2, p2, r1, r2 and squeeze a challenge")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rng() -> impl RngCore {
        ark_std::test_rng()
    }

    /// A proof built with the real witness verifies. (Completeness.)
    #[test]
    fn schnorr_valid_proof_verifies() {
        let mut r = rng();
        let w = Fr::rand(&mut r);
        let p = generator() * w;
        let proof = SchnorrProof::prove(w, p, &mut r);
        assert!(proof.verify(p));
    }

    /// A proof for one point does not verify against a different point.
    /// (Soundness / binding.)
    #[test]
    fn schnorr_wrong_point_fails() {
        let mut r = rng();
        let w = Fr::rand(&mut r);
        let p = generator() * w;
        let proof = SchnorrProof::prove(w, p, &mut r);
        let other = generator() * Fr::rand(&mut r);
        assert!(!proof.verify(other));
    }

    /// When both points genuinely share the discrete log, the DLEQ verifies.
    #[test]
    fn dleq_valid_proof_verifies() {
        let mut r = rng();
        let w = Fr::rand(&mut r);
        let g1 = generator();
        let g2 = generator() * Fr::rand(&mut r);
        let p1 = g1 * w;
        let p2 = g2 * w;
        let proof = DleqProof::prove(w, g1, p1, g2, p2, &mut r);
        assert!(proof.verify(g1, p1, g2, p2));
    }

    /// When the two logs differ, no proof can make the verifier accept.
    #[test]
    fn dleq_mismatched_logs_fail() {
        let mut r = rng();
        let g1 = generator();
        let g2 = generator() * Fr::rand(&mut r);
        let p1 = g1 * Fr::rand(&mut r);
        let p2 = g2 * Fr::rand(&mut r); // independent witness
        let proof = DleqProof::prove(Fr::rand(&mut r), g1, p1, g2, p2, &mut r);
        assert!(!proof.verify(g1, p1, g2, p2));
    }
}
