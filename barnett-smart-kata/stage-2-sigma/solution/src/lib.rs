//! Stage 2 — Non-interactive sigma proofs (Fiat–Shamir). **Reference solution.**

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
    pub fn prove(w: Fr, point: Projective, rng: &mut impl RngCore) -> Self {
        let g = generator();
        let k = Fr::rand(rng);
        let r = g * k;
        let mut t = Transcript::new(b"pkmental/schnorr");
        t.absorb(&g);
        t.absorb(&point);
        t.absorb(&r);
        let e = t.challenge();
        let s = k + e * w;
        Self { r, s }
    }

    /// Verify the proof against the claimed `point = w·G`.
    #[must_use]
    pub fn verify(&self, point: Projective) -> bool {
        let g = generator();
        let mut t = Transcript::new(b"pkmental/schnorr");
        t.absorb(&g);
        t.absorb(&point);
        t.absorb(&self.r);
        let e = t.challenge();
        g * self.s == self.r + point * e
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
    pub fn prove(
        w: Fr,
        g1: Projective,
        p1: Projective,
        g2: Projective,
        p2: Projective,
        rng: &mut impl RngCore,
    ) -> Self {
        let k = Fr::rand(rng);
        let r1 = g1 * k;
        let r2 = g2 * k;
        let e = Self::challenge(g1, p1, g2, p2, r1, r2);
        let s = k + e * w;
        Self { r1, r2, s }
    }

    /// Verify the equality-of-discrete-logs proof.
    #[must_use]
    pub fn verify(&self, g1: Projective, p1: Projective, g2: Projective, p2: Projective) -> bool {
        let e = Self::challenge(g1, p1, g2, p2, self.r1, self.r2);
        g1 * self.s == self.r1 + p1 * e && g2 * self.s == self.r2 + p2 * e
    }

    fn challenge(
        g1: Projective,
        p1: Projective,
        g2: Projective,
        p2: Projective,
        r1: Projective,
        r2: Projective,
    ) -> Fr {
        let mut t = Transcript::new(b"pkmental/dleq");
        for p in [&g1, &p1, &g2, &p2, &r1, &r2] {
            t.absorb(p);
        }
        t.challenge()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rng() -> impl RngCore {
        ark_std::test_rng()
    }

    #[test]
    fn schnorr_valid_proof_verifies() {
        let mut r = rng();
        let w = Fr::rand(&mut r);
        let p = generator() * w;
        let proof = SchnorrProof::prove(w, p, &mut r);
        assert!(proof.verify(p));
    }

    #[test]
    fn schnorr_wrong_point_fails() {
        let mut r = rng();
        let w = Fr::rand(&mut r);
        let p = generator() * w;
        let proof = SchnorrProof::prove(w, p, &mut r);
        let other = generator() * Fr::rand(&mut r);
        assert!(!proof.verify(other));
    }

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
