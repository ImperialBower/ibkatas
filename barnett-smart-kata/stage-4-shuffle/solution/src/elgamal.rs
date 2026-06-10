//! Provided working context — the solved **stage 3** threshold-ElGamal backend.
//!
//! Supplies the `MaskedCard`/`AggregateKey` types and `ElGamalCrypto`, including
//! `remask_with` (the masking primitive the shuffle re-uses per card).

// Provided working context: the shuffle uses only part of this backend's API.
#![allow(dead_code)]

use ark_pallas::{Fr, Projective};
use ark_std::UniformRand;
use ark_std::Zero;
use rand::RngCore;

use crate::card::Card;
use crate::encode::{decode_point, encode_point};
use crate::sigma::{generator, DleqProof, SchnorrProof};

/// Errors raised by the card-crypto layer.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum MpError {
    /// `decode` was called on a card that is not yet fully unmasked.
    StillMasked,
    /// A zero-knowledge proof failed to verify.
    BadProof(&'static str),
    /// Two decks that should match differ in length.
    DeckLength { expected: usize, got: usize },
}

/// A player's secret key share `x_i`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SecretKey(pub(crate) Fr);

/// A player's public key share `h_i = x_i·G`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PublicKey(pub(crate) Projective);

/// The aggregate public key `H = ∑ h_i`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AggregateKey(pub(crate) Projective);

/// A masked card: an ElGamal ciphertext, two Pallas points.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MaskedCard {
    /// `c1 = r·G`.
    pub c1: Projective,
    /// `c2 = M + r·H`.
    pub c2: Projective,
}

/// A reveal token: one player's partial unmask `d_i` plus its DLEQ proof.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RevealToken {
    /// `d_i = x_i·c1`.
    pub d: Projective,
    proof: DleqProof,
}

/// The threshold-ElGamal mental-poker backend.
#[derive(Clone, Copy, Debug, Default)]
pub struct ElGamalCrypto;

impl ElGamalCrypto {
    #[must_use]
    pub fn new() -> Self {
        Self
    }

    /// Re-mask `c` with explicit randomness `a`: `(c1 + a·G, c2 + a·H)`.
    /// Shared by `mask`, `remask`, and the shuffle prover.
    pub(crate) fn remask_with(agg: &AggregateKey, c: &MaskedCard, a: Fr) -> MaskedCard {
        MaskedCard {
            c1: c.c1 + generator() * a,
            c2: c.c2 + agg.0 * a,
        }
    }

    pub fn keygen(&self, rng: &mut impl RngCore) -> (SecretKey, PublicKey, SchnorrProof) {
        let x = Fr::rand(rng);
        let h = generator() * x;
        let proof = SchnorrProof::prove(x, h, rng);
        (SecretKey(x), PublicKey(h), proof)
    }

    pub fn verify_key(&self, pk: &PublicKey, proof: &SchnorrProof) -> Result<(), MpError> {
        if proof.verify(pk.0) {
            Ok(())
        } else {
            Err(MpError::BadProof("key ownership"))
        }
    }

    pub fn aggregate(&self, pks: &[PublicKey]) -> AggregateKey {
        let mut sum = Projective::zero();
        for pk in pks {
            sum += pk.0;
        }
        AggregateKey(sum)
    }

    pub fn encode(&self, card: Card) -> MaskedCard {
        MaskedCard {
            c1: Projective::zero(),
            c2: encode_point(card),
        }
    }

    pub fn decode(&self, m: &MaskedCard) -> Result<Card, MpError> {
        decode_point(&m.c2).ok_or(MpError::StillMasked)
    }

    pub fn mask(
        &self,
        agg: &AggregateKey,
        m: &MaskedCard,
        rng: &mut impl RngCore,
    ) -> (MaskedCard, DleqProof) {
        self.remask(agg, m, rng)
    }

    pub fn remask(
        &self,
        agg: &AggregateKey,
        c: &MaskedCard,
        rng: &mut impl RngCore,
    ) -> (MaskedCard, DleqProof) {
        let a = Fr::rand(rng);
        let out = Self::remask_with(agg, c, a);
        let proof = DleqProof::prove(a, generator(), out.c1 - c.c1, agg.0, out.c2 - c.c2, rng);
        (out, proof)
    }

    pub fn verify_mask(
        &self,
        agg: &AggregateKey,
        input: &MaskedCard,
        output: &MaskedCard,
        proof: &DleqProof,
    ) -> Result<(), MpError> {
        let d1 = output.c1 - input.c1;
        let d2 = output.c2 - input.c2;
        if proof.verify(generator(), d1, agg.0, d2) {
            Ok(())
        } else {
            Err(MpError::BadProof("mask re-encryption"))
        }
    }

    pub fn reveal_token(
        &self,
        sk: &SecretKey,
        pk: &PublicKey,
        c: &MaskedCard,
        rng: &mut impl RngCore,
    ) -> RevealToken {
        let d = c.c1 * sk.0;
        let proof = DleqProof::prove(sk.0, generator(), pk.0, c.c1, d, rng);
        RevealToken { d, proof }
    }

    pub fn verify_reveal_token(
        &self,
        pk: &PublicKey,
        c: &MaskedCard,
        t: &RevealToken,
    ) -> Result<(), MpError> {
        if t.proof.verify(generator(), pk.0, c.c1, t.d) {
            Ok(())
        } else {
            Err(MpError::BadProof("reveal token"))
        }
    }

    pub fn unmask(&self, c: &MaskedCard, tokens: &[RevealToken]) -> Result<MaskedCard, MpError> {
        let mut sum = Projective::zero();
        for t in tokens {
            sum += t.d;
        }
        Ok(MaskedCard {
            c1: c.c1,
            c2: c.c2 - sum,
        })
    }
}
