//! Stage 3 — Threshold ElGamal masking.
//!
//! A masked card is an ElGamal ciphertext `(c1, c2)` of a plaintext point `M`
//! under the **aggregate** key `H = ∑ x_i·G` (every player contributes a share
//! `x_i`). The magic property: a card opens **only** when *every* player adds
//! their reveal token. Any missing share leaves it masked.
//!
//! ```text
//! mask:    (c1, c2) = (r·G, M + r·H)
//! token_i: d_i = x_i·c1                       (+ a Chaum–Pedersen proof)
//! unmask:  M = c2 − ∑ d_i = (M + r·H) − r·H   (since ∑ x_i·c1 = r·H)
//! ```
//!
//! Stages 1 and 2 are **provided** as working modules (`card`, `encode`,
//! `sigma`). Implement the methods marked `todo!()` below, then `cargo test`.

// The stubs below leave parameters and provided helpers unused until you
// implement them. Delete this once everything is wired up.
#![allow(unused_variables, unused_imports, dead_code)]

mod card;
mod encode;
mod sigma;

pub use card::{Card, Rank, Suit, DECK_ARRAY};

use ark_pallas::{Fr, Projective};
use ark_std::UniformRand;
use ark_std::Zero;
use rand::RngCore;

use encode::{decode_point, encode_point};
use sigma::{generator, DleqProof, SchnorrProof};

/// Errors raised by the card-crypto layer.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum MpError {
    /// `decode` was called on a card that is not yet fully unmasked.
    StillMasked,
    /// A zero-knowledge proof failed to verify.
    BadProof(&'static str),
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
    /// Construct the backend.
    #[must_use]
    pub fn new() -> Self {
        Self
    }

    /// Re-mask `c` with explicit randomness `a`: `(c1 + a·G, c2 + a·H)`.
    ///
    /// TODO(you): this is the core ElGamal masking step. Add `a·G` to `c1` and
    /// `a·H` to `c2`, where `H` is `agg.0` and `G` is `generator()`. Re-masking
    /// re-randomizes the ciphertext without changing the plaintext it hides.
    pub(crate) fn remask_with(agg: &AggregateKey, c: &MaskedCard, a: Fr) -> MaskedCard {
        todo!("return (c1 + a·G, c2 + a·H)")
    }

    /// Generate a key share with a Schnorr proof of knowledge of its secret.
    ///
    /// TODO(you): draw a secret `x` (`Fr::rand`), publish `h = x·G`, and attach
    /// a `SchnorrProof::prove(x, h, rng)` so others can check you own it.
    pub fn keygen(&self, rng: &mut impl RngCore) -> (SecretKey, PublicKey, SchnorrProof) {
        todo!("x = rand; h = x·G; prove knowledge of x")
    }

    /// Verify a key share's proof of knowledge (stops rogue-key attacks).
    /// Provided for you.
    pub fn verify_key(&self, pk: &PublicKey, proof: &SchnorrProof) -> Result<(), MpError> {
        if proof.verify(pk.0) {
            Ok(())
        } else {
            Err(MpError::BadProof("key ownership"))
        }
    }

    /// Fold verified key shares into the aggregate key `H = ∑ h_i`.
    ///
    /// TODO(you): sum the public points. Start from `Projective::zero()`.
    pub fn aggregate(&self, pks: &[PublicKey]) -> AggregateKey {
        todo!("sum all pk.0 into the aggregate H")
    }

    /// Encode a [`Card`] to its trivial (public) masked form. Provided for you.
    pub fn encode(&self, card: Card) -> MaskedCard {
        // Trivial encryption: r = 0, so c1 = identity and c2 = M.
        MaskedCard {
            c1: Projective::zero(),
            c2: encode_point(card),
        }
    }

    /// Recover a [`Card`] from a fully unmasked card. Provided for you.
    pub fn decode(&self, m: &MaskedCard) -> Result<Card, MpError> {
        decode_point(&m.c2).ok_or(MpError::StillMasked)
    }

    /// Mask a (public) card under the aggregate key. Provided — delegates to
    /// `remask`, which you implement.
    pub fn mask(
        &self,
        agg: &AggregateKey,
        m: &MaskedCard,
        rng: &mut impl RngCore,
    ) -> (MaskedCard, DleqProof) {
        self.remask(agg, m, rng)
    }

    /// Re-mask an already-masked card without decrypting it, with a proof.
    ///
    /// TODO(you):
    /// 1. Draw random `a` and compute `out = Self::remask_with(agg, c, a)`.
    /// 2. Prove the increments `(Δc1, Δc2) = (a·G, a·H)` share the witness `a`
    ///    with a `DleqProof::prove`. The bases are `G` and `H = agg.0`; the
    ///    points are `out.c1 - c.c1` and `out.c2 - c.c2`.
    pub fn remask(
        &self,
        agg: &AggregateKey,
        c: &MaskedCard,
        rng: &mut impl RngCore,
    ) -> (MaskedCard, DleqProof) {
        todo!("re-mask with random a, then DLEQ-prove (a·G, a·H) share a")
    }

    /// Verify a mask/remask proof. Provided for you — note the exact DLEQ
    /// statement it checks; your `remask` must produce a matching proof.
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

    /// Produce this player's reveal token (partial unmask) for a card.
    ///
    /// TODO(you): the token is `d = x_i·c1` (the part of the mask only this
    /// player can strip). Attach a `DleqProof` that `log_G(pk) = log_{c1}(d)`,
    /// i.e. the same secret `x_i` relates `G→pk` and `c1→d`.
    pub fn reveal_token(
        &self,
        sk: &SecretKey,
        pk: &PublicKey,
        c: &MaskedCard,
        rng: &mut impl RngCore,
    ) -> RevealToken {
        todo!("d = x·c1; DLEQ-prove log_G(pk) = log_{{c1}}(d)")
    }

    /// Verify a reveal token against its author's public key. Provided for you.
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

    /// Combine reveal tokens, subtracting `∑ d_i` from `c2`.
    ///
    /// TODO(you): sum all `t.d`, then return a `MaskedCard` with the same `c1`
    /// and `c2 - ∑ d_i`. A *full* set of tokens makes `c2` collapse back to `M`.
    pub fn unmask(&self, c: &MaskedCard, tokens: &[RevealToken]) -> Result<MaskedCard, MpError> {
        todo!("subtract the sum of all token d's from c2")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn setup(n: usize) -> (ElGamalCrypto, Vec<SecretKey>, Vec<PublicKey>, AggregateKey) {
        let mut rng = ark_std::test_rng();
        let crypto = ElGamalCrypto::new();
        let mut sks = Vec::new();
        let mut pks = Vec::new();
        for _ in 0..n {
            let (sk, pk, proof) = crypto.keygen(&mut rng);
            crypto.verify_key(&pk, &proof).unwrap();
            sks.push(sk);
            pks.push(pk);
        }
        let agg = crypto.aggregate(&pks);
        (crypto, sks, pks, agg)
    }

    /// A full set of reveal tokens recovers the original card.
    #[test]
    fn full_unmask_recovers_card() {
        let mut rng = ark_std::test_rng();
        let (crypto, sks, pks, agg) = setup(3);
        let card = DECK_ARRAY[17];
        let (masked, _) = crypto.mask(&agg, &crypto.encode(card), &mut rng);
        let tokens: Vec<_> = (0..3)
            .map(|i| crypto.reveal_token(&sks[i], &pks[i], &masked, &mut rng))
            .collect();
        let opened = crypto.unmask(&masked, &tokens).unwrap();
        assert_eq!(crypto.decode(&opened), Ok(card));
    }

    /// A *partial* set of tokens leaves the card masked — the threshold property.
    #[test]
    fn partial_unmask_stays_masked() {
        let mut rng = ark_std::test_rng();
        let (crypto, sks, pks, agg) = setup(3);
        let card = DECK_ARRAY[17];
        let (masked, _) = crypto.mask(&agg, &crypto.encode(card), &mut rng);
        // Only seats 1 and 2 contribute; seat 0 (the recipient) withholds.
        let tokens: Vec<_> = (1..3)
            .map(|i| crypto.reveal_token(&sks[i], &pks[i], &masked, &mut rng))
            .collect();
        let partial = crypto.unmask(&masked, &tokens).unwrap();
        assert_eq!(crypto.decode(&partial), Err(MpError::StillMasked));
    }

    /// A mask comes with a proof that verifies against input and output.
    #[test]
    fn mask_proof_round_trips() {
        let mut rng = ark_std::test_rng();
        let (crypto, _, _, agg) = setup(2);
        let card = DECK_ARRAY[0];
        let input = crypto.encode(card);
        let (output, proof) = crypto.mask(&agg, &input, &mut rng);
        assert!(crypto.verify_mask(&agg, &input, &output, &proof).is_ok());
    }

    /// A token computed with one secret but presented under another key fails.
    #[test]
    fn reveal_token_with_wrong_key_fails() {
        let mut rng = ark_std::test_rng();
        let (crypto, sks, pks, agg) = setup(2);
        let card = DECK_ARRAY[0];
        let (masked, _) = crypto.mask(&agg, &crypto.encode(card), &mut rng);
        // Token computed with seat 0's secret but presented as seat 1's.
        let t = crypto.reveal_token(&sks[0], &pks[0], &masked, &mut rng);
        assert!(crypto.verify_reveal_token(&pks[1], &masked, &t).is_err());
    }
}
