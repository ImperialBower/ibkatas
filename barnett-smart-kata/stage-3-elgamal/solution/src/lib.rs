//! Stage 3 — Threshold ElGamal masking. **Reference solution.**
//!
//! Each card is an ElGamal ciphertext `(c1, c2)` of a plaintext group element
//! `M` under the aggregate key `H = ∑ x_i·G`:
//!
//! ```text
//! mask:    (c1, c2) = (r·G, M + r·H)
//! token_i: d_i = x_i·c1                       (with a Chaum–Pedersen proof)
//! unmask:  M = c2 − ∑ d_i = (M + r·H) − r·H   (since ∑ x_i·c1 = r·H)
//! ```

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
    pub(crate) fn remask_with(agg: &AggregateKey, c: &MaskedCard, a: Fr) -> MaskedCard {
        MaskedCard {
            c1: c.c1 + generator() * a,
            c2: c.c2 + agg.0 * a,
        }
    }

    /// Generate a key share with a Schnorr proof of knowledge of its secret.
    pub fn keygen(&self, rng: &mut impl RngCore) -> (SecretKey, PublicKey, SchnorrProof) {
        let x = Fr::rand(rng);
        let h = generator() * x;
        let proof = SchnorrProof::prove(x, h, rng);
        (SecretKey(x), PublicKey(h), proof)
    }

    /// Verify a key share's proof of knowledge (stops rogue-key attacks).
    pub fn verify_key(&self, pk: &PublicKey, proof: &SchnorrProof) -> Result<(), MpError> {
        if proof.verify(pk.0) {
            Ok(())
        } else {
            Err(MpError::BadProof("key ownership"))
        }
    }

    /// Fold verified key shares into the aggregate key `H = ∑ h_i`.
    pub fn aggregate(&self, pks: &[PublicKey]) -> AggregateKey {
        let mut sum = Projective::zero();
        for pk in pks {
            sum += pk.0;
        }
        AggregateKey(sum)
    }

    /// Encode a [`Card`] to its trivial (public) masked form.
    pub fn encode(&self, card: Card) -> MaskedCard {
        // Trivial encryption: r = 0, so c1 = identity and c2 = M.
        MaskedCard {
            c1: Projective::zero(),
            c2: encode_point(card),
        }
    }

    /// Recover a [`Card`] from a fully unmasked card.
    pub fn decode(&self, m: &MaskedCard) -> Result<Card, MpError> {
        decode_point(&m.c2).ok_or(MpError::StillMasked)
    }

    /// Mask a (public) card under the aggregate key.
    pub fn mask(
        &self,
        agg: &AggregateKey,
        m: &MaskedCard,
        rng: &mut impl RngCore,
    ) -> (MaskedCard, DleqProof) {
        self.remask(agg, m, rng)
    }

    /// Re-mask an already-masked card without decrypting it.
    pub fn remask(
        &self,
        agg: &AggregateKey,
        c: &MaskedCard,
        rng: &mut impl RngCore,
    ) -> (MaskedCard, DleqProof) {
        let a = Fr::rand(rng);
        let out = Self::remask_with(agg, c, a);
        // Prove the increments (Δc1, Δc2) = (a·G, a·H) share the witness a.
        let proof = DleqProof::prove(a, generator(), out.c1 - c.c1, agg.0, out.c2 - c.c2, rng);
        (out, proof)
    }

    /// Verify a mask/remask proof.
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
    pub fn reveal_token(
        &self,
        sk: &SecretKey,
        pk: &PublicKey,
        c: &MaskedCard,
        rng: &mut impl RngCore,
    ) -> RevealToken {
        let d = c.c1 * sk.0;
        // Prove log_G(pk) = log_{c1}(d) = x_i.
        let proof = DleqProof::prove(sk.0, generator(), pk.0, c.c1, d, rng);
        RevealToken { d, proof }
    }

    /// Verify a reveal token against its author's public key.
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
