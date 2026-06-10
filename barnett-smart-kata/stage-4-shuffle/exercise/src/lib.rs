//! Stage 4 — A sound, zero-knowledge cut-and-choose verifiable shuffle.
//!
//! Re-masking and permuting a deck is easy (stage 3 gave you `remask_with`).
//! *Proving* the output is a genuine permutation of the input — no card added,
//! dropped, or duplicated — **without revealing the permutation** is the hard
//! part. This is the Sako–Kilian **cut-and-choose** protocol:
//!
//! For each of `ROUNDS` rounds the prover publishes an independent intermediate
//! shuffle `E_j` of the input. A Fiat–Shamir challenge **bit** then forces the
//! prover to reveal *one* linkage:
//!
//! - bit 0: how `E_j` is a shuffle of the **input**, or
//! - bit 1: how the **output** is a shuffle of `E_j`.
//!
//! A cheater who did not really shuffle can answer at most one of the two for
//! any `E_j`, so each round catches a cheat with probability ≥ 1/2 — and
//! `ROUNDS` rounds make the soundness error `2^-ROUNDS`. Revealing only one
//! linkage per round leaks nothing about the real permutation.
//!
//! All the helpers are **provided**. Implement `prove` and `verify`, then
//! `cargo test`. (Note: the honest test runs all 40 rounds over 52 cards, so it
//! takes ~30s — that is the real soundness parameter at work.)

// `prove`/`verify` are stubbed; the helpers below stay unused until you wire
// them in. Delete this once both functions are implemented.
#![allow(unused_variables, unused_imports, dead_code)]

mod card;
mod elgamal;
mod encode;
mod sigma;

pub use card::{Card, Rank, Suit, DECK_ARRAY};

use ark_pallas::{Fr, Projective};
use ark_std::UniformRand;
use rand::RngCore;

use crate::elgamal::{AggregateKey, ElGamalCrypto, MaskedCard, MpError};
use crate::sigma::fiat_shamir_bits;

/// Number of cut-and-choose rounds; soundness error is `2^-ROUNDS`.
pub const ROUNDS: usize = 40;

/// One round's revealed linkage: a permutation and the per-card re-mask
/// randomness that maps one deck onto another.
#[derive(Clone, Debug, PartialEq, Eq)]
struct RoundResponse {
    perm: Vec<usize>,
    rand: Vec<Fr>,
}

/// Proof that one deck is a permutation-plus-re-mask of another.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ShuffleProof {
    intermediates: Vec<Vec<MaskedCard>>,
    responses: Vec<RoundResponse>,
}

/// Draw a uniformly random permutation of `0..n` (Fisher–Yates). Provided.
fn random_permutation(n: usize, rng: &mut impl RngCore) -> Vec<usize> {
    let mut p: Vec<usize> = (0..n).collect();
    for i in (1..n).rev() {
        let j = (rng.next_u64() % (i as u64 + 1)) as usize;
        p.swap(i, j);
    }
    p
}

/// Invert a permutation: `inv[p[i]] = i`. Provided.
fn invert(p: &[usize]) -> Vec<usize> {
    let mut inv = vec![0usize; p.len()];
    for (i, &pi) in p.iter().enumerate() {
        inv[pi] = i;
    }
    inv
}

/// Is `p` a permutation of `0..n`? Provided — your `verify` must reject a
/// response whose `perm` is not one (that is how duplicates are caught).
fn is_permutation(p: &[usize], n: usize) -> bool {
    if p.len() != n {
        return false;
    }
    let mut seen = vec![false; n];
    for &x in p {
        if x >= n || seen[x] {
            return false;
        }
        seen[x] = true;
    }
    true
}

/// Apply `out[i] = remask(deck[perm[i]], rand[i])`. Provided — this is how a
/// permutation + per-card randomness turns one deck into another.
fn apply(agg: &AggregateKey, deck: &[MaskedCard], perm: &[usize], rand: &[Fr]) -> Vec<MaskedCard> {
    perm.iter()
        .zip(rand.iter())
        .map(|(&src, &a)| ElGamalCrypto::remask_with(agg, &deck[src], a))
        .collect()
}

/// Flatten decks into a point sequence for the Fiat–Shamir challenge. Provided.
fn transcript_points(
    input: &[MaskedCard],
    output: &[MaskedCard],
    intermediates: &[Vec<MaskedCard>],
) -> Vec<Projective> {
    let mut pts = Vec::new();
    let mut push = |deck: &[MaskedCard]| {
        for c in deck {
            pts.push(c.c1);
            pts.push(c.c2);
        }
    };
    push(input);
    push(output);
    for e in intermediates {
        push(e);
    }
    pts
}

/// Shuffle `deck` under `agg` and prove it.
///
/// TODO(you):
/// 1. Pick the real shuffle: a permutation `pi` (`random_permutation(n, rng)`)
///    and per-card randomness `rho` (`Fr::rand`). `output = apply(agg, deck, pi, rho)`.
/// 2. For each of `ROUNDS` rounds, pick an independent intermediate shuffle of
///    the input: permutation `sigma`, randomness `alpha`, and
///    `E_j = apply(agg, deck, sigma, alpha)`. Keep `sigma`/`alpha`/`E_j`.
/// 3. Get challenge bits: `fiat_shamir_bits(b"pkmental/shuffle",
///    &transcript_points(deck, &output, &intermediates), ROUNDS)`.
/// 4. For round `j`, build the `RoundResponse`:
///    - bit 0: reveal input→`E_j` — just `perm = sigma`, `rand = alpha`.
///    - bit 1: reveal `E_j`→output — `tau[i] = sigma⁻¹[pi[i]]` (use `invert`)
///      and `b[i] = rho[i] − alpha[tau[i]]`.
/// 5. Return `(output, ShuffleProof { intermediates, responses })`.
pub fn prove(
    agg: &AggregateKey,
    deck: &[MaskedCard],
    rng: &mut impl RngCore,
) -> (Vec<MaskedCard>, ShuffleProof) {
    todo!("cut-and-choose prover: real shuffle + ROUNDS intermediates + responses")
}

/// Verify a shuffle proof.
///
/// TODO(you):
/// 1. Length checks: `output` and every intermediate must have `n = input.len()`
///    cards (`MpError::DeckLength`); there must be exactly `ROUNDS` intermediates
///    and responses (`MpError::BadProof`).
/// 2. Recompute the same challenge bits with `fiat_shamir_bits` over
///    `transcript_points(input, output, &proof.intermediates)`.
/// 3. For each `(bit, E_j, response)`: reject if `response.perm` is not a
///    permutation of `0..n` or `response.rand` has the wrong length. Then
///    recompute the claimed linkage with `apply` and compare:
///    - bit 1: `apply(agg, E_j, perm, rand)` must equal `output`.
///    - bit 0: `apply(agg, input, perm, rand)` must equal `E_j`.
///    Any mismatch is `MpError::BadProof`.
pub fn verify(
    agg: &AggregateKey,
    input: &[MaskedCard],
    output: &[MaskedCard],
    proof: &ShuffleProof,
) -> Result<(), MpError> {
    todo!("cut-and-choose verifier: check each round's revealed linkage")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn agg_and_deck() -> (ElGamalCrypto, AggregateKey, Vec<MaskedCard>) {
        let mut rng = ark_std::test_rng();
        let crypto = ElGamalCrypto::new();
        let (_, pk0, _) = crypto.keygen(&mut rng);
        let (_, pk1, _) = crypto.keygen(&mut rng);
        let agg = crypto.aggregate(&[pk0, pk1]);
        let deck: Vec<MaskedCard> = DECK_ARRAY
            .iter()
            .map(|&c| crypto.mask(&agg, &crypto.encode(c), &mut rng).0)
            .collect();
        (crypto, agg, deck)
    }

    /// An honestly produced shuffle proof verifies.
    #[test]
    fn honest_shuffle_verifies() {
        let mut rng = ark_std::test_rng();
        let (_, agg, deck) = agg_and_deck();
        let (out, proof) = prove(&agg, &deck, &mut rng);
        assert_eq!(out.len(), 52);
        assert!(verify(&agg, &deck, &out, &proof).is_ok());
    }

    /// Tampering with the output (a swap) breaks verification.
    #[test]
    fn tampered_output_is_rejected() {
        let mut rng = ark_std::test_rng();
        let (_, agg, deck) = agg_and_deck();
        let (mut out, proof) = prove(&agg, &deck, &mut rng);
        out.swap(0, 1);
        assert!(verify(&agg, &deck, &out, &proof).is_err());
    }

    /// Injecting a duplicate card is rejected.
    #[test]
    fn duplicated_card_is_rejected() {
        let mut rng = ark_std::test_rng();
        let (_, agg, deck) = agg_and_deck();
        let (mut out, proof) = prove(&agg, &deck, &mut rng);
        out[5] = out[6]; // inject a duplicate
        assert!(verify(&agg, &deck, &out, &proof).is_err());
    }
}
