//! Stage 4 — A sound, zero-knowledge cut-and-choose verifiable shuffle.
//! **Reference solution.**
//!
//! For each of `ROUNDS` rounds the prover publishes an independent intermediate
//! shuffle `E_j` of the input. A Fiat–Shamir challenge bit then forces the
//! prover to reveal *one* linkage: input→`E_j` (bit 0) or `E_j`→output (bit 1).
//! A cheat survives a round with probability ≤ 1/2, so `ROUNDS` rounds drive the
//! soundness error to `2^-ROUNDS`. Revealing one linkage per round leaks nothing
//! about the real permutation.

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

/// Is `p` a permutation of `0..n`? Provided.
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

/// Apply `out[i] = remask(deck[perm[i]], rand[i])`. Provided.
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
pub fn prove(
    agg: &AggregateKey,
    deck: &[MaskedCard],
    rng: &mut impl RngCore,
) -> (Vec<MaskedCard>, ShuffleProof) {
    let n = deck.len();

    // The real shuffle: pi[i] = source index for output position i.
    let pi = random_permutation(n, rng);
    let rho: Vec<Fr> = (0..n).map(|_| Fr::rand(rng)).collect();
    let output = apply(agg, deck, &pi, &rho);

    // Per round, an independent intermediate shuffle E_j of the input.
    let mut intermediates = Vec::with_capacity(ROUNDS);
    let mut sigmas = Vec::with_capacity(ROUNDS);
    let mut alphas = Vec::with_capacity(ROUNDS);
    for _ in 0..ROUNDS {
        let sigma = random_permutation(n, rng);
        let alpha: Vec<Fr> = (0..n).map(|_| Fr::rand(rng)).collect();
        intermediates.push(apply(agg, deck, &sigma, &alpha));
        sigmas.push(sigma);
        alphas.push(alpha);
    }

    // Fiat–Shamir: bits bound to input, output, and every intermediate.
    let bits = fiat_shamir_bits(
        b"pkmental/shuffle",
        &transcript_points(deck, &output, &intermediates),
        ROUNDS,
    );

    let mut responses = Vec::with_capacity(ROUNDS);
    for j in 0..ROUNDS {
        let sigma = &sigmas[j];
        let alpha = &alphas[j];
        let response = if bits[j] {
            // Reveal E_j -> output. tau[i] = sigma^{-1}[pi[i]],
            // b[i] = rho[i] - alpha[tau[i]].
            let sigma_inv = invert(sigma);
            let tau: Vec<usize> = (0..n).map(|i| sigma_inv[pi[i]]).collect();
            let b: Vec<Fr> = (0..n).map(|i| rho[i] - alpha[tau[i]]).collect();
            RoundResponse { perm: tau, rand: b }
        } else {
            // Reveal input -> E_j.
            RoundResponse {
                perm: sigma.clone(),
                rand: alpha.clone(),
            }
        };
        responses.push(response);
    }

    (
        output,
        ShuffleProof {
            intermediates,
            responses,
        },
    )
}

/// Verify a shuffle proof.
pub fn verify(
    agg: &AggregateKey,
    input: &[MaskedCard],
    output: &[MaskedCard],
    proof: &ShuffleProof,
) -> Result<(), MpError> {
    let n = input.len();
    if output.len() != n {
        return Err(MpError::DeckLength {
            expected: n,
            got: output.len(),
        });
    }
    if proof.intermediates.len() != ROUNDS || proof.responses.len() != ROUNDS {
        return Err(MpError::BadProof("shuffle round count"));
    }
    for e in &proof.intermediates {
        if e.len() != n {
            return Err(MpError::DeckLength {
                expected: n,
                got: e.len(),
            });
        }
    }

    let bits = fiat_shamir_bits(
        b"pkmental/shuffle",
        &transcript_points(input, output, &proof.intermediates),
        ROUNDS,
    );

    for ((bit, e_j), resp) in bits.iter().zip(&proof.intermediates).zip(&proof.responses) {
        if !is_permutation(&resp.perm, n) || resp.rand.len() != n {
            return Err(MpError::BadProof("shuffle response shape"));
        }
        let recomputed = if *bit {
            // bit 1: output must be E_j permuted+re-masked.
            apply(agg, e_j, &resp.perm, &resp.rand)
        } else {
            // bit 0: E_j must be input permuted+re-masked.
            apply(agg, input, &resp.perm, &resp.rand)
        };
        let target: &[MaskedCard] = if *bit { output } else { e_j };
        if recomputed.as_slice() != target {
            return Err(MpError::BadProof("shuffle linkage"));
        }
    }
    Ok(())
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
