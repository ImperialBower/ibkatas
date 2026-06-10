# Stage 4 — Solution walkthrough

## The problem

A player shuffles the (encrypted) deck: permutes it and re-masks every card so
nobody can track which card moved where. But how do the *others* know the
shuffler did not quietly swap in a second ace, or drop a card? They must be
convinced the output is a true permutation of the input — **without learning the
permutation** (or the shuffler could read everyone's cards).

## The cut-and-choose idea

Proving a shuffle directly is hard. So we prove it *indirectly* with a game the
cheater cannot reliably win. For each round the prover publishes an independent
intermediate shuffle `E_j` of the input. Then a coin flip (a Fiat–Shamir bit)
demands **one** of two openings:

```
input  ──σ──▶  E_j  ──τ──▶  output
        bit 0          bit 1
```

- **bit 0:** reveal `σ` — prove `E_j` is a real shuffle of the input.
- **bit 1:** reveal `τ` — prove the output is a real shuffle of `E_j`.

Here is the crux. If the output is an *honest* shuffle of the input, the prover
knows both `σ` and the composed map, so it can answer either bit. If the output
is **dishonest** (a card was swapped), then for a given `E_j` *at most one* of
the two links can be valid — because if both held, their composition would make
the output an honest shuffle of the input, contradiction. So a cheater is caught
with probability ≥ ½ per round. Over `ROUNDS = 40` rounds the cheat survives with
probability `2^-40` ≈ one in a trillion.

Crucially, each round reveals only **one** link of a **fresh, independent** `E_j`,
so the real permutation `pi` (input→output) is never exposed. That is the
zero-knowledge half.

## The prover's bit-1 algebra

The only fiddly part is answering bit 1. We know the real shuffle `pi`/`rho`
(input→output) and this round's `sigma`/`alpha` (input→`E_j`). We need the map
`E_j → output`. Composing:

```
tau = sigma⁻¹ ∘ pi          tau[i] = sigma⁻¹[pi[i]]
```

and the re-mask randomness subtracts what `E_j` already added:

```
b[i] = rho[i] − alpha[tau[i]]
```

so that `apply(E_j, tau, b)` re-masks exactly back to `output`. (`invert` gives
`sigma⁻¹`.) Bit 0 is trivial — you already hold `sigma`/`alpha`, so just hand
them over.

## The verifier

For each round, recompute the claimed link with the *same* `apply` the prover
used and check it lands on the right deck:

```rust
let recomputed = if bit { apply(agg, e_j, perm, rand) }   // → must equal output
                 else    { apply(agg, input, perm, rand) }; // → must equal E_j
```

Two structural checks do the rest of the work:

- `is_permutation(perm, n)` — rejects a `perm` that repeats or drops an index.
  This is what catches `duplicated_card_is_rejected`: a duplicated output card
  forces some round's revealed map to not be a bijection.
- Recomputing the Fiat–Shamir bits from the transcript binds the challenge to
  *these specific* intermediates, so the prover cannot choose `E_j` after seeing
  the bits. `tampered_output_is_rejected` fails because swapping two output cards
  changes the transcript and breaks the bit-1 linkage check.

## Why re-derive the bits instead of trusting them?

The proof does not store the challenge bits — the verifier recomputes them by
hashing the input, output, and all intermediates (`transcript_points` +
`fiat_shamir_bits`). If a cheating prover tried to pick favorable bits, the hash
would not match. This is the same Fiat–Shamir discipline as stage 2, scaled up to
a whole deck.

## How the real version differs

[`pkmental/src/crypto/shuffle.rs`](https://github.com/ImperialBower/pkmental/blob/main/src/crypto/shuffle.rs) — identical
algorithm. The doc comment there notes that production systems often use
Bayer–Groth (`O(√n)` proof size) instead; Sako–Kilian cut-and-choose is chosen
here because it is sound, zero-knowledge, and simple enough to implement from
scratch with confidence — exactly what makes it a good thing to *learn*.
