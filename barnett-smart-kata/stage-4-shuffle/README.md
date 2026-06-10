# Stage 4 — Verifiable shuffle (cut-and-choose)

> Shuffle the encrypted deck and **prove you shuffled honestly** — no card added,
> dropped, or duplicated — without revealing the order you put them in. The
> hardest and most beautiful piece of the protocol.

## The concept

When a player shuffles the deck, they permute it and re-mask every card (stage 3)
so nobody can follow a card through the shuffle. But the other players need a
guarantee: that the new deck is a genuine rearrangement of the old one, with the
same 52 cards. A cheating shuffler who could inject a duplicate ace — or peek at
the order — would break the game.

So the shuffler must produce a **zero-knowledge proof of a correct shuffle**:
convincing that the output is a permutation-plus-re-mask of the input, while
revealing *nothing* about the permutation. This kata uses the **Sako–Kilian
cut-and-choose** protocol:

```
            bit 0 ↙        ↘ bit 1
   input ───────▶  E_j  ───────▶ output
        (reveal this)   (or reveal this — never both)
```

Each round the prover commits to a fresh intermediate shuffle `E_j`, then a
Fiat–Shamir coin flip forces it to open *one* of the two links. A cheater can
fake at most one link per round, so `ROUNDS = 40` rounds make cheating succeed
with probability only `2^-40`. Opening one link of an independent `E_j` leaks
nothing about the real order.

## Your challenge

Edit `exercise/src/lib.rs`. Everything from stages 1–3 plus all the shuffle
helpers (`random_permutation`, `invert`, `is_permutation`, `apply`,
`transcript_points`) are **provided**. Implement two functions:

| Function | What it must do |
|----------|-----------------|
| `prove` | real shuffle + `ROUNDS` intermediates + per-round responses |
| `verify` | recompute the challenge bits, check each round's revealed linkage |

### Run it

```bash
cd exercise
cargo test          # 3 tests: honest / tampered / duplicate
```

> ⏱️ The honest test runs all 40 rounds over a 52-card deck, so it takes ~30
> seconds. That is the real soundness parameter — not a slow test.

## Hints

<details>
<summary>What does each round of <code>prove</code> produce?</summary>

A fresh intermediate `E_j = apply(agg, deck, sigma, alpha)` for a new random
`sigma`/`alpha`, kept alongside the real shuffle `pi`/`rho`. After hashing the
challenge bits, each round emits a `RoundResponse` that opens *one* link
depending on the bit.
</details>

<details>
<summary>The bit-1 response (the only tricky algebra)</summary>

You hold input→output (`pi`,`rho`) and input→`E_j` (`sigma`,`alpha`). You need
`E_j`→output. Compose: `tau[i] = sigma⁻¹[pi[i]]` (use the provided `invert`), and
the leftover randomness is `b[i] = rho[i] − alpha[tau[i]]`. Then
`apply(E_j, tau, b) == output`. The bit-0 response is just `sigma`/`alpha`
unchanged.
</details>

<details>
<summary>How does <code>verify</code> catch a duplicate?</summary>

For each round, recompute the link with `apply` and compare to the target deck
(`output` for bit 1, `E_j` for bit 0). Also reject any `perm` that is not a true
permutation via `is_permutation` — a duplicated output card cannot be explained
by a bijection, so some round fails. And re-derive the bits with `fiat_shamir_bits`
so the prover cannot have chosen them.
</details>

<details>
<summary>Why recompute the challenge bits?</summary>

The proof does not carry the bits; `verify` rehashes the input, output, and all
intermediates (`transcript_points` → `fiat_shamir_bits`). This binds the
challenge to exactly the decks in the proof — the Fiat–Shamir discipline from
stage 2, applied to the whole deck.
</details>

<details>
<summary>Full solution</summary>

See [`solution/`](solution/) and [`SOLUTION.md`](solution/SOLUTION.md).
</details>

## Where this lives in the real codebase

[`pkmental/src/crypto/shuffle.rs`](https://github.com/ImperialBower/pkmental/blob/main/src/crypto/shuffle.rs) — the same
algorithm. Production systems often prefer Bayer–Groth (`O(√n)` proofs);
cut-and-choose is used here because it is sound, zero-knowledge, and simple
enough to build — and to learn — from scratch.

🎉 **You've reconstructed the full Barnett–Smart card layer.** See the
[top-level README](../README.md) for how these four stages compose into a real
trustless poker engine.
