# Stage 3 — Threshold ElGamal masking

> Encrypt a card so that **no single player can open it** — it takes everyone's
> cooperation to reveal. This is the "shuffle-up-and-deal" layer of mental poker.

## The concept

In a real card game you trust the dealer to shuffle face-down and hand you cards
only you can see. Mental poker removes the dealer. Instead, cards are encrypted
under a key that is **split across all players**: each player `i` holds a secret
share `x_i`, and the deck is masked under the aggregate public key
`H = ∑ x_i·G`.

The defining property is **threshold decryption**: a masked card opens only when
*every* player contributes their piece (a "reveal token"). Withhold one and the
card stays hidden. That is how the protocol deals you a hole card nobody else can
read (everyone reveals to you but not to each other), and how it opens community
cards (everyone reveals to everyone).

A masked card is an **ElGamal ciphertext** — two curve points:

```text
mask:    (c1, c2) = (r·G, M + r·H)        M = the card's point (stage 1)
token_i: d_i = x_i·c1                      one player's partial unmask
unmask:  M = c2 − ∑ d_i                    only when all tokens are present
```

Every secret operation carries a **DLEQ proof** (stage 2) so cheating is caught.

## Your challenge

Edit `exercise/src/lib.rs`. Stages 1 & 2 are provided as working modules
(`card`, `encode`, `sigma`). Implement the six `todo!()` methods:

| Method | What it must do |
|--------|-----------------|
| `remask_with` | the masking formula `(c1 + a·G, c2 + a·H)` |
| `keygen` | random `x`, publish `x·G`, attach a Schnorr proof |
| `aggregate` | sum the public shares into `H` |
| `remask` | re-mask with random `a`, plus a DLEQ proof of `(a·G, a·H)` |
| `reveal_token` | `d = x·c1`, plus a DLEQ proof tying it to `pk` |
| `unmask` | subtract `∑ d_i` from `c2` |

The verifiers (`verify_mask`, `verify_reveal_token`), `encode`, `decode`, and
`mask` are **provided** — read the verifiers closely, they reveal the exact proof
shape your `remask`/`reveal_token` must produce.

### Run it

```bash
cd exercise
cargo test          # 4 tests: full unmask, threshold, mask proof, bad token
```

## Hints

<details>
<summary>The masking formula</summary>

`remask_with` adds the *same* scalar `a` to both components, scaled by the two
bases: `c1 + a·G` and `c2 + a·H`. `G` is `generator()`, `H` is `agg.0`. Point
addition and scalar multiplication are just `+` and `*`.
</details>

<details>
<summary>Which DLEQ statement does re-mask prove?</summary>

The increments are `Δc1 = out.c1 − c.c1 = a·G` and `Δc2 = out.c2 − c.c2 = a·H`.
You are proving these two share the witness `a`, with bases `G` and `H`. Look at
the provided `verify_mask` — it calls `proof.verify(generator(), Δc1, agg.0, Δc2)`,
so your `prove` must use those same four points (plus the witness `a`).
</details>

<details>
<summary>Which DLEQ statement does a reveal token prove?</summary>

`d = x·c1`, and the player already published `pk = x·G`. So the same `x` is the
discrete log of `pk` base `G` *and* of `d` base `c1`. That is
`DleqProof::prove(x, G, pk, c1, d, rng)`. The provided `verify_reveal_token`
shows the matching verification.
</details>

<details>
<summary>Why does a partial unmask stay masked?</summary>

`unmask` subtracts only the tokens it is given. With one share `x_j` missing,
`c2 − ∑_{i≠j} d_i = M + x_j·c1`, which is **not** one of the 52 card points — so
`decode` returns `StillMasked`. You do not special-case this; it falls out of the
math.
</details>

<details>
<summary>Full solution</summary>

See [`solution/`](solution/) and [`SOLUTION.md`](solution/SOLUTION.md).
</details>

## Where this lives in the real codebase

[`pkmental/src/crypto/elgamal.rs`](https://github.com/ImperialBower/pkmental/blob/main/src/crypto/elgamal.rs). The real backend
is the same arithmetic behind a `CardCrypto` *trait* (so the engine can swap in a
plaintext mock); here it is plain inherent methods to keep the focus on the
crypto. See [`SOLUTION.md`](solution/SOLUTION.md) for the full diff.

➡️ **Next:** [Stage 4 — Verifiable shuffle](../stage-4-shuffle/), the hardest
piece: prove a deck was shuffled honestly without revealing the order.
