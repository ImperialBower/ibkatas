# Stage 2 — Sigma proofs (Schnorr + Chaum–Pedersen)

> Prove you know a secret — or that two public values hide the *same* secret —
> without revealing it. These zero-knowledge proofs are the trust machinery the
> whole protocol runs on.

## The concept

Mental poker is **trustless**: no player is allowed to cheat even though there is
no referee. That guarantee comes from *zero-knowledge proofs*. Every time a
player does something secret (publishes a key, re-encrypts a card, reveals their
share) they attach a small proof that they did it *correctly* — checkable by
everyone, revealing nothing.

This stage builds the two proofs the rest of the protocol uses, both **sigma
protocols** with a three-move shape — *commit, challenge, respond*:

- **Schnorr** — "I know the `w` behind this public `P = w·G`." Used to prove a
  player owns the secret key behind their published share (stopping *rogue-key*
  attacks, where an attacker publishes a key they cannot actually use).
- **Chaum–Pedersen (DLEQ)** — "These two public points `P1 = w·G1` and
  `P2 = w·G2` share the *same* secret `w`." Used for reveal tokens and re-mask
  proofs in later stages.

Both are made **non-interactive** with the **Fiat–Shamir transform**: the random
challenge that a live verifier would send is replaced by a hash of the statement
and the prover's commitments. The provided `Transcript` type is that hash.

## Your challenge

Edit `exercise/src/lib.rs`. The `Transcript` (Fiat–Shamir) machinery is given.
Implement the five `todo!()`s:

| Function | What it must do |
|----------|-----------------|
| `SchnorrProof::prove` | commit `k·G`, hash a challenge `e`, respond `s = k + e·w` |
| `SchnorrProof::verify` | recompute `e`, check `s·G == r + e·P` |
| `DleqProof::prove` | one nonce `k`, two commitments `k·g1`, `k·g2` |
| `DleqProof::verify` | check `s·g1 == r1 + e·p1` **and** `s·g2 == r2 + e·p2` |
| `DleqProof::challenge` | absorb the 6 points, squeeze a scalar |

### Run it

```bash
cd exercise
cargo test          # 4 tests: completeness + soundness for each proof
```

## Hints

<details>
<summary>What's the verification equation, and why does it work?</summary>

For Schnorr, the verifier checks `s·G == r + e·P`. Substitute the honest
`s = k + e·w` and `P = w·G`:

```
s·G = (k + e·w)·G = k·G + e·w·G = r + e·P  ✓
```

It only balances when `P` really equals `w·G`. That is why a proof verifies for
the right point but fails for any other.
</details>

<details>
<summary>Order of operations in the transcript</summary>

You must absorb the **commitment** (`r`, or `r1`/`r2`) into the transcript
*before* squeezing the challenge — in both `prove` and `verify`, in the same
order. If prover and verifier absorb different points or in a different order,
they compute different `e` and every proof fails. Match the labels too:
`b"pkmental/schnorr"` and `b"pkmental/dleq"`.
</details>

<details>
<summary>DLEQ: what makes the two logs "equal"?</summary>

Use a **single** nonce `k` for both commitments (`r1 = k·g1`, `r2 = k·g2`) and a
**single** response `s`. Verifying both equations with that one `s` is what
forces the two discrete logs to coincide. If they differed, no single `s` could
satisfy both at once.
</details>

<details>
<summary>Full solution</summary>

See [`solution/`](solution/) and [`SOLUTION.md`](solution/SOLUTION.md).
</details>

## Where this lives in the real codebase

[`pkmental/src/crypto/sigma.rs`](https://github.com/ImperialBower/pkmental/blob/main/src/crypto/sigma.rs) — identical, plus a
`fiat_shamir_bits` helper used by the shuffle (you will meet it in stage 4).

➡️ **Next:** [Stage 3 — Threshold ElGamal](../stage-3-elgamal/), where these
proofs guard a card-encryption scheme that no single player can open alone.
