# Stage 2 — Solution walkthrough

## The key insight: commit – challenge – respond

Both proofs are **sigma protocols**, a three-move shape:

1. **Commit.** The prover picks a fresh random nonce `k` and sends a commitment
   built from it (`r = k·G`).
2. **Challenge.** A random `e` is chosen.
3. **Respond.** The prover sends `s = k + e·w`, blending the nonce with the
   secret `w` under the challenge.

The verifier checks one equation that can only hold if the prover really knew
`w`. For Schnorr:

```
s·G  ==  r + e·P          where P = w·G
```

Expand the left side with the honest `s = k + e·w`:

```
s·G = (k + e·w)·G = k·G + e·(w·G) = r + e·P   ✓
```

It balances **only** because `P = w·G`. A cheater who does not know `w` cannot
produce an `s` that satisfies the equation for a challenge they could not predict
— that is the soundness, and it is exactly what `schnorr_wrong_point_fails`
checks: the same proof against a different `P` breaks the equation.

## Fiat–Shamir: removing the verifier

Step 2 needs a random challenge the prover cannot predict *before* committing.
Classically a live verifier supplies it. The **Fiat–Shamir transform** replaces
that verifier with a hash: the prover derives `e` by hashing the statement and
its own commitments.

```rust
let mut t = Transcript::new(b"pkmental/schnorr");
t.absorb(&g);
t.absorb(&point);
t.absorb(&r);          // commitment must be absorbed BEFORE the challenge
let e = t.challenge();
```

Because `r` is hashed in, the prover is "committed" to it before `e` exists — it
cannot grind `r` to fit a chosen `e`. This turns an interactive proof into a
single, non-interactive, publicly-verifiable object. The domain-separation label
(`b"pkmental/schnorr"` vs `b"pkmental/dleq"`) stops a proof of one kind from
being replayed as another.

## DLEQ: one secret, two bases

Chaum–Pedersen proves `p1 = w·g1` **and** `p2 = w·g2` for the *same* `w`,
without revealing it. The construction reuses **one** nonce `k` across both
bases:

```
r1 = k·g1     r2 = k·g2     s = k + e·w
```

and the verifier checks **both** equations with the same `s`:

```
s·g1 == r1 + e·p1   AND   s·g2 == r2 + e·p2
```

Sharing `k` and `s` across the two bases is what ties the two discrete logs
together. If `p1` and `p2` had *different* logs (as in
`dleq_mismatched_logs_fail`), no single `s` can satisfy both equations at once,
so verification fails.

This "two points share a secret exponent" proof is the workhorse of stages 3–4:
a reveal token proves `log_G(pk) = log_{c1}(d)`, and a re-mask proves
`log_G(Δc1) = log_H(Δc2)`.

## How the real version differs

Identical to [`pkmental/src/crypto/sigma.rs`](https://github.com/ImperialBower/pkmental/blob/main/src/crypto/sigma.rs). The
real file also has a `fiat_shamir_bits` helper (challenge *bits* for the shuffle)
— omitted here because stage 2 does not need it; it returns in stage 4.
