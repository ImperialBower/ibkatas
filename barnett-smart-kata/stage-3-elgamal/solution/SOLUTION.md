# Stage 3 — Solution walkthrough

## The key insight: split the decryption key across all players

Ordinary ElGamal encrypts a message point `M` under a public key `H` as

```
(c1, c2) = (r·G, M + r·H)        r random
```

and whoever holds the secret `x` (with `H = x·G`) decrypts by computing
`c2 − x·c1 = M`. Mental poker's twist: **no single player may hold `x`.** So the
key is *distributed*. Each of the `l` players picks a share `x_i`, publishes
`h_i = x_i·G`, and the deck is masked under the **aggregate**

```
H = ∑ h_i = (∑ x_i)·G
```

Now decryption needs *every* share. Each player contributes a **reveal token**
`d_i = x_i·c1`, and:

```
∑ d_i = ∑ x_i·c1 = (∑ x_i)·c1 = r·H
c2 − ∑ d_i = (M + r·H) − r·H = M
```

The card opens only when the tokens are complete. That is the whole game:
`partial_unmask_stays_masked` checks that with one share missing, `c2 − partial`
is `M + x_missing·c1` — a non-card point, so `decode` returns `StillMasked`.

## Masking and re-masking

`remask_with` is the one formula everything is built on:

```rust
MaskedCard {
    c1: c.c1 + generator() * a,   // c1 + a·G
    c2: c.c2 + agg.0 * a,         // c2 + a·H
}
```

Adding `(a·G, a·H)` to a ciphertext re-randomizes it **without changing the
plaintext** — `M` is untouched because the added `a·H` lands in the `r·H` blind,
not in `M`. `encode` produces the trivial ciphertext `(O, M)` (an unencrypted
card), and `mask` is just `remask` applied to it: a fresh `a` turns the public
card into a hidden one.

## Why every secret step carries a proof

A malicious player could send a *wrong* token to corrupt the opening, or mask a
card into garbage. Each operation therefore ships a **DLEQ proof** (stage 2):

- **Re-mask** proves `(Δc1, Δc2) = (a·G, a·H)` share the witness `a` — i.e. the
  same randomness was added to both components, so the plaintext is preserved:
  ```rust
  DleqProof::prove(a, generator(), out.c1 - c.c1, agg.0, out.c2 - c.c2, rng)
  ```
- **Reveal token** proves `log_G(pk) = log_{c1}(d)` — i.e. the token used the
  *same* `x_i` that the player committed to in their public key:
  ```rust
  DleqProof::prove(sk.0, generator(), pk.0, c.c1, d, rng)
  ```

`reveal_token_with_wrong_key_fails` is exactly this guard: a token made with
seat 0's secret cannot pass verification against seat 1's public key, because the
two discrete logs no longer match.

## How the real version differs

This lives in [`pkmental/src/crypto/elgamal.rs`](https://github.com/ImperialBower/pkmental/blob/main/src/crypto/elgamal.rs).
**One deliberate simplification:** the real code implements a `CardCrypto`
*trait* (with associated types and a second `PlaintextCrypto` mock backend), so
the poker engine stays generic over the scheme. Here those same methods are
plain inherent methods on `ElGamalCrypto` — identical bodies, less plumbing — so
the focus stays on the cryptography rather than the trait abstraction. The real
backend also has `shuffle`/`verify_shuffle` methods; those are stage 4.
