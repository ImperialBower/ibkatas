# Stage 1 — Encoding cards as curve points

> Build the bijection that turns 52 playing cards into 52 distinct points on an
> elliptic curve, so the rest of the protocol can encrypt *cards* by doing
> arithmetic on *points*.

## The concept

Every cryptographic operation in mental poker — masking, shuffling, revealing —
is arithmetic in a finite cyclic **group**. Cards are not group elements, so the
very first thing the protocol needs is a fixed, public, agreed-upon map:

```
Card  ⇄  group element (a point on the Pallas curve)
```

The map must be a **bijection**: every card gets its own point, no two cards
collide, and you can go back from a point to the card. Barnett–Smart's original
paper calls these the 52 "plaintext messages" `m₁ … m₅₂`.

The elegant way to get 52 guaranteed-distinct points is to use the generator
`G` of a prime-order group. Because the group has prime order, the multiples
`1·G, 2·G, …, 52·G` are all different. So the card at index `i` of the canonical
deck maps to `G·(i + 1)`. (Why `+1`? See the hints.)

This stage has **no encryption yet** — it is pure encoding. But it sets up the
data type that stages 2–4 all operate on.

## Your challenge

Edit `exercise/src/lib.rs` and implement the three functions marked `todo!()`:

| Function | What it must do |
|----------|-----------------|
| `point_for_index(i)` | Return the fixed point for deck index `i`: `G·(i + 1)`. |
| `encode_point(card)` | Look up the card's index, return its point. |
| `decode_point(point)` | Reverse the map; `None` if the point is not a card. |

The lookup tables (`decode_table`, `index_table`) and the point→bytes helper
(`point_key`) are **provided** — they start working as soon as your three
functions are correct.

### Run it

```bash
cd exercise
cargo test          # 3 tests: start red, finish green
```

You are done when `all_52_cards_round_trip`, `all_52_encodings_are_distinct`,
and `identity_is_not_a_card` all pass.

## Hints

<details>
<summary>How do I make a point from an integer?</summary>

`Projective::generator()` gives you `G`. Scalar multiplication is just `*`, but
the scalar must be a field element: `Fr::from(n)` converts a `u64`. So
`Projective::generator() * Fr::from(7u64)` is `7·G`.
</details>

<details>
<summary>Why <code>i + 1</code> instead of <code>i</code>?</summary>

Index `0` would give `0·G`, which is the group's **identity element** (the
"point at infinity"). The identity is a degenerate point that shows up elsewhere
in the protocol (a trivially-encrypted card uses it). Shifting every card by one
guarantees all 52 encodings are non-identity points — which is exactly what
`identity_is_not_a_card` checks.
</details>

<details>
<summary>Why can't I just use a <code>HashMap&lt;Projective, Card&gt;</code>?</summary>

Curve points don't implement `Hash`. The provided `point_key` serializes a point
to its **canonical compressed bytes**, and the tables are keyed on those. Your
`decode_point` should key the incoming point the same way before looking it up.
</details>

<details>
<summary>Full solution</summary>

See [`solution/`](solution/) and its [`SOLUTION.md`](solution/SOLUTION.md).
</details>

## Where this lives in the real codebase

[`pkmental/src/encode.rs`](https://github.com/ImperialBower/pkmental/blob/main/src/encode.rs). The real version is identical
except it uses `pkcore`'s production `Card` (a Cactus-Kev `u32`); the encoding
depends only on the card's *index* in `DECK_ARRAY`, so the simplified card here
behaves the same.

➡️ **Next:** [Stage 2 — Sigma proofs](../stage-2-sigma/), where you prove you
know a secret without revealing it.
