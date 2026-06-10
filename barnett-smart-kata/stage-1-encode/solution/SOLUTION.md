# Stage 1 — Solution walkthrough

## The key insight

Mental poker does its encryption on **group elements**, not on card structs. So
before anything cryptographic happens, every card must become a point on the
curve — and the map has to be a **bijection**: distinct cards → distinct points,
invertibly.

The trick is to lean on the discrete-log group's own structure. The Pallas
generator `G` has prime order, so the multiples

```
1·G, 2·G, 3·G, …, 52·G
```

are all distinct (you only repeat after the full group order, which is ~2²⁵⁴).
That hands us 52 distinct points for free. So we map the card at `DECK_ARRAY`
index `i` to:

```rust
fn point_for_index(i: usize) -> Projective {
    Projective::generator() * Fr::from((i as u64) + 1)
}
```

### Why `i + 1` and not `i`?

Index `0` would give `0·G = O`, the identity element. The identity is special —
it is the "empty" point and the trivial ElGamal encryption `(O, M)` uses it as
`c1`. Keeping every card encoding a *non-identity* point avoids that collision
and a class of degenerate cases. Shifting by one is the whole fix.

## Encode / decode

`encode_point` is a forward lookup (`Card → index → point`). `decode_point` is
the inverse, and here is the wrinkle: curve points do not implement `Hash`, so
you cannot use a `HashMap<Projective, Card>` directly. The provided `point_key`
serializes a point to its **canonical compressed bytes**, and we key the table
on those bytes instead. "Canonical" matters: two equal points must serialize
identically, or the lookup would miss.

`decode_point` returns `Option` — a point that is not one of the 52 encodings
returns `None`. That is not just defensive coding: in later stages, a card that
is only *partially* unmasked decodes to a non-card point, and that `None` is
exactly how the engine learns "not enough players have revealed yet."

## How the real version differs

In `pkmental` this lives in [`src/encode.rs`](https://github.com/ImperialBower/pkmental/blob/main/src/encode.rs). The only
difference is the `Card` type: the real `pkcore::card::Card` is a Cactus-Kev
`u32` bit-encoding for fast hand evaluation. The encoding logic is byte-identical
— it depends solely on a card's index in `DECK_ARRAY`, never on the card's
internal bits — so the minimal rank+suit `Card` here is faithful.
