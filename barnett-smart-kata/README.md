# Barnett–Smart Mental Poker — a TDD kata series

> One section of the [**ibkatas**](../README.md) collection.

Rebuild, from scratch and test-first, the cryptographic engine behind
[`pkmental`](https://github.com/ImperialBower/pkmental): a **trustless, serverless mental-poker** card layer. "Mental
poker" is the problem of playing a fair card game with **no trusted dealer** —
no server deals the cards, yet nobody can cheat, peek, or duplicate a card. The
solution is a stack of elliptic-curve cryptography, and this kata has you build
it one layer at a time.

Each stage hands you a runnable Rust project with stubbed functions and a failing
test suite. You make the tests pass; the original `pkmental` implementation is
the reference solution. By the end you will have reconstructed the whole card
layer — and understand every cryptographic idea it rests on.

## How the stages relate

The stages form a strict bottom-up progression — each builds directly on the one
before, and each later stage *hands you the previous stage's solved code* as
working context:

```
Stage 1  Encode      cards  ⇄  curve points              (the data everything sits on)
   │
Stage 2  Sigma       prove you know a secret             (the trust machinery)
   │                 — Schnorr + Chaum–Pedersen, Fiat–Shamir
   │
Stage 3  ElGamal     threshold masking & reveal          (uses stage 1 + 2)
   │                 — "no card opens until everyone helps"
   │
Stage 4  Shuffle     prove an honest shuffle             (uses stage 1 + 2 + 3)
                     — cut-and-choose, zero-knowledge
```

| Stage | Concept | Real source | Self-contained? |
|-------|---------|-------------|-----------------|
| [1 — Encode](stage-1-encode/) | 52 cards ↔ 52 distinct points, `G·(i+1)` | [`src/encode.rs`](https://github.com/ImperialBower/pkmental/blob/main/src/encode.rs) | yes |
| [2 — Sigma](stage-2-sigma/) | Schnorr + DLEQ proofs via Fiat–Shamir | [`src/crypto/sigma.rs`](https://github.com/ImperialBower/pkmental/blob/main/src/crypto/sigma.rs) | yes |
| [3 — ElGamal](stage-3-elgamal/) | threshold masking, reveal tokens, unmask | [`src/crypto/elgamal.rs`](https://github.com/ImperialBower/pkmental/blob/main/src/crypto/elgamal.rs) | stages 1–2 provided |
| [4 — Shuffle](stage-4-shuffle/) | cut-and-choose verifiable shuffle | [`src/crypto/shuffle.rs`](https://github.com/ImperialBower/pkmental/blob/main/src/crypto/shuffle.rs) | stages 1–3 provided |

**Recommended order: 1 → 2 → 3 → 4.** Stages 1 and 2 are independent (do them in
either order), but 3 needs the ideas from both, and 4 needs all three. Each stage
is sized for roughly 45–90 minutes.

## How each stage works

```
stage-N-xxx/
├── README.md            ← concept from first principles + challenge + hints
├── exercise/            ← you work here; `cargo test` starts red
│   └── src/             ← stubbed target + provided working context modules
└── solution/
    ├── src/             ← the real pkmental implementation
    └── SOLUTION.md      ← walkthrough of the key insight
```

Work in `exercise/`:

```bash
cd stage-1-encode/exercise
cargo test          # watch it fail, implement the todo!()s, watch it pass
```

This is a single **Cargo workspace**: the eight stage crates share one `target/`
and one lockfile, so the arkworks dependencies compile only once. `cd`-ing into a
stage's `exercise/` and running `cargo test` builds just that crate. From the
repo root you can also run everything at once:

```bash
cargo build --workspace                 # compile all stages
cargo test  -p shuffle-kata-solution    # run one crate's tests by name
```

(Exercise crates are named `<concept>-kata`; solutions `<concept>-kata-solution`.
A bare `cargo test --workspace` will report the unsolved exercises as failing —
that is expected until you implement them.)

Stuck? Each stage README has a progressive hints section, and `solution/` has the
real code plus a written walkthrough. Peeking at `SOLUTION.md` after you finish is
worthwhile too — it explains *why* the construction is built the way it is.

## What you need

- A Rust toolchain (the projects use **edition 2024**, so Rust 1.94+).
- No network or external crates beyond [arkworks](https://arkworks.rs/)
  (elliptic-curve math), `sha2`, and `rand` — all pulled automatically by Cargo.
- No `pkcore` dependency: a minimal stand-in `Card` is vendored into each stage,
  faithful to what the crypto actually observes (see any stage's `src/card.rs`).

## The big picture

Put the four layers together and you get the real protocol:

1. **Setup** — every player runs `keygen` (stage 3) and proves key ownership with
   a Schnorr proof (stage 2). Shares aggregate into one public key `H`.
2. **Shuffle up** — the encoded deck (stage 1) is masked under `H`, then each
   player shuffles it in turn with a cut-and-choose proof (stage 4). After a full
   round, nobody knows where any card is.
3. **Deal & reveal** — to show a card to a player, everyone *else* sends a reveal
   token (stage 3); to open a community card, everyone does. The threshold
   property guarantees a card stays hidden until exactly the right people help.

Every step carries a zero-knowledge proof, so the whole game runs with no trusted
party and no opportunity to cheat. That is mental poker — and you built it.

### Where the full engine lives

The complete, production version is the [`pkmental`](https://github.com/ImperialBower/pkmental) crate. Beyond
the four crypto layers here, it adds a signed, hash-linked **event log**
(`src/event.rs`) and a **coordinator** (`src/coordinator/`) that sequences the
protocol across players — the transport and bookkeeping around the cryptography
you just rebuilt.
