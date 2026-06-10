# ibkatas

ImperialBower's collection of hands-on **coding katas**. Each kata is a
self-contained, test-driven exercise — or a series of them — that teaches a core
technique by handing you stubbed functions and a failing test suite. You make the
tests pass; a reference solution and a written walkthrough are included.

Every kata in this repo lives in its own top-level section directory and is fully
self-contained (its own build, its own tests, its own README), so you can work
any one of them without touching the others.

## Katas

### 1. [Barnett–Smart Mental Poker](barnett-smart-kata/) · Rust

A four-stage TDD series that rebuilds the cryptographic engine behind
**trustless, serverless mental poker** (playing cards fairly with no trusted
dealer). You build it one layer at a time:

| Stage | Concept |
|-------|---------|
| [1 — Encode](barnett-smart-kata/stage-1-encode/) | cards ⇄ distinct curve points |
| [2 — Sigma](barnett-smart-kata/stage-2-sigma/) | Schnorr + Chaum–Pedersen proofs, Fiat–Shamir |
| [3 — ElGamal](barnett-smart-kata/stage-3-elgamal/) | threshold masking & reveal tokens |
| [4 — Shuffle](barnett-smart-kata/stage-4-shuffle/) | cut-and-choose verifiable shuffle |

A Cargo workspace (Rust, edition 2024). Derived from the
[`pkmental`](https://github.com/ImperialBower/pkmental) crate.
➡️ Start at [`barnett-smart-kata/README.md`](barnett-smart-kata/README.md).

<!-- Add new katas here as new sections. -->

## Repository layout

```
ibkatas/
├── README.md              ← this index
└── <kata>-kata/           ← one self-contained section per kata
    ├── README.md          ← that kata's overview, challenge, and hints
    └── …                  ← its own project(s), tests, and solution
```

## Running a kata

Each section's README has the exact commands, but the shape is always: open the
exercise, run the tests, watch them fail, implement until they pass. For the Rust
katas:

```bash
cd barnett-smart-kata/stage-1-encode/exercise
cargo test          # starts red; make it green
```

## Contributing a kata

Add a new top-level `<name>-kata/` directory containing a self-contained exercise
(stubbed code + failing tests), a `solution/` with the reference implementation
and a walkthrough, and a `README.md` that teaches the concept from first
principles. Then add a section for it to this index.
