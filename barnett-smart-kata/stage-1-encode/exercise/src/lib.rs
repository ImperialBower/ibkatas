//! Stage 1 — Encoding cards as curve points.
//!
//! Barnett–Smart mental poker represents the deck as 52 *fixed, public,
//! distinct* elements of an elliptic-curve group. Encryption then happens on
//! these points. Your job: build the bijection between a [`Card`] and its point.
//!
//! The scheme: the card at index `i` of [`DECK_ARRAY`] encodes to `G·(i + 1)`,
//! where `G` is the Pallas generator. Using `i + 1` (never `0`) keeps every
//! encoding a non-identity point. Decoding inverts the map with a lookup table.
//!
//! Implement the three functions marked `todo!()`. Run `cargo test`.

// The stubs below leave parameters and the provided helpers unused until you
// implement them. This keeps `cargo test` output focused on the failing tests;
// delete it once everything is wired up.
#![allow(unused_variables, unused_imports, dead_code)]

mod card;
pub use card::{Card, Rank, Suit, DECK_ARRAY};

use std::collections::HashMap;
use std::sync::OnceLock;

use ark_ec::PrimeGroup;
use ark_pallas::{Fr, Projective};
use ark_serialize::CanonicalSerialize;

/// Compressed serialization of a point, used as a hashable map key.
///
/// Provided for you: curve points are not `Hash`, so we key the lookup tables on
/// their canonical compressed byte form instead.
fn point_key(p: &Projective) -> Vec<u8> {
    let mut bytes = Vec::new();
    p.serialize_compressed(&mut bytes)
        .expect("Pallas point serialization is infallible");
    bytes
}

/// The plaintext group element for the card at `DECK_ARRAY` index `i` (`0..52`).
///
/// TODO(you): return the fixed group element for this index. Map index `i` to
/// `G·(i + 1)`, where `G` is [`Projective::generator()`]. The `+ 1` guarantees a
/// non-identity point (index `0` would otherwise encode to the identity).
fn point_for_index(i: usize) -> Projective {
    todo!("encode index i as G·(i + 1)")
}

/// `point compressed bytes → Card`, built once from `DECK_ARRAY`.
///
/// Provided for you: this memoizes the reverse table. It calls
/// `point_for_index`, so it starts working once you implement that.
fn decode_table() -> &'static HashMap<Vec<u8>, Card> {
    static TABLE: OnceLock<HashMap<Vec<u8>, Card>> = OnceLock::new();
    TABLE.get_or_init(|| {
        DECK_ARRAY
            .iter()
            .enumerate()
            .map(|(i, &card)| (point_key(&point_for_index(i)), card))
            .collect()
    })
}

/// `Card → DECK_ARRAY index`, built once. Provided for you.
fn index_table() -> &'static HashMap<Card, usize> {
    static TABLE: OnceLock<HashMap<Card, usize>> = OnceLock::new();
    TABLE.get_or_init(|| {
        DECK_ARRAY
            .iter()
            .enumerate()
            .map(|(i, &card)| (card, i))
            .collect()
    })
}

/// Encode a [`Card`] to its fixed plaintext group element.
///
/// TODO(you): find the card's index in `DECK_ARRAY` (use [`index_table`]) and
/// return the matching point via [`point_for_index`].
pub fn encode_point(card: Card) -> Projective {
    todo!("look up card's index, then point_for_index")
}

/// Recover the [`Card`] for a plaintext group element, or `None` if the point is
/// not one of the 52 card encodings.
///
/// TODO(you): key the point with [`point_key`] and look it up in
/// [`decode_table`].
pub fn decode_point(point: &Projective) -> Option<Card> {
    todo!("look up point_key(point) in decode_table")
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every card encodes to a point that decodes back to the same card.
    #[test]
    fn all_52_cards_round_trip() {
        for &card in DECK_ARRAY.iter() {
            let point = encode_point(card);
            assert_eq!(decode_point(&point), Some(card));
        }
    }

    /// No two cards share an encoding — a hard requirement for a usable deck.
    #[test]
    fn all_52_encodings_are_distinct() {
        let mut keys: Vec<Vec<u8>> = DECK_ARRAY
            .iter()
            .map(|&c| point_key(&encode_point(c)))
            .collect();
        keys.sort();
        keys.dedup();
        assert_eq!(
            keys.len(),
            52,
            "all 52 card encodings must be distinct points"
        );
    }

    /// The identity element is not a card encoding (that is why we use `i + 1`).
    #[test]
    fn identity_is_not_a_card() {
        assert_eq!(decode_point(&Projective::default()), None);
    }
}
