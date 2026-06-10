//! Stage 1 — Encoding cards as curve points. **Reference solution.**

mod card;
pub use card::{Card, Rank, Suit, DECK_ARRAY};

use std::collections::HashMap;
use std::sync::OnceLock;

use ark_ec::PrimeGroup;
use ark_pallas::{Fr, Projective};
use ark_serialize::CanonicalSerialize;

/// Compressed serialization of a point, used as a hashable map key.
fn point_key(p: &Projective) -> Vec<u8> {
    let mut bytes = Vec::new();
    p.serialize_compressed(&mut bytes)
        .expect("Pallas point serialization is infallible");
    bytes
}

/// The plaintext group element for the card at `DECK_ARRAY` index `i` (`0..52`).
fn point_for_index(i: usize) -> Projective {
    Projective::generator() * Fr::from((i as u64) + 1)
}

/// `point compressed bytes → Card`, built once from `DECK_ARRAY`.
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

/// `Card → DECK_ARRAY index`, built once.
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
pub fn encode_point(card: Card) -> Projective {
    let i = index_table()
        .get(&card)
        .copied()
        .expect("every Card is in DECK_ARRAY");
    point_for_index(i)
}

/// Recover the [`Card`] for a plaintext group element, or `None`.
pub fn decode_point(point: &Projective) -> Option<Card> {
    decode_table().get(&point_key(point)).copied()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn all_52_cards_round_trip() {
        for &card in DECK_ARRAY.iter() {
            let point = encode_point(card);
            assert_eq!(decode_point(&point), Some(card));
        }
    }

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

    #[test]
    fn identity_is_not_a_card() {
        assert_eq!(decode_point(&Projective::default()), None);
    }
}
