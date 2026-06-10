//! Provided working context — the solved **stage 1** card encoding.
//!
//! `encode_point` maps a card to its fixed curve point `G·(i + 1)`;
//! `decode_point` inverts the map (or returns `None` for a non-card point).

use std::collections::HashMap;
use std::sync::OnceLock;

use ark_ec::PrimeGroup;
use ark_pallas::{Fr, Projective};
use ark_serialize::CanonicalSerialize;

use crate::card::{Card, DECK_ARRAY};

fn point_key(p: &Projective) -> Vec<u8> {
    let mut bytes = Vec::new();
    p.serialize_compressed(&mut bytes)
        .expect("Pallas point serialization is infallible");
    bytes
}

fn point_for_index(i: usize) -> Projective {
    Projective::generator() * Fr::from((i as u64) + 1)
}

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
