//! A minimal stand-in for `pkcore`'s `Card`.
//!
//! The real `pkcore::card::Card` is a Cactus-Kev `u32` bit-encoding tuned for
//! fast poker-hand evaluation. The mental-poker layer never inspects those bits
//! — it only needs **52 distinct cards in a fixed order**. So here a `Card` is a
//! plain rank + suit pair, and [`DECK_ARRAY`] lists the 52 cards in the same
//! order `pkcore` uses (spades A→2, then hearts, diamonds, clubs).
//!
//! The card → curve-point encoding depends only on a card's *index* in
//! `DECK_ARRAY`, so this simplification is faithful to what the crypto observes.

/// Card rank, high to low.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Rank {
    Ace,
    King,
    Queen,
    Jack,
    Ten,
    Nine,
    Eight,
    Seven,
    Six,
    Five,
    Four,
    Trey,
    Deuce,
}

/// Card suit.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Suit {
    Spades,
    Hearts,
    Diamonds,
    Clubs,
}

/// A single playing card.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Card {
    pub rank: Rank,
    pub suit: Suit,
}

/// The canonical 52-card deck, in `pkcore`'s ordering.
pub const DECK_ARRAY: [Card; 52] = [
    Card { rank: Rank::Ace, suit: Suit::Spades },
    Card { rank: Rank::King, suit: Suit::Spades },
    Card { rank: Rank::Queen, suit: Suit::Spades },
    Card { rank: Rank::Jack, suit: Suit::Spades },
    Card { rank: Rank::Ten, suit: Suit::Spades },
    Card { rank: Rank::Nine, suit: Suit::Spades },
    Card { rank: Rank::Eight, suit: Suit::Spades },
    Card { rank: Rank::Seven, suit: Suit::Spades },
    Card { rank: Rank::Six, suit: Suit::Spades },
    Card { rank: Rank::Five, suit: Suit::Spades },
    Card { rank: Rank::Four, suit: Suit::Spades },
    Card { rank: Rank::Trey, suit: Suit::Spades },
    Card { rank: Rank::Deuce, suit: Suit::Spades },
    Card { rank: Rank::Ace, suit: Suit::Hearts },
    Card { rank: Rank::King, suit: Suit::Hearts },
    Card { rank: Rank::Queen, suit: Suit::Hearts },
    Card { rank: Rank::Jack, suit: Suit::Hearts },
    Card { rank: Rank::Ten, suit: Suit::Hearts },
    Card { rank: Rank::Nine, suit: Suit::Hearts },
    Card { rank: Rank::Eight, suit: Suit::Hearts },
    Card { rank: Rank::Seven, suit: Suit::Hearts },
    Card { rank: Rank::Six, suit: Suit::Hearts },
    Card { rank: Rank::Five, suit: Suit::Hearts },
    Card { rank: Rank::Four, suit: Suit::Hearts },
    Card { rank: Rank::Trey, suit: Suit::Hearts },
    Card { rank: Rank::Deuce, suit: Suit::Hearts },
    Card { rank: Rank::Ace, suit: Suit::Diamonds },
    Card { rank: Rank::King, suit: Suit::Diamonds },
    Card { rank: Rank::Queen, suit: Suit::Diamonds },
    Card { rank: Rank::Jack, suit: Suit::Diamonds },
    Card { rank: Rank::Ten, suit: Suit::Diamonds },
    Card { rank: Rank::Nine, suit: Suit::Diamonds },
    Card { rank: Rank::Eight, suit: Suit::Diamonds },
    Card { rank: Rank::Seven, suit: Suit::Diamonds },
    Card { rank: Rank::Six, suit: Suit::Diamonds },
    Card { rank: Rank::Five, suit: Suit::Diamonds },
    Card { rank: Rank::Four, suit: Suit::Diamonds },
    Card { rank: Rank::Trey, suit: Suit::Diamonds },
    Card { rank: Rank::Deuce, suit: Suit::Diamonds },
    Card { rank: Rank::Ace, suit: Suit::Clubs },
    Card { rank: Rank::King, suit: Suit::Clubs },
    Card { rank: Rank::Queen, suit: Suit::Clubs },
    Card { rank: Rank::Jack, suit: Suit::Clubs },
    Card { rank: Rank::Ten, suit: Suit::Clubs },
    Card { rank: Rank::Nine, suit: Suit::Clubs },
    Card { rank: Rank::Eight, suit: Suit::Clubs },
    Card { rank: Rank::Seven, suit: Suit::Clubs },
    Card { rank: Rank::Six, suit: Suit::Clubs },
    Card { rank: Rank::Five, suit: Suit::Clubs },
    Card { rank: Rank::Four, suit: Suit::Clubs },
    Card { rank: Rank::Trey, suit: Suit::Clubs },
    Card { rank: Rank::Deuce, suit: Suit::Clubs },
];
