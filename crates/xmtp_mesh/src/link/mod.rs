//! Private discovery and Noise links (DESIGN.md §B14): keys derived from
//! the account key, rotating advert tokens, Noise handshakes and sealed
//! records.
pub mod keys;

pub use keys::{
    ADVERT_LEN, ADVERT_VERSION, FLAG_PAIRING, FLAG_RELAY, TOKEN_LEN, Token, WINDOW_SECS,
    advert_token, parse_service_data, service_data, window_at,
};
