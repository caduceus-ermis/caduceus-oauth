mod config;
mod google;
pub use config::Config;
pub mod crypto;
pub mod db;
mod error;
mod http;
pub use http::{config_service, Challenge, JwtToken, WalletAddress, WalletSignature};
pub mod hex;
mod random;
pub mod state;

#[macro_use]
extern crate serde;

pub static CHALLENGE_TEMPLATE: &str = "Please read this carefully:

Click to sign to prove you are in possesion of your private key to the account.
This request will not trigger a blockchain transaction or cost any gas fees.";

pub static KEYS_URL: &str = "https://www.googleapis.com/oauth2/v3/certs";
