use actix_web::{
    http::{header::ContentType, StatusCode},
    HttpResponse, ResponseError,
};
use openidconnect::JsonWebTokenError;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum ApiError {
    #[error("sqlx error")]
    Sqlx(#[from] sqlx::Error),
    #[error("wallet not found")]
    WalletNotFound,
    #[error("refresh token not found")]
    TokenNotFound,
    #[error("signature incorrect")]
    SignatureIncorrect,
    #[error("signing error")]
    SigningError(#[from] JsonWebTokenError),
    #[error("reqwest error")]
    Reqwest(#[from] reqwest::Error),
}

impl ApiError {
    pub fn code(&self) -> &str {
        match self {
            Self::Sqlx(_) => "DB",
            Self::WalletNotFound => "WalletNotFound",
            Self::SignatureIncorrect => "SignatureIncorrect",
            Self::SigningError(_) => "SigningError",
            Self::TokenNotFound => "TokenNotFound",
            Self::Reqwest(_) => "ReqwestError",
        }
    }

    pub fn message(&self) -> String {
        match self {
            Self::Sqlx(_) => String::from("Internal error"),
            Self::WalletNotFound => String::from("Wallet not found"),
            Self::SignatureIncorrect => String::from("Signature incorrect"),
            Self::SigningError(_) => String::from("Signing error"),
            Self::TokenNotFound => String::from("Refresh token not found"),
            Self::Reqwest(_) => String::from("Reqwest error"),
        }
    }
}

#[derive(Serialize)]
struct ErrorInfo {
    error: String,
    message: String,
}

impl From<&ApiError> for ErrorInfo {
    fn from(api_error: &ApiError) -> Self {
        Self {
            error: api_error.code().into(),
            message: api_error.message(),
        }
    }
}

impl ResponseError for ApiError {
    /// Return error as JSON.
    fn error_response(&self) -> HttpResponse {
        HttpResponse::build(self.status_code())
            .insert_header(ContentType::json())
            .json(ErrorInfo::from(self))
    }

    fn status_code(&self) -> StatusCode {
        match self {
            Self::Sqlx(_) => StatusCode::INTERNAL_SERVER_ERROR,
            ApiError::WalletNotFound
            | ApiError::SignatureIncorrect
            | ApiError::SigningError(_)
            | ApiError::TokenNotFound => StatusCode::UNAUTHORIZED,
            ApiError::Reqwest(_) => StatusCode::INTERNAL_SERVER_ERROR,
        }
    }
}

#[derive(Debug, Error)]
pub enum Web3Error {
    #[error("hex decoding error")]
    Decode,
    #[error("invalid message")]
    InvalidMessage,
    #[error("invalid recovery id")]
    InvalidRecoveryId,
    #[error("error parsing signature")]
    ParseSignature,
    #[error("recovery error")]
    Recovery,
    #[error("error verifying address")]
    VerifyAddress,
}

#[derive(Debug, Error, PartialEq)]
pub enum HexError {
    #[error("Invalid character {0}")]
    InvalidCharacter(u8),
    #[error("Invalid string length {0}")]
    InvalidStringLength(usize),
}

use std::error::Error;
use std::fmt;

use jsonwebtoken::errors::Error as JwtError;
use reqwest::Error as ReqwestError;

/// A network, validation or decoding error
#[non_exhaustive]
#[derive(Debug)]
pub enum GoogleJwtError {
    /// The JWK id in the provided identity token has no counterpart in <https://appleid.apple.com/auth/keys>
    MissingJwk(String),
    /// The JWK header is missing the key id field (kid)
    MissingKeyId,
    /// Error from the [jsonwebtoken] crate
    JwtError(JwtError),
    /// Error from the [reqwest] crate. Can occur when fetching keys from <https://appleid.apple.com/auth/keys>
    HttpError(ReqwestError),
}

impl Error for GoogleJwtError {}

impl fmt::Display for GoogleJwtError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Self::MissingJwk(kid) => {
                write!(
                    f,
                    "JSON Web Key id '{}' missing in {}",
                    kid,
                    crate::KEYS_URL
                )
            }
            Self::MissingKeyId => {
                f.write_str("Identity token header is missing key id (kid) field")
            }
            Self::JwtError(e) => e.fmt(f),
            Self::HttpError(e) => e.fmt(f),
        }
    }
}

impl From<JwtError> for GoogleJwtError {
    fn from(value: JwtError) -> Self {
        Self::JwtError(value)
    }
}

impl From<ReqwestError> for GoogleJwtError {
    fn from(value: ReqwestError) -> Self {
        Self::HttpError(value)
    }
}
