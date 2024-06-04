use crate::error::GoogleJwtError;
use jsonwebtoken::{errors::ErrorKind, jwk::JwkSet, Algorithm, DecodingKey, Validation};
#[derive(Clone, Debug)]
pub struct GoogleJwtClient {
    keyset_cache: Option<JwkSet>,
    validation: Validation,
}
#[derive(Debug, Deserialize, Serialize)]
pub struct IdInfo<EF = bool, TM = u64> {
    /// These six fields are included in all Google ID Tokens.
    pub iss: String,
    pub sub: String,
    pub azp: String,
    pub aud: String,
    pub iat: TM,
    pub exp: TM,

    /// This value indicates the user belongs to a Google Hosted Domain
    pub hd: Option<String>,

    /// These seven fields are only included when the user has granted the "profile" and
    /// "email" OAuth scopes to the application.
    pub email: Option<String>,
    pub email_verified: Option<EF>, // eg. "true" (but unusually as a string)
    pub name: Option<String>,
    pub picture: Option<String>,
    pub given_name: Option<String>,
    pub family_name: Option<String>,
    pub locale: Option<String>,
}

impl GoogleJwtClient {
    pub fn new<T: ToString>(app_bundle_ids: &[T]) -> Self {
        let mut validation = Validation::new(Algorithm::RS256);
        validation.set_audience(app_bundle_ids);
        validation.set_issuer(&["https://accounts.google.com"]);
        validation.set_required_spec_claims(&["exp", "sub", "iss", "aud"]);

        Self {
            keyset_cache: None,
            validation,
        }
    }

    /// Validate and decode apple identity JWT
    pub async fn decode(&mut self, identity_token: &str) -> Result<IdInfo, GoogleJwtError> {
        let header = jsonwebtoken::decode_header(identity_token)?;

        let Some(key_id) = header.kid else {
            return Err(GoogleJwtError::MissingKeyId);
        };

        let mut res;

        loop {
            let (just_loaded, keyset) = self.take_cached_keyset().await?;

            res = Self::try_decode(&key_id, &keyset, identity_token, &self.validation);

            let is_keyset_error = match res {
                Err(ref e) => match e {
                    GoogleJwtError::MissingJwk(_) => true,
                    GoogleJwtError::JwtError(e) => matches!(
                        e.kind(),
                        ErrorKind::InvalidEcdsaKey
                            | ErrorKind::InvalidRsaKey(_)
                            | ErrorKind::InvalidAlgorithmName
                            | ErrorKind::InvalidKeyFormat
                    ),
                    _ => false,
                },
                _ => false,
            };

            if just_loaded || res.is_ok() || !is_keyset_error {
                self.keyset_cache = Some(keyset);

                break;
            }
        }

        res
    }

    fn try_decode(
        kid: &str,
        keyset: &JwkSet,
        token: &str,
        validation: &Validation,
    ) -> Result<IdInfo, GoogleJwtError> {
        let Some(jwk) = keyset.find(kid) else {
            return Err(GoogleJwtError::MissingJwk(kid.to_string()));
        };

        let key = DecodingKey::from_jwk(jwk)?;

        let token = jsonwebtoken::decode::<IdInfo>(token, &key, validation)?;

        Ok(token.claims)
    }

    async fn take_cached_keyset(&mut self) -> Result<(bool, JwkSet), GoogleJwtError> {
        if let Some(keyset) = self.keyset_cache.take() {
            return Ok((false, keyset));
        }

        let keyset = reqwest::get(crate::KEYS_URL)
            .await?
            .json::<JwkSet>()
            .await?;
        println!("keyset: {:?}", keyset);

        Ok((true, keyset))
    }
}
