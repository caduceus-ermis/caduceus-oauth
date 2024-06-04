use actix_web::{
    get, post,
    web::{self, Json},
};
use apple_signin::AppleJwtClient;
use chrono::{Duration, Utc};

use jsonwebtoken::{EncodingKey, Header};
use openidconnect::{
    core::{
        CoreGenderClaim, CoreHmacKey, CoreIdToken, CoreIdTokenClaims, CoreJsonWebKeyType,
        CoreJweContentEncryptionAlgorithm, CoreJwsSigningAlgorithm, CoreRsaPrivateSigningKey,
    },
    url::Url,
    Audience, EmptyAdditionalClaims, IdToken, IssuerUrl, JsonWebTokenError, Nonce, StandardClaims,
    SubjectIdentifier,
};

use sqlx::query_as;

use crate::{
    db::{RefreshToken, Wallet},
    error::ApiError,
    google::GoogleJwtClient,
    state::AppState,
};

#[derive(Serialize, Deserialize)]
pub struct Challenge {
    pub challenge: String,
}

#[derive(Serialize, Deserialize)]
pub struct WalletAddress {
    pub address: String,
}

#[derive(Serialize, Deserialize)]
pub struct WalletSignature {
    pub address: String,
    pub signature: String,
    pub nonce: String,
}

#[derive(Serialize, Deserialize)]
pub struct JwtToken {
    pub token: String,
    pub refresh_token: String,
}

#[derive(Serialize, Deserialize)]
pub struct RefreshTokenRequest {
    pub refresh_token: String,
}

#[derive(Serialize, Deserialize)]
struct TokenForm {
    token: String,
}
#[derive(Serialize, Deserialize, PartialEq, Debug, Clone)]
pub struct GoogleUser {
    pub sub: String,
    pub email: String,
    pub name: String,
    pub given_name: String,
    pub family_name: String,
    pub picture: String,
    pub locale: String,
}

/// Simple HTTP server health check.
#[get("/api/health")]
async fn health_check() -> &'static str {
    "alive"
}

// List wallets
#[get("/api/wallet")]
async fn list_wallets(app_state: web::Data<AppState>) -> Result<Json<Vec<Wallet>>, ApiError> {
    let wallets = query_as!(
        Wallet,
        "SELECT id \"id?\", address, challenge_message, challenge_signature, creation_timestamp, validation_timestamp FROM wallet"
    ).fetch_all(&app_state.pool).await?;
    Ok(Json(wallets))
}

/// Start Web3 authentication. Returns challenge message for specified wallet address.
#[post("/auth/start")]
pub async fn web3auth_start(
    app_state: web::Data<AppState>,
    data: Json<WalletAddress>,
) -> Result<Json<Challenge>, ApiError> {
    // Create wallet if it does not exist yet
    let address = data.into_inner().address.to_lowercase();
    let mut wallet =
        if let Some(wallet) = Wallet::find_by_address(&app_state.pool, &address).await? {
            wallet
        } else {
            let mut wallet = Wallet::new(address);
            wallet.save(&app_state.pool).await?;
            wallet
        };
    wallet.save(&app_state.pool).await?;
    Ok(Json(Challenge {
        challenge: wallet.challenge_message,
    }))
}

#[derive(Serialize, Deserialize)]
pub struct ErmisTokenClaims {
    pub user_id: String,
    pub exp: i64,
}

fn ermis_token(user_id: String, token_expiration: u32, client_secret: String) -> String {
    let issue_time = Utc::now().timestamp_millis();
    let expiration = issue_time + token_expiration as i64;

    let claims = ErmisTokenClaims {
        user_id,
        exp: expiration,
    };
    let token = jsonwebtoken::encode(
        &jsonwebtoken::Header::default(),
        &claims,
        &EncodingKey::from_secret(client_secret.as_ref()),
    )
    .unwrap();
    token
}

/// Creates OIDC id token for given wallet
fn issue_id_token<T>(
    wallet_address: &str,
    base_url: &Url,
    secret: T,
    rsa_key: Option<CoreRsaPrivateSigningKey>,
    nonce: &str,
    client_id: &str,
    token_expiration: u32,
) -> Result<
    IdToken<
        EmptyAdditionalClaims,
        CoreGenderClaim,
        CoreJweContentEncryptionAlgorithm,
        CoreJwsSigningAlgorithm,
        CoreJsonWebKeyType,
    >,
    JsonWebTokenError,
>
where
    T: Into<Vec<u8>>,
{
    let wallet_address = wallet_address.to_lowercase();
    let issue_time = Utc::now();
    let expiration = issue_time + Duration::seconds(token_expiration.into());
    let claims = StandardClaims::new(SubjectIdentifier::new(wallet_address));
    let id_token_claims = CoreIdTokenClaims::new(
        IssuerUrl::from_url(base_url.clone()),
        vec![Audience::new(client_id.to_string())],
        expiration,
        issue_time,
        claims,
        openidconnect::EmptyAdditionalClaims {},
    )
    .set_nonce(Some(Nonce::new(nonce.to_string())));

    match rsa_key {
        // RSA flow
        Some(key) => CoreIdToken::new(
            id_token_claims,
            &key,
            CoreJwsSigningAlgorithm::RsaSsaPkcs1V15Sha256,
            None,
            None,
        ),
        // HMAC flow
        None => CoreIdToken::new(
            id_token_claims,
            &CoreHmacKey::new(secret),
            CoreJwsSigningAlgorithm::HmacSha256,
            None,
            None,
        ),
    }
}

/// Finish Web3 authentication. Verifies signature and returns OIDC id_token if correct.
#[post("/auth")]
pub async fn web3auth_end(
    app_state: web::Data<AppState>,
    signature: Json<WalletSignature>,
) -> Result<Json<JwtToken>, ApiError> {
    let address = signature.address.to_lowercase();
    let Some(mut wallet) = Wallet::find_by_address(&app_state.pool, &address).await? else {
        return Err(ApiError::WalletNotFound);
    };
    match wallet.verify_address(&wallet.challenge_message, &signature.signature) {
        Ok(true) => {
            let id_token = ermis_token(
                address,
                app_state.config.token_timeout,
                app_state.config.client_secret.clone(),
            );
            wallet.challenge_signature = Some(signature.signature.clone());
            wallet.save(&app_state.pool).await?;
            if let Some(wallet_id) = wallet.id {
                let mut refresh_token =
                    RefreshToken::new(wallet_id, app_state.config.refresh_token_timeout);
                refresh_token.save(&app_state.pool).await?;
                Ok(Json(JwtToken {
                    token: id_token.to_string(),
                    refresh_token: refresh_token.token,
                }))
            } else {
                log::error!("Wallet with address: {} has no id", wallet.address);
                Err(ApiError::WalletNotFound)
            }
        }
        Err(_) => {
            return Err(ApiError::SignatureIncorrect);
        }
        _ => Err(ApiError::SignatureIncorrect),
    }
}

/// Issue new id token and refresh token set old as used
#[post("/refresh")]
pub async fn refresh(
    app_state: web::Data<AppState>,
    data: Json<RefreshTokenRequest>,
) -> Result<Json<JwtToken>, ApiError> {
    let refresh_token = data.into_inner().refresh_token;
    if let Ok(Some(mut refresh_token)) =
        RefreshToken::find_refresh_token(&app_state.pool, &refresh_token).await
    {
        log::debug!(
            "Refreshing token: {} for user with id: {}",
            refresh_token.token,
            refresh_token.wallet_id,
        );
        refresh_token.set_used(&app_state.pool).await?;
        let mut new_refresh_token = RefreshToken::new(
            refresh_token.wallet_id,
            app_state.config.refresh_token_timeout,
        );
        if let Some(wallet) = Wallet::find_by_id(&app_state.pool, refresh_token.wallet_id).await? {
            // Doesn't return nonce while refreshing token
            // https://openid.net/specs/openid-connect-core-1_0.html#RefreshTokenResponse
            // let id_token = issue_id_token(
            //     &wallet.address,
            //     &app_state.config.issuer_url,
            //     app_state.config.client_secret.clone(),
            //     None,
            //     "",
            //     &app_state.config.client_id,
            //     app_state.config.token_timeout,
            // )?;
            let id_token = ermis_token(
                wallet.address,
                app_state.config.token_timeout,
                app_state.config.client_secret.clone(),
            );
            new_refresh_token.save(&app_state.pool).await?;
            log::info!(
                "Issued new id_token and refresh token for user with id: {}",
                refresh_token.wallet_id,
            );
            Ok(Json(JwtToken {
                token: id_token.to_string(),
                refresh_token: new_refresh_token.token,
            }))
        } else {
            log::debug!(
                "Wallet with id: {} assigned to token: {} not found",
                refresh_token.wallet_id,
                refresh_token.token,
            );
            Err(ApiError::WalletNotFound)
        }
    } else {
        log::debug!("Refresh token: {} not found", refresh_token);
        Err(ApiError::TokenNotFound)
    }
}

// get token from app, verify it with apple, get email, check if email is in db, if not create new user
#[post("/auth/apple")]
async fn apple_auth(
    app_state: web::Data<AppState>,
    request_data: web::Json<TokenForm>,
) -> anyhow::Result<Json<TokenForm>, actix_web::Error> {
    let token = &request_data.token;

    let mut client = AppleJwtClient::new(&["com.tuyenvx.testloging"]);

    let payload = client.decode(token).await;
    match payload {
        Ok(payload) => {
            // let header = Header::new(Algorithm::RS256);
            let token = jsonwebtoken::encode(
                &Header::default(),
                &payload,
                &EncodingKey::from_secret(&app_state.config.client_secret.as_ref()),
            )
            .unwrap();
            let token = TokenForm { token };

            return Ok(Json(token));
        }
        Err(e) => return Err(actix_web::error::ErrorBadRequest(e.to_string())),
    }
}

#[post("/auth/google")]
pub async fn google_login(
    app_state: web::Data<AppState>,
    request_data: web::Json<TokenForm>,
) -> anyhow::Result<Json<TokenForm>, actix_web::Error> {
    let token = &request_data.token;

    let mut client = GoogleJwtClient::new(&[
        "189085125783-c038123hbeum42s6tsvd222kqmoite13.apps.googleusercontent.com",
    ]);

    let payload = client.decode(token).await;
    match payload {
        Ok(payload) => {
            // let header = Header::new(Algorithm::RS256);
            let token = jsonwebtoken::encode(
                &Header::default(),
                &payload,
                &EncodingKey::from_secret(&app_state.config.client_secret.as_ref()),
            )
            .unwrap();
            let token = TokenForm { token };

            return Ok(Json(token));
        }
        Err(e) => return Err(actix_web::error::ErrorBadRequest(e.to_string())),
    }
}

// pub async fn check_wallet_transactions(address: String) -> web3::Result<()> {
//     let transport = web3::transports::Http::new("http://localhost:8545")?;
//     let web3 = web3::Web3::new(transport);

//     println!("Calling accounts.");
//     let mut accounts = web3.eth().accounts().await?;
//     println!("Accounts: {:?}", accounts);
//     accounts.push(address.parse().unwrap());

//     println!("Calling balance.");
//     for account in accounts {
//         let balance = web3.eth().balance(account, None).await?;
//         println!("Balance of {:?}: {}", account, balance);
//     }

//     Ok(())
// }

/// Configure Actix Web server.
pub fn config_service(config: &mut web::ServiceConfig) {
    config
        .service(health_check)
        .service(list_wallets)
        .service(web3auth_start)
        .service(web3auth_end)
        .service(apple_auth)
        .service(google_login)
        .service(refresh);
}
