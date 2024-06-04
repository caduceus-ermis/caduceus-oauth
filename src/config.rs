use clap::Parser;
use log::LevelFilter;
use openidconnect::url::Url;

#[derive(Clone, Parser)]
pub struct Config {
    #[arg(
        long,
        env = "EM_ISSUER_URL",
        value_parser = Url::parse,
        default_value = "http://localhost:5173",
        help = "URL to be used as issuer in JWT token"
    )]
    pub issuer_url: Url,

    #[arg(
        long,
        env = "EM_CLIENT_ID",
        default_value = "client_id",
        help = "OIDC client id, shared with client application"
    )]
    pub client_id: String,

    #[arg(
        long,
        env = "EM_CLIENT_SECRET",
        default_value = "client_secret",
        help = "OIDC client secret, shared with client application to perform HMAC JWT validation"
    )]
    pub client_secret: String,

    #[arg(
        long,
        env = "EM_CLIENT_ORIGIN_URL",
        default_value = "http://localhost:5173",
        help = "Url from which client requests will come, used to set CORS header"
    )]
    pub client_origin_url: String,

    #[arg(
        long,
        env = "EM_LISTEN_PORT",
        default_value_t = 8080,
        help = "REST API listen port"
    )]
    pub listen_port: u16,

    #[arg(
        long,
        env = "EM_DB_HOST",
        default_value = "localhost",
        help = "Database host"
    )]
    pub db_host: String,

    #[arg(
        long,
        env = "EM_DB_PORT",
        default_value_t = 5432,
        help = "Database port"
    )]
    pub db_port: u16,

    #[arg(
        long,
        env = "EM_DB_NAME",
        default_value = "ermis-login",
        help = "Database name"
    )]
    pub db_name: String,

    #[arg(
        long,
        env = "EM_DB_USER",
        default_value = "ermis-login",
        help = "Database user"
    )]
    pub db_user: String,

    #[arg(
        long,
        env = "EM_DB_PASSWORD",
        default_value = "",
        help = "Database password"
    )]
    pub db_password: String,

    #[arg(long, env = "EM_LOG_LEVEL", default_value_t = LevelFilter::Info, help = "Log level")]
    pub log_level: LevelFilter,

    #[arg(
        long,
        env = "TOKEN_TIMEOUT",
        default_value_t = 60 * 2 * 1000,
        help = "Token timeout"
    )]
    pub token_timeout: u32,

    #[arg(
        long,
        env = "REFRESH_TOKEN_TIMEOUT",
        default_value_t = 3600 * 24,
        help = "Refresh token timeout"
    )]
    pub refresh_token_timeout: u32,

    #[arg(
        long,
        env = "APPLE_CLIENT_SECRET",
        default_value = "apple_client_secret",
        help = "Client secret for Apple login"
    )]
    pub apple_client_secret: String,
}
