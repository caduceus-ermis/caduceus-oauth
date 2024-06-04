use std::net::{IpAddr, Ipv4Addr};

use actix_cors::Cors;
use actix_web::{middleware, web, App, HttpServer};
use anyhow::Result;
use ermis_login::{config_service, db::init_db, state::AppState, Config};
use clap::Parser;
use env_logger::Builder;

#[macro_use]
extern crate log;

// extern crate google_signin;

#[actix_web::main]
async fn main() -> Result<()> {
    let config = Config::parse();
    Builder::new().filter_level(config.log_level).init();
    info!("Ermis Login Service started.");

    // Initialize DB connection
    let pool = init_db(
        &config.db_host,
        config.db_port,
        &config.db_name,
        &config.db_user,
        &config.db_password,
    )
    .await;
    let listen_port = config.listen_port;
    HttpServer::new(move || {
        let cors = Cors::permissive();
        App::new()
            .app_data(web::Data::new(AppState::new(config.clone(), pool.clone())))
            .wrap(middleware::Logger::default())
            .wrap(cors)
            .configure(config_service)
    })
    .bind((IpAddr::V4(Ipv4Addr::UNSPECIFIED), listen_port))?
    .run()
    .await?;

    Ok(())
}
