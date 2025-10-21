use axum::response::IntoResponse;
use axum::routing::get;
use axum::{Router, extract::State};
use std::{env, error, fs, sync::Arc};

use dotenv::dotenv;
use sea_orm::DatabaseConnection;
use serde::Deserialize;
use tokio::{net::TcpListener, signal};
use tracing::info;

pub mod entities;
pub mod utils;

#[derive(Debug, Clone)]
pub struct AppState {
    db: DatabaseConnection,
}

async fn create_router(
    config: Arc<AppConfig<'_>>,
) -> Result<Router, Box<dyn error::Error>> {
    let state = Arc::new(AppState {
        db: utils::open_db(config.database_url, config.database_name).await?,
    });
    Ok(Router::new()
        .route("/", get(|| async { "Hello 🚀" }))
        .route("/_ping", get(ping_get))
        .with_state(state))
}

async fn ping_get(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    match state.db.ping().await {
        Ok(_) => "Healthy".to_string(),
        Err(err) => err.to_string(),
    }
}

#[derive(Deserialize, Debug, Clone)]
struct AppConfig<'c> {
    database_url: &'c str,
    database_name: &'c str,
    host: &'c str,
    port: u16,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let _ = dotenv().unwrap();
    tracing_subscriber::fmt().init();

    let db_url_var = env::var("DATABASE_URL")?;
    let db_name_var = env::var("DATABASE_NAME")?;
    // Read the file content into a string
    let yaml_string = fs::read_to_string("config.yml")?;
    let yml_config = yaml_string
        .replace("${DATABASE_URL}", &db_url_var)
        .replace("${DATABASE_NAME}", &db_name_var);
    // Deserialize the JSON string into your AppConfig struct
    let config: AppConfig = serde_yaml::from_str(yml_config.as_str())?;
    // Deserialize the JSON string into your AppConfig struct
    let config = Arc::new(config);
    let app = create_router(config.clone()).await?;
    let addr =
        TcpListener::bind(format!("{}:{}", config.host, config.port)).await?;

    info!("listing on port {}", config.port);
    // Serve with graceful shutdown
    axum::serve(addr, app.into_make_service())
        .with_graceful_shutdown(shutdown_signal())
        .await?;
    info!("Server exited gracefully");
    Ok(())
}

async fn shutdown_signal() {
    let ctrl_c = async {
        tokio::signal::ctrl_c()
            .await
            .expect("failed to install Ctrl+C handler");
    };

    #[cfg(unix)]
    let terminate = async {
        signal::unix::signal(signal::unix::SignalKind::terminate())
            .expect("failed to install signal handler")
            .recv()
            .await;
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => {},
        _ = terminate => {},
    }
}
