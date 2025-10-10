use std::fs;

use serde::Deserialize;
use tokio::{net::TcpListener, signal};

use axum::Router;
use axum::routing::get;
use tracing::{info, warn};
use voice::open_db;

#[derive(Deserialize, Debug)]
struct AppConfig<'c> {
    database_url: &'c str,
    database_name: &'c str,
    host: &'c str,
    port: u16,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt().init();

    // Read the file content into a string
    let json_content = fs::read_to_string("config.json")?;

    // Deserialize the JSON string into your AppConfig struct
    let config: AppConfig = serde_json::from_str(&json_content)?;
    let db = open_db(config.database_url, config.database_name).await?;
    let app = Router::new()
        .route("/", get(|| async { "Hello 🚀" }))
        .with_state(db);
    let addr =
        TcpListener::bind(format!("{}:{}", config.host, config.port)).await?;

    info!("listing on port {}", config.port);
    // Serve with graceful shutdown
    axum::serve(addr, app.into_make_service())
        .with_graceful_shutdown(shutdown_signal())
        .await
        .unwrap();
    info!("Server exited gracefully");
    Ok(())
}

async fn shutdown_signal() {
    warn!("shutting down the server");
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
