use authintic::{
    app::AppContext, controllers::api::create_api_router,
    Config,
};
use axum::{
    Router, extract::State, response::IntoResponse,
    routing::get,
};
use std::{error, sync::Arc};

use dotenv::dotenv;
use sea_orm::DatabaseConnection;
use tokio::{net::TcpListener, signal};
use tracing::info;

async fn create_router(
    ctx: AppContext
) -> Result<Router, Box<dyn error::Error>> {
    let state = Arc::new(ctx);
    Ok(Router::new()
        .route("/", get(|| async { "Hello 🚀" }))
        .route("/_ping", get(ping_get))
        .nest("/api", create_api_router(state.clone()))
        .with_state(state))
}

async fn ping_get(
    State(state): State<Arc<AppContext>>
) -> impl IntoResponse {
    match state.db.ping().await {
        Ok(_) => "Healthy".to_string(),
        Err(err) => err.to_string(),
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let _ = dotenv().unwrap();
    tracing_subscriber::fmt().init();

    let mut ctx = AppContext {
        config: Config::new("config.yml")?,
        db: DatabaseConnection::Disconnected,
    };
    ctx.open_db_connection().await?;
    let con = ctx.config.clone();

    let app = create_router(ctx).await?;
    let addr = TcpListener::bind(format!(
        "{}:{}",
        con.host, con.port
    ))
    .await?;

    info!("listing on port {}", con.port);
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
        signal::unix::signal(
            signal::unix::SignalKind::terminate(),
        )
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
