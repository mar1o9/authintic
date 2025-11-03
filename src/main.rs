use authintic::{
    app::{App, AppContext},
    bgworker::{worker_manager, Job},
    controllers::api::create_api_router,
};
use axum::{
    Router, extract::State, response::IntoResponse,
    routing::get,
};
use tokio::sync::mpsc;
use std::{error, sync::Arc};

use dotenv::dotenv;
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

    let mut ctx = AppContext::new().await;
    // start the background Worker
    let (tx, rx) = mpsc::channel::<Job>(100);
    tokio::spawn(worker_manager(rx));
    ctx.tx = Some(tx);
    let con = ctx.config.clone();

    let app = create_router(ctx).await?;
    App::serve(app, con.host, con.port).await?;
    info!("Server exited gracefully");
    Ok(())
}
