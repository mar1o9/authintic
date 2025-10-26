use std::sync::Arc;

use axum::{
    routing::{post},
    Router,
};

use crate::{
    controllers::auth::jwt::{jwt_login, jwt_register},
    AppState,
};

pub mod jwt;

pub fn create_auth_router(
    state: Arc<AppState>
) -> Router<Arc<AppState>> {
    Router::new()
        .route("/jwt/register", post(jwt_register))
        .route("/jwt/login", post(jwt_login))
        .with_state(state)
}
