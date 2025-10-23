use std::sync::Arc;

use axum::{Router, routing::post};

use crate::{
    AppState, controllers::auth::jwt::jwt_register,
};

pub mod jwt;

pub fn create_auth_router(
    state: Arc<AppState>,
) -> Router<Arc<AppState>> {
    Router::new()
        .route("/jwt/register", post(jwt_register))
        .with_state(state)
}
