use std::sync::Arc;

use axum::Router;

use crate::{
    AppState, controllers::auth::create_auth_router,
};

pub fn create_api_router(
    state: Arc<AppState>,
) -> Router<Arc<AppState>> {
    Router::new()
        .with_state(state.clone())
        .nest("/auth", create_auth_router(state))
}
