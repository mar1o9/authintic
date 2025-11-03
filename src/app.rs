use axum::Router;
use sea_orm::{ConnectOptions, Database, DatabaseConnection};
use tokio::sync::mpsc::Sender;
use std::{error, time::Duration};

use crate::bgworker::Job;
use crate::Config;

#[derive(Debug)]
pub struct App;
impl App {
    pub async fn serve(
        app: Router,
        host: String,
        port: i32,
    ) -> Result<(), Box<dyn error::Error>> {
        let listener = tokio::net::TcpListener::bind(
            &format!("{}:{}", host, port),
        )
        .await?;

        tracing::info!("listing on port {}", port);
        axum::serve(listener, app)
            .with_graceful_shutdown(shutdown_signal())
            .await?;

        Ok(())
    }
}

#[derive(Debug)]
pub struct AppContext {
    pub config: Config,
    pub db: DatabaseConnection,
    pub tx: Option<Sender<Job>>,
}

impl AppContext {
    ///Create's a AppContext instanse or panics
    pub async fn new() -> Self {
        let mut ctx = AppContext {
            config: Config::new("config.yml").unwrap(),
            db: DatabaseConnection::Disconnected,
            tx: None,
        };
        ctx.open_db_connection().await.unwrap();
        ctx
    }
    pub async fn open_db_connection(
        &mut self
    ) -> Result<(), Box<dyn error::Error>> {
        let mut opt = ConnectOptions::new(
            self.config.database.uri.clone(),
        );
        opt.max_connections(
            self.config.database.max_connections,
        )
        .min_connections(
            self.config.database.min_connections,
        )
        .connect_timeout(Duration::from_secs(
            self.config.database.connect_timeout,
        ))
        .idle_timeout(Duration::from_millis(
            self.config.database.idle_timeout,
        ))
        .sqlx_logging(self.config.database.enable_logging)
        .sqlx_logging_level(log::LevelFilter::Debug);
        if let Some(acq_time) =
            self.config.database.acquire_timeout
        {
            opt.acquire_timeout(Duration::from_millis(
                acq_time,
            ));
        }
        self.db = Database::connect(opt).await?;
        Ok(())
    }
}

async fn shutdown_signal() {
    let ctrl_c = async {
        tokio::signal::ctrl_c()
            .await
            .expect("failed to install Ctrl+C handler");
    };

    #[cfg(unix)]
    use tokio::signal;
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
