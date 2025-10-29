use sea_orm::{ConnectOptions, Database, DatabaseConnection};
use std::{error, time::Duration};

use crate::Config;

#[derive(Debug)]
pub struct AppContext {
    pub config: Config,
    pub db: DatabaseConnection,
}

impl AppContext {
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
