use std::{error, fs};

use serde_json::json;
use tera::{Context, Tera};
use serde::{Deserialize, Serialize};

pub mod app;
pub mod bgworker;
pub mod controllers;
pub mod models;

#[derive(Deserialize, Serialize, PartialEq, Debug, Clone)]
pub struct Config {
    pub host: String,
    pub port: i32,
    pub mailer: Mailer,
    pub database: Database,
}

impl Config {
    pub fn new(
        path: &str
    ) -> Result<Self, Box<dyn error::Error>> {
        let config = Self::load_from_file(path)?;
        Ok(config)
    }
    fn load_from_file(
        path: &str
    ) -> Result<Self, Box<dyn error::Error>> {
        let content = fs::read_to_string(path)?;
        let render = render_string(&content, &json!({}))?;

        let config: Config = serde_yaml::from_str(&render)?;
        Ok(config)
    }
}

#[derive(Deserialize, Serialize, PartialEq, Debug, Clone)]
pub struct Mailer {
    // the mail app domain host
    pub host: String,
    // the mail app port
    pub port: u16,
    // if secure needs auth
    pub is_secure: bool,
    // auth variables
    pub auth: MailAuth,
}

#[derive(Deserialize, Serialize, PartialEq, Debug, Clone)]
pub struct MailAuth {
    pub user: String,
    pub password: String,
}

#[derive(Serialize, Deserialize)]
#[derive(Debug, Clone, PartialEq)]
pub struct Database {
    /// The URI for connecting to the database. For example:
    /// * Postgres: `postgres://root:12341234@localhost:5432/myapp_development`
    /// * Sqlite: `sqlite://db.sqlite?mode=rwc`
    pub uri: String,

    /// Enable `SQLx` statement logging
    pub enable_logging: bool,

    /// Minimum number of connections for a pool
    pub min_connections: u32,

    /// Maximum number of connections for a pool
    pub max_connections: u32,

    /// Set the timeout duration when acquiring a connection
    pub connect_timeout: u64,

    /// Set the idle duration before closing a connection
    pub idle_timeout: u64,

    /// Set the timeout for acquiring a connection
    pub acquire_timeout: Option<u64>,
}

fn render_string(
    tera_template: &str,
    locals: &serde_json::Value,
) -> Result<String, Box<dyn error::Error>> {
    let text = Tera::one_off(
        tera_template,
        &Context::from_serialize(locals)?,
        false,
    )?;
    Ok(text)
}

#[cfg(test)]
mod test {
    use dotenv::dotenv;

    use super::*;
    #[test]
    fn test_pars_config() {
        let _ = dotenv().unwrap();
        let _config: Config =
            match Config::new("config/testing.yml") {
                Ok(conf) => conf,
                Err(err) => {
                    panic!("{}", err.to_string());
                }
            };
    }
}
