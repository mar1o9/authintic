use std::{error, fs};

use serde_json::json;
use tera::{Context, Tera};
use serde::{Deserialize, Serialize};

pub mod app;
pub mod controllers;
pub mod entities;

#[derive(Deserialize, Serialize, PartialEq, Debug, Clone)]
pub struct Config {
    pub host: String,
    pub port: i32,
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
        // let mut temp = tera::Tera::new(concat!(
        //     env!("CARGO_MANIFEST_DIR"),
        //     "/config/*"
        // ))?;
        // temp.add_template_file(
        //     "config.yml",
        //     Some("config"),
        // )?;
        // let db_url_var = var("DATABASE_URL")?;
        // let mut ctx = tera::Context::new();
        // ctx.insert("${DATABASE_URL}", &db_url_var);
        // let rendered = temp.render("config", &ctx)?;
        // let yml_config = fs::read_to_string(path)?
        //     .replace("${DATABASE_URL}", &db_url_var);
        let content = fs::read_to_string(path)?;
        let render = render_string(&content, &json!({}))?;

        let config: Config = serde_yaml::from_str(&render)?;
        Ok(config)
    }
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
        let config: Config = match Config::new("config.yml")
        {
            Ok(conf) => conf,
            Err(err) => {
                panic!("{}", err.to_string());
            }
        };
        let c = Config {
            host: "localhost".to_string(),
            port: 8989,
            database: Database {
                uri: "sqlite://debug.sqlite?mode=rwc"
                    .to_string(),
                enable_logging: false,
                min_connections: 1,
                max_connections: 10,
                idle_timeout: 500,
                connect_timeout: 500,
                acquire_timeout: Some(500),
            },
        };
        assert_eq!(config, c);
    }
}
