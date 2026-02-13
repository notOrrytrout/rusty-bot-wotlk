use anyhow::Result;
use serde::Deserialize;
use std::fs;

#[derive(Debug, Deserialize)]
pub struct Config {
    pub username: String,
    pub password: String,
    pub host: String,
    pub port: u16,
    pub realm: String,
    pub ollama: OllamaConfig,
    pub bot: BotConfig,
}

#[derive(Debug, Deserialize)]
pub struct OllamaConfig {
    pub model: String,
    pub url: String,
}

#[derive(Debug, Deserialize)]
pub struct BotConfig {
    pub character_index: usize,
    pub count: usize,
}

impl Config {
    /// Loads configuration from a TOML file at the given path.
    pub fn load_from_file(path: &str) -> Result<Self> {
        let content = fs::read_to_string(path)?;
        let config: Config = toml::from_str(&content)?;
        Ok(config)
    }
}
