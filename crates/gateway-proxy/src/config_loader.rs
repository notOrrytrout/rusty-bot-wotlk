use std::env;
use std::path::{Path, PathBuf};

use anyhow::Context;
use serde::de::DeserializeOwned;

/// Minimal config loader for the standalone proxy.
///
/// Search order matches the repo's existing conventions:
/// 1) `RUSTY_BOT_CONFIG_DIR/<relative_path>`
/// 2) `./<relative_path>`
/// 3) `<crate_root>/../config/<relative_path>` (repo-local convenience)
pub struct ConfigLoader;

impl ConfigLoader {
    pub fn parse_from_file<T: DeserializeOwned>(relative_path: &str) -> anyhow::Result<T> {
        let path = Self::resolve_path(relative_path)?;
        let text = std::fs::read_to_string(&path)
            .with_context(|| format!("Failed to read config at {}", path.display()))?;
        Self::parse_from_string(text)
    }

    pub fn parse_from_string<T: DeserializeOwned>(text: String) -> anyhow::Result<T> {
        toml::from_str(&text).with_context(|| "Failed to parse TOML")
    }

    fn resolve_path(relative_path: &str) -> anyhow::Result<PathBuf> {
        let rel = Path::new(relative_path);

        if let Some(root) = env::var_os("RUSTY_BOT_CONFIG_DIR") {
            let candidate = PathBuf::from(root).join(rel);
            if candidate.is_file() {
                return Ok(candidate);
            }
        }

        if let Ok(cwd) = env::current_dir() {
            let candidate = cwd.join(rel);
            if candidate.is_file() {
                return Ok(candidate);
            }
        }

        // Repo convenience: <repo_root>/config/<relative_path>.
        // This crate typically lives at <repo_root>/crates/gateway-proxy.
        let candidate = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .ancestors()
            .nth(2)
            .ok_or_else(|| anyhow::anyhow!("CARGO_MANIFEST_DIR has insufficient ancestors"))?
            .join("config")
            .join(rel);
        if candidate.is_file() {
            return Ok(candidate);
        }

        anyhow::bail!("Config file not found for {:?}", rel);
    }
}
