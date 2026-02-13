// llm.rs
//
// Handles communication with the Ollama LLM API.
// Sends structured vision prompts and receives command responses.

use reqwest::Client;
use serde::{Deserialize, Serialize};
use crate::config::Config;

#[derive(Serialize)]
struct OllamaRequest {
    model: String,
    prompt: String,
    stream: bool,
}

#[derive(Deserialize)]
struct OllamaResponse {
    response: String,
}

/// Sends a prompt to the configured Ollama instance and returns interpreted lines.
///
/// # Arguments
/// * `prompt` - The bot's current world vision frame
/// * `config` - Contains model and URL info from config.toml
///
/// # Returns
/// A vector of command strings issued by the LLM (one per line)
pub async fn query_ollama(prompt: &str, config: &Config) -> anyhow::Result<Vec<String>> {
    let client = Client::new();
    let request = OllamaRequest {
        model: config.ollama.model.clone(),
        prompt: prompt.to_string(),
        stream: false,
    };

    let res = client
        .post(format!("{}/api/generate", config.ollama.url))
        .json(&request)
        .send()
        .await?
        .json::<OllamaResponse>()
        .await?;

    let lines = res
        .response
        .lines()
        .map(|l| l.trim().to_string())
        .filter(|l| !l.is_empty())
        .collect();

    Ok(lines)
}
