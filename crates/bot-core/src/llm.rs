use anyhow::Context;
use reqwest::Client;
use serde::{Deserialize, Serialize};

/// Minimal config for an Ollama-style `POST /api/generate` endpoint.
#[derive(Debug, Clone)]
pub struct OllamaConfig {
    /// Full endpoint URL, e.g. `http://127.0.0.1:11435/api/generate`.
    pub endpoint: String,
    pub model: String,
}

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

/// Sends a prompt to an Ollama-style generate endpoint and returns the raw response text.
pub async fn query_ollama_generate(prompt: &str, cfg: &OllamaConfig) -> anyhow::Result<String> {
    let client = Client::new();
    let request = OllamaRequest {
        model: cfg.model.clone(),
        prompt: prompt.to_string(),
        stream: false,
    };

    let res = client
        .post(&cfg.endpoint)
        .json(&request)
        .send()
        .await
        .context("ollama request failed")?
        .error_for_status()
        .context("ollama non-2xx response")?
        .json::<OllamaResponse>()
        .await
        .context("ollama response decode failed")?;

    Ok(res.response)
}
