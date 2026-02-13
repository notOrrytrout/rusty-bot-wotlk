// main.rs
//
// Entry point: Loads configuration and launches multiple bots using the given settings.
mod bot_launcher;
mod builder;
mod config;
mod input;
mod login;
mod packets;
mod player;
mod receiver;
mod transport;
mod utils;
mod world;
use std::sync::Arc;
mod auth;

use crate::bot_launcher::start_bot;
use crate::config::Config;
use tokio::task;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Load full configuration from file
    let config = Arc::new(Config::load_from_file("config.toml")?);

    // Launch the configured number of bots
    let mut handles = Vec::new();
    for index in 0..config.bot.count {
        let config_clone = Arc::clone(&config);
        handles.push(task::spawn(async move {
            if let Err(e) = start_bot(index, config_clone).await {
                eprintln!("Bot {} encountered an error: {:?}", index, e);
            }
        }));
    }

    // Wait for all bots to complete
    for handle in handles {
        handle.await?;
    }

    Ok(())
}
