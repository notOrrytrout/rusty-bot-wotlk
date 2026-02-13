// src/bot_launcher.rs

use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Mutex;

use crate::builder::build_packet;
use crate::config::Config;
use crate::input::interpret_llm_input;
use crate::login::{login_realmd, login_world, select_character};
use crate::receiver::start_receiver;
use crate::transport::Transport;
use rusty_bot_core::llm::{query_ollama_generate, OllamaConfig};
use rusty_bot_core::vision::generate_prompt;
use rusty_bot_core::world::world_state::WorldState;

/// Starts a single bot instance based on config and index.
pub async fn start_bot(index: usize, config: Arc<Config>) -> anyhow::Result<()> {
    // 1. Prepare credentials
    let account = if config.username.contains("{}") {
        config.username.replace("{}", &index.to_string())
    } else {
        config.username.clone()
    };
    let password = config.password.clone();

    // 2. Login to realm & world
    let realmd_addr = format!("{}:{}", config.host, config.port);
    let world_addr = format!("{}:8085", config.host);
    let character_index = config.bot.character_index;

    let realmd_sess = login_realmd(&realmd_addr, &account, &password).await?;
    let world_sess = login_world(&world_addr, &realmd_sess).await?;

    // 3. Split socket
    let mut read_half = world_sess.read_half;
    let write_half = world_sess.write_half;
    let read_cipher = world_sess.read_cipher;
    let write_cipher = world_sess.write_cipher;

    // 4. Select character
    let player_guid = select_character(&mut read_half, character_index).await?;

    // 5. Spawn receiver
    let world_state = Arc::new(Mutex::new(WorldState::new()));
    let rx = Arc::clone(&world_state);
    tokio::spawn(async move {
        start_receiver(read_half, read_cipher, rx).await;
    });

    // 6. Main loop
    let mut transport = Transport::new(write_half, write_cipher);
    loop {
        let state = world_state.lock().await;
        let prompt = generate_prompt(&state, player_guid);
        drop(state);

        let cfg = OllamaConfig {
            endpoint: format!("{}/api/generate", config.ollama.url.trim_end_matches('/')),
            model: config.ollama.model.clone(),
        };

        let response_text = query_ollama_generate(&prompt, &cfg)
            .await
            .unwrap_or_default();
        for line in response_text
            .lines()
            .map(|l| l.trim())
            .filter(|l| !l.is_empty())
        {
            if let Some(pkt_type) = interpret_llm_input(line) {
                let pkt = build_packet(pkt_type, player_guid);
                transport.send(&pkt).await?;
            }
        }

        tokio::time::sleep(Duration::from_millis(300)).await;
    }
}
