use rusty_bot_proxy::run_proxy;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    run_proxy().await
}
