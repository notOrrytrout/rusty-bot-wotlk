use std::io::Cursor;
use std::io::Read;
use std::sync::Arc;
use std::time::Duration;

use anyhow::Context;
use binrw::{BinRead, BinWrite, Endian};
use byteorder::{BigEndian, LittleEndian, ReadBytesExt};
use num_bigint::{BigInt, Sign, ToBigInt};
use serde::Deserialize;
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{Mutex, mpsc, oneshot};
use tokio::time::{Instant, MissedTickBehavior};

use rusty_bot_core::agent::ToolCall as AgentToolCall;
use rusty_bot_core::agent::ToolCallWire as AgentToolCallWire;
use rusty_bot_core::agent::ToolInvocation as AgentToolInvocation;
use rusty_bot_core::agent::game_api::GameApi as AgentGameApi;
use rusty_bot_core::agent::harness::{
    HarnessConfig as AgentHarnessConfig, HarnessOutcome as AgentHarnessOutcome,
    LlmCallSuppressed as AgentLlmCallSuppressed, LlmClient as AgentLlmClient, tick as agent_tick,
};
use rusty_bot_core::agent::r#loop::AgentLoop;
use rusty_bot_core::agent::memory::{ToolResult as AgentToolResult, ToolStatus as AgentToolStatus};
use rusty_bot_core::agent::observation::{
    ObservationBuilder as AgentObservationBuilder, ObservationInputs as AgentObservationInputs,
};
use rusty_bot_core::agent::tools::ToolMeta;
use rusty_bot_core::player::player_state::PlayerCurrentState;
use rusty_bot_core::vision::generate_prompt as generate_vision_prompt;
use rusty_bot_core::world::world_state::WorldState;

use crate::config_loader::ConfigLoader;
use crate::wotlk::movement::{
    JumpInfo, MovementExtraFlags, MovementFlags, MovementInfo, PackedGuid,
};
use crate::wotlk::opcode::Opcode;
use crate::wotlk::rc4::{Decryptor, Encryptor};
use crate::wotlk::srp::Srp;

// Local gateway config types (kept separate from any client/protocol library config).
#[derive(Debug, Clone, Copy, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
enum RuntimeMode {
    Client,
    Gateway,
}

#[derive(Debug, Clone, Copy, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
enum AuthMode {
    HeadlessSrp,
    DualSrp,
    TransparentDbFallback,
}

#[derive(Debug, Deserialize)]
struct Connection {
    host: String,
    account_name: String,
    password: String,
}

#[derive(Debug, Deserialize)]
struct Gateway {
    #[serde(default = "default_runtime_mode")]
    mode: RuntimeMode,
    #[serde(default = "default_auth_mode")]
    auth_mode: AuthMode,
    #[serde(default)]
    proxy: Proxy,
}

#[derive(Debug, Deserialize)]
struct Proxy {
    #[serde(default = "default_login_listen")]
    login_listen: String,
    #[serde(default = "default_world_listen")]
    world_listen: String,
    #[serde(default = "default_control_listen")]
    control_listen: String,
}

impl Default for Proxy {
    fn default() -> Self {
        Self {
            login_listen: default_login_listen(),
            world_listen: default_world_listen(),
            control_listen: default_control_listen(),
        }
    }
}

#[derive(Debug, Deserialize)]
struct Config {
    connection: Option<Connection>,
    gateway: Option<Gateway>,
}

fn default_runtime_mode() -> RuntimeMode {
    RuntimeMode::Client
}

fn default_auth_mode() -> AuthMode {
    AuthMode::HeadlessSrp
}

fn default_login_listen() -> String {
    "127.0.0.1:3725".to_string()
}

fn default_world_listen() -> String {
    "127.0.0.1:8086".to_string()
}

fn default_control_listen() -> String {
    "127.0.0.1:7878".to_string()
}

const CRC_HASH: [u8; 20] = [
    0xCD, 0xCB, 0xBD, 0x51, 0x88, 0x31, 0x5E, 0x6B, 0x4D, 0x19, 0x44, 0x9D, 0x49, 0x2D, 0xBC, 0xFA,
    0xF1, 0x56, 0xA3, 0x47,
];

const LOGIN_CHALLENGE_OP: u8 = 0;
const LOGIN_PROOF_OP: u8 = 1;
const REALM_LIST_OP: u8 = 16;
const EARLY_PACKET_TRACE_LIMIT: usize = 20;
const SMSG_AUTH_CHALLENGE_OPCODE: u32 = 0x01ec;
const SMSG_AUTH_RESPONSE_OPCODE: u32 = 0x01ee;
const CMSG_AUTH_SESSION_OPCODE: u32 = 0x01ed;

#[derive(Clone)]
struct WorldSession {
    account: String,
    client_key: Vec<u8>,
    server_key: Vec<u8>,
    upstream_world_addr: String,
}

#[derive(Debug)]
struct UpstreamChallenge {
    n: Vec<u8>,
    g: Vec<u8>,
    server_ephemeral: [u8; 32],
    salt: [u8; 32],
}

#[derive(Clone, Debug)]
struct WorldPacket {
    opcode: u32,
    body: Vec<u8>,
}

async fn send_injected_packet(
    packet: WorldPacket,
    upstream_tx: &mpsc::Sender<WorldPacket>,
    downstream_tx: &mpsc::Sender<WorldPacket>,
    echo_to_client: bool,
) -> anyhow::Result<()> {
    // Echoing injected packets to the client is risky: the client expects server->client packets
    // on that lane, and forwarding client->server opcodes can freeze/disconnect the client.
    // Keep it opt-in for local experimentation only.
    let unsafe_echo_to_client = std::env::var("RUSTY_BOT_UNSAFE_ECHO_INJECTED_TO_CLIENT")
        .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
        .unwrap_or(false);

    if matches!(route_for_opcode(packet.opcode), InjectRoute::UpstreamOnly) {
        if echo_to_client && unsafe_echo_to_client {
            // Historically used for demo/local testing. Do not enable in normal runs.
            upstream_tx.send(packet.clone()).await?;
            downstream_tx.send(packet).await?;
            return Ok(());
        }
        upstream_tx.send(packet).await?;
        return Ok(());
    }
    Ok(())
}

#[derive(Debug, Clone, Copy)]
enum InjectRoute {
    UpstreamOnly,
}

fn route_for_opcode(opcode: u32) -> InjectRoute {
    if opcode == Opcode::CMSG_TEXT_EMOTE {
        return InjectRoute::UpstreamOnly;
    }

    if let Ok(op_u16) = u16::try_from(opcode) {
        if is_world_move_opcode(op_u16) {
            return InjectRoute::UpstreamOnly;
        }
    }

    // Default: injected packets should go upstream only. Echoing to the client is unsafe.
    InjectRoute::UpstreamOnly
}

#[derive(Default, Debug)]
struct InjectionGuardState {
    client_move_mask: u8,
    last_client_move_at: Option<Instant>,
    last_client_move_time: Option<u32>,
    last_client_move_packet: Option<WorldPacket>,
    last_demo_packet: Option<WorldPacket>,
    last_demo_inject_at: Option<Instant>,
    last_client_correction_at: Option<Instant>,
    suppressed_count: u32,
    last_self_guid: Option<u64>,
}

#[derive(Default, Debug)]
struct AuthBoundaryState {
    client_auth_session_seen: bool,
    server_auth_challenge_count: u32,
    loop_reported: bool,
}

#[derive(Debug)]
struct AuthRewriteState {
    expected_account: String,
    server_key: Vec<u8>,
    server_seed: Option<[u8; 4]>,
}

#[derive(Debug)]
struct SrpServer {
    account: String,
    password: String,
    modulus: BigInt,
    generator: BigInt,
    salt: [u8; 32],
    private_ephemeral: BigInt,
    public_ephemeral: BigInt,
    session_key: Vec<u8>,
}

impl SrpServer {
    fn new(account: String, password: String, n: &[u8], g: &[u8]) -> Self {
        let modulus = BigInt::from_bytes_le(Sign::Plus, n);
        let generator = BigInt::from_bytes_le(Sign::Plus, g);
        let salt: [u8; 32] = rand::random();
        let private_bytes: [u8; 19] = rand::random();
        let private_ephemeral = BigInt::from_bytes_le(Sign::Plus, &private_bytes);

        let x = calculate_x(&account, &password, &salt);
        let v = generator.modpow(&x, &modulus);
        let k = 3.to_bigint().expect("k conversion");
        let gb = generator.modpow(&private_ephemeral, &modulus);
        let public_ephemeral = mod_floor(&(k * v + gb), &modulus);

        Self {
            account,
            password,
            modulus,
            generator,
            salt,
            private_ephemeral,
            public_ephemeral,
            session_key: Vec::new(),
        }
    }

    fn challenge_ephemeral_padded(&self) -> [u8; 32] {
        pad_to_32_bytes(self.public_ephemeral.to_bytes_le().1)
    }

    fn verify_client_proof(
        &mut self,
        client_public_ephemeral: [u8; 32],
        client_proof: [u8; 20],
    ) -> anyhow::Result<[u8; 20]> {
        let client_a = BigInt::from_bytes_le(Sign::Plus, &client_public_ephemeral);
        let x = calculate_x(&self.account, &self.password, &self.salt);
        let verifier = self.generator.modpow(&x, &self.modulus);

        let u = calculate_u(&client_a, &self.public_ephemeral);
        let vu = verifier.modpow(&u, &self.modulus);
        let avu = mod_floor(&(client_a.clone() * vu), &self.modulus);
        let s = avu.modpow(&self.private_ephemeral, &self.modulus);
        let session_key = calculate_interleaved(s);
        self.session_key = trim_trailing_zeros(session_key);

        let expected_m1 = calculate_m1(
            &self.modulus,
            &self.generator,
            &self.account,
            &self.salt,
            &client_a,
            &self.public_ephemeral,
            &self.session_key,
        );

        if expected_m1 != client_proof {
            anyhow::bail!("Client proof mismatch");
        }

        Ok(calculate_m2(&client_a, expected_m1, &self.session_key))
    }
}

pub async fn run_proxy() -> anyhow::Result<()> {
    let config: Config = ConfigLoader::parse_from_file("wow/wotlk/connection.toml")
        .context("parse wow/wotlk/connection.toml")?;

    let gateway = config
        .gateway
        .ok_or_else(|| anyhow::anyhow!("Missing [gateway] section for proxy mode"))?;
    if gateway.mode != RuntimeMode::Gateway {
        anyhow::bail!("Proxy requires [gateway].mode = \"gateway\"");
    }
    if gateway.auth_mode != AuthMode::DualSrp {
        anyhow::bail!("Proxy requires [gateway].auth_mode = \"dual_srp\"");
    }

    let conn = config
        .connection
        .ok_or_else(|| anyhow::anyhow!("Missing [connection] section"))?;

    let account = conn.account_name.to_uppercase();
    let password = conn.password.to_uppercase();
    let auth_upstream = conn.host.clone();

    if auth_upstream == gateway.proxy.login_listen {
        anyhow::bail!(
            "Invalid config: [connection].host (auth_upstream) must not equal [gateway.proxy].login_listen (would proxy into itself): {}",
            auth_upstream
        );
    }

    let login_listener = TcpListener::bind(&gateway.proxy.login_listen)
        .await
        .with_context(|| format!("bind login listener {}", gateway.proxy.login_listen))?;
    let world_listener = TcpListener::bind(&gateway.proxy.world_listen)
        .await
        .with_context(|| format!("bind world listener {}", gateway.proxy.world_listen))?;
    let control_listener = Arc::new(
        TcpListener::bind(&gateway.proxy.control_listen)
            .await
            .with_context(|| format!("bind control listener {}", gateway.proxy.control_listen))?,
    );

    println!(
        "proxy.started login={} world={} control={} auth_upstream={}",
        gateway.proxy.login_listen,
        gateway.proxy.world_listen,
        gateway.proxy.control_listen,
        auth_upstream
    );

    let (session_tx, mut session_rx) = mpsc::channel::<WorldSession>(8);

    let login_task = {
        let account = account.clone();
        let password = password.clone();
        let auth_upstream = auth_upstream.clone();
        let world_listen_addr = gateway.proxy.world_listen.clone();
        tokio::spawn(async move {
            loop {
                let (client_stream, client_addr) = login_listener.accept().await?;
                println!("proxy.login.accepted client={client_addr}");

                match handle_login_session(
                    client_stream,
                    &auth_upstream,
                    &account,
                    &password,
                    &world_listen_addr,
                )
                .await
                {
                    Ok(session) => {
                        if session_tx.send(session).await.is_err() {
                            anyhow::bail!("world session channel closed");
                        }
                    }
                    Err(err) => {
                        eprintln!("proxy.login.error {err:#}");
                    }
                }
            }
            #[allow(unreachable_code)]
            Ok::<(), anyhow::Error>(())
        })
    };

    let world_task = tokio::spawn(async move {
        loop {
            let session = session_rx
                .recv()
                .await
                .ok_or_else(|| anyhow::anyhow!("world session channel closed"))?;

            println!(
                "proxy.world.waiting upstream={} client_listen={}",
                session.upstream_world_addr, gateway.proxy.world_listen
            );
            let (client_stream, client_addr) = world_listener.accept().await?;
            println!("proxy.world.accepted client={client_addr}");

            match handle_world_session(client_stream, session, control_listener.clone()).await {
                Ok(()) => println!("proxy.world.closed"),
                Err(err) => eprintln!("proxy.world.error {err:#}"),
            }
        }
        #[allow(unreachable_code)]
        Ok::<(), anyhow::Error>(())
    });

    let _ = tokio::try_join!(login_task, world_task)?;
    Ok(())
}

async fn handle_login_session(
    mut client: TcpStream,
    auth_upstream: &str,
    account: &str,
    password: &str,
    proxy_world_addr: &str,
) -> anyhow::Result<WorldSession> {
    println!("proxy.login.stage connect_upstream");
    let mut upstream = TcpStream::connect(auth_upstream)
        .await
        .with_context(|| format!("connect auth upstream {auth_upstream}"))?;

    println!("proxy.login.stage read_client_challenge");
    let login_challenge = read_client_login_challenge(&mut client).await?;
    println!("proxy.login.stage write_upstream_challenge");
    upstream.write_all(&login_challenge).await?;

    println!("proxy.login.stage read_upstream_challenge");
    let upstream_challenge = read_upstream_challenge(&mut upstream).await?;
    let mut downstream_srp = SrpServer::new(
        account.to_string(),
        password.to_string(),
        &upstream_challenge.n,
        &upstream_challenge.g,
    );
    println!("proxy.login.stage send_downstream_challenge");
    send_downstream_challenge(&mut client, &upstream_challenge, &downstream_srp).await?;

    println!("proxy.login.stage read_client_proof");
    let (client_a, client_m1) = read_client_proof(&mut client).await?;
    let client_m2 = downstream_srp.verify_client_proof(client_a, client_m1)?;
    println!("proxy.login.stage send_client_proof_ok");
    send_client_proof_ok(&mut client, client_m2).await?;

    let mut upstream_srp = Srp::default();
    upstream_srp.init(
        &upstream_challenge.n,
        &upstream_challenge.g,
        &upstream_challenge.server_ephemeral,
        upstream_challenge.salt,
    );
    upstream_srp.calculate_session_key(account, password);
    let upstream_m1 = upstream_srp.calculate_proof(account);
    let upstream_a = upstream_srp.public_ephemeral();
    println!("proxy.login.stage send_upstream_proof");
    send_upstream_proof(&mut upstream, upstream_a, upstream_m1).await?;
    println!("proxy.login.stage read_upstream_proof_response");
    let upstream_m2 = read_upstream_proof_response(&mut upstream).await?;
    if !upstream_srp.validate_proof(upstream_m2) {
        anyhow::bail!("Upstream server proof mismatch");
    }
    let upstream_key = upstream_srp.session_key;
    let client_key = downstream_srp.session_key;

    println!("proxy.login.stage read_client_realmlist_request");
    read_client_realmlist_request(&mut client).await?;
    println!("proxy.login.stage send_upstream_realmlist_request");
    send_upstream_realmlist_request(&mut upstream).await?;
    println!("proxy.login.stage read_upstream_realmlist_response");
    let upstream_realmlist_body = read_upstream_realmlist_response(&mut upstream).await?;
    let (rewritten_realmlist_body, upstream_world_addr) =
        rewrite_realmlist_addresses(&upstream_realmlist_body, proxy_world_addr)?;
    println!("proxy.login.stage send_client_realmlist_response");
    send_client_realmlist_response(&mut client, &rewritten_realmlist_body).await?;

    let proxy_world_addr = proxy_world_addr.to_string();
    tokio::spawn(async move {
        if let Err(err) = keep_login_bridge_alive(client, upstream, &proxy_world_addr).await {
            eprintln!("proxy.login.keepalive.error {err:#}");
        }
    });

    println!("proxy.login.stage done upstream_world_addr={upstream_world_addr}");
    Ok(WorldSession {
        account: account.to_string(),
        client_key,
        server_key: upstream_key,
        upstream_world_addr,
    })
}

async fn handle_world_session(
    client_stream: TcpStream,
    session: WorldSession,
    control_listener: Arc<TcpListener>,
) -> anyhow::Result<()> {
    println!(
        "proxy.world.keys client_key_len={} server_key_len={}",
        session.client_key.len(),
        session.server_key.len()
    );
    let upstream_stream = TcpStream::connect(&session.upstream_world_addr)
        .await
        .with_context(|| format!("connect world upstream {}", session.upstream_world_addr))?;

    let (client_read, client_write) = client_stream.into_split();
    let (upstream_read, upstream_write) = upstream_stream.into_split();

    let (upstream_tx, upstream_rx) = mpsc::channel::<WorldPacket>(512);
    let (downstream_tx, downstream_rx) = mpsc::channel::<WorldPacket>(512);
    let downstream_inject_tx = downstream_tx.clone();
    let injection_guard = Arc::new(Mutex::new(InjectionGuardState::default()));
    let world_state = Arc::new(Mutex::new(WorldState::new()));
    let auth_boundary = Arc::new(Mutex::new(AuthBoundaryState::default()));
    let auth_rewrite = Arc::new(Mutex::new(AuthRewriteState {
        expected_account: session.account.clone(),
        server_key: session.server_key.clone(),
        server_seed: None,
    }));

    let client_reader = tokio::spawn(read_client_world_packets(
        client_read,
        Encryptor::new(&session.client_key),
        upstream_tx.clone(),
        injection_guard.clone(),
        world_state.clone(),
        auth_boundary.clone(),
        auth_rewrite.clone(),
        "client->proxy",
    ));
    let upstream_reader = tokio::spawn(read_world_packets(
        upstream_read,
        Decryptor::new(&session.server_key),
        downstream_tx,
        world_state.clone(),
        auth_boundary.clone(),
        auth_rewrite.clone(),
        "server->proxy",
    ));
    let upstream_writer = tokio::spawn(write_client_world_packets(
        upstream_write,
        Encryptor::new(&session.server_key),
        upstream_rx,
        false,
        "proxy->server",
    ));
    let downstream_writer = tokio::spawn(write_server_world_packets(
        client_write,
        Decryptor::new(&session.client_key),
        downstream_rx,
        false,
        "proxy->client",
    ));

    // The in-proxy agent loop is the only runner. It can be enabled/disabled at runtime via the
    // control port (`op=agent_enable`), so we always start the control channel.
    let (agent_tx, agent_rx) = {
        let (tx, rx) = mpsc::channel::<AgentControlCommand>(32);
        (Some(tx), rx)
    };

    let control_task = tokio::spawn(serve_control(
        control_listener,
        upstream_tx.clone(),
        downstream_inject_tx.clone(),
        injection_guard.clone(),
        world_state.clone(),
        agent_tx.clone(),
    ));
    let agent_task = tokio::spawn(run_agent_llm_injector(
        upstream_tx.clone(),
        downstream_inject_tx.clone(),
        injection_guard.clone(),
        world_state.clone(),
        agent_rx,
    ));

    tokio::select! {
        result = client_reader => {
            match result {
                Ok(Ok(())) => println!("proxy.world.end lane=client_reader result=ok"),
                Ok(Err(err)) => {
                    eprintln!("proxy.world.end lane=client_reader error={err:#}");
                    return Err(err);
                }
                Err(err) => {
                    eprintln!("proxy.world.end lane=client_reader join_error={err}");
                    return Err(err.into());
                }
            }
        }
        result = upstream_reader => {
            match result {
                Ok(Ok(())) => println!("proxy.world.end lane=upstream_reader result=ok"),
                Ok(Err(err)) => {
                    eprintln!("proxy.world.end lane=upstream_reader error={err:#}");
                    return Err(err);
                }
                Err(err) => {
                    eprintln!("proxy.world.end lane=upstream_reader join_error={err}");
                    return Err(err.into());
                }
            }
        }
        result = upstream_writer => {
            match result {
                Ok(Ok(())) => println!("proxy.world.end lane=upstream_writer result=ok"),
                Ok(Err(err)) => {
                    eprintln!("proxy.world.end lane=upstream_writer error={err:#}");
                    return Err(err);
                }
                Err(err) => {
                    eprintln!("proxy.world.end lane=upstream_writer join_error={err}");
                    return Err(err.into());
                }
            }
        }
        result = downstream_writer => {
            match result {
                Ok(Ok(())) => println!("proxy.world.end lane=downstream_writer result=ok"),
                Ok(Err(err)) => {
                    eprintln!("proxy.world.end lane=downstream_writer error={err:#}");
                    return Err(err);
                }
                Err(err) => {
                    eprintln!("proxy.world.end lane=downstream_writer join_error={err}");
                    return Err(err.into());
                }
            }
        }
    }

    control_task.abort();
    agent_task.abort();
    Ok(())
}

async fn read_world_packets(
    mut reader: OwnedReadHalf,
    mut decryptor: Decryptor,
    tx: mpsc::Sender<WorldPacket>,
    world_state: Arc<Mutex<WorldState>>,
    auth_boundary: Arc<Mutex<AuthBoundaryState>>,
    auth_rewrite: Arc<Mutex<AuthRewriteState>>,
    lane: &'static str,
) -> anyhow::Result<()> {
    let mut decrypt_active = false;
    let mut packet_count = 0usize;
    loop {
        let packet = read_server_world_packet(&mut reader, &mut decryptor, &mut decrypt_active)
            .await
            .with_context(|| format!("{lane} read_world_packet"))?;
        packet_count += 1;
        if packet_count <= EARLY_PACKET_TRACE_LIMIT {
            println!(
                "proxy.world.rx lane={} idx={} opcode=0x{:04x} body_len={} decrypt_active={}",
                lane,
                packet_count,
                packet.opcode,
                packet.body.len(),
                decrypt_active
            );
        }
        record_auth_boundary_observation(lane, packet_count, packet.opcode, &auth_boundary).await;
        update_auth_rewrite_state_from_server_packet(lane, &packet, &auth_rewrite).await;
        record_server_world_observation(&packet, &world_state).await;
        if tx.send(packet).await.is_err() {
            return Ok(());
        }
    }
}

async fn read_client_world_packets(
    mut reader: OwnedReadHalf,
    mut decryptor: Encryptor,
    tx: mpsc::Sender<WorldPacket>,
    injection_guard: Arc<Mutex<InjectionGuardState>>,
    world_state: Arc<Mutex<WorldState>>,
    auth_boundary: Arc<Mutex<AuthBoundaryState>>,
    auth_rewrite: Arc<Mutex<AuthRewriteState>>,
    lane: &'static str,
) -> anyhow::Result<()> {
    let suppress_client_movement = std::env::var("RUSTY_BOT_SUPPRESS_CLIENT_MOVEMENT")
        .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
        // Default to allowing the user's real client to keep sending movement so:
        // - server-side corrections (walls, slopes) stay in effect
        // - the user can steer/turn while the bot runs
        .unwrap_or(false);
    if suppress_client_movement {
        println!("proxy.bot suppress_client_movement=true");
    }

    // First world packet from client is CMSG_AUTH_SESSION and must be read plaintext.
    let mut decrypt_active = false;
    let mut packet_count = 0usize;
    loop {
        let mut packet = read_client_world_packet(&mut reader, &mut decryptor, &mut decrypt_active)
            .await
            .with_context(|| format!("{lane} read_world_packet"))?;
        packet_count += 1;
        if packet_count <= EARLY_PACKET_TRACE_LIMIT {
            println!(
                "proxy.world.rx lane={} idx={} opcode=0x{:04x} body_len={} decrypt_active={}",
                lane,
                packet_count,
                packet.opcode,
                packet.body.len(),
                decrypt_active
            );
        }
        record_auth_boundary_observation(lane, packet_count, packet.opcode, &auth_boundary).await;
        maybe_rewrite_client_auth_session(&mut packet, lane, &auth_rewrite).await;
        record_client_movement_observation(&packet, &injection_guard, &world_state).await;

        if suppress_client_movement {
            if let Ok(op_u16) = u16::try_from(packet.opcode) {
                if is_world_move_opcode(op_u16) {
                    // Let the bot injector be the sole writer of movement to the server.
                    // We still record movement observations above so the injector can reuse templates.
                    continue;
                }
            }
        }

        if tx.send(packet).await.is_err() {
            return Ok(());
        }
    }
}

async fn write_client_world_packets(
    mut writer: OwnedWriteHalf,
    mut encryptor: Encryptor,
    mut rx: mpsc::Receiver<WorldPacket>,
    start_encrypted: bool,
    lane: &'static str,
) -> anyhow::Result<()> {
    let mut encrypt_active = start_encrypted;
    let mut packet_count = 0usize;
    while let Some(packet) = rx.recv().await {
        packet_count += 1;
        if packet_count <= EARLY_PACKET_TRACE_LIMIT {
            println!(
                "proxy.world.tx lane={} idx={} opcode=0x{:04x} body_len={} encrypt_active={}",
                lane,
                packet_count,
                packet.opcode,
                packet.body.len(),
                encrypt_active
            );
        }
        write_client_world_packet(&mut writer, &packet, &mut encryptor, &mut encrypt_active)
            .await
            .with_context(|| format!("{lane} write_world_packet"))?;
    }
    Ok(())
}

async fn write_server_world_packets(
    mut writer: OwnedWriteHalf,
    mut encryptor: Decryptor,
    mut rx: mpsc::Receiver<WorldPacket>,
    start_encrypted: bool,
    lane: &'static str,
) -> anyhow::Result<()> {
    let mut encrypt_active = start_encrypted;
    let mut packet_count = 0usize;
    while let Some(packet) = rx.recv().await {
        packet_count += 1;
        if packet_count <= EARLY_PACKET_TRACE_LIMIT {
            println!(
                "proxy.world.tx lane={} idx={} opcode=0x{:04x} body_len={} encrypt_active={}",
                lane,
                packet_count,
                packet.opcode,
                packet.body.len(),
                encrypt_active
            );
        }
        write_server_world_packet(&mut writer, &packet, &mut encryptor, &mut encrypt_active)
            .await
            .with_context(|| format!("{lane} write_world_packet"))?;
    }
    Ok(())
}

async fn record_auth_boundary_observation(
    lane: &'static str,
    idx: usize,
    opcode: u32,
    auth_boundary: &Arc<Mutex<AuthBoundaryState>>,
) {
    let mut state = auth_boundary.lock().await;

    if lane == "client->proxy" && opcode == CMSG_AUTH_SESSION_OPCODE {
        if !state.client_auth_session_seen {
            println!(
                "proxy.world.auth.client_auth_session_seen lane={} idx={} opcode=0x{:04x}",
                lane, idx, opcode
            );
        }
        state.client_auth_session_seen = true;
    }

    if lane == "client->proxy" && idx == 1 && opcode != CMSG_AUTH_SESSION_OPCODE {
        eprintln!(
            "proxy.world.auth.missing_client_auth_session first_client_opcode=0x{:04x} expected=0x{:04x}",
            opcode, CMSG_AUTH_SESSION_OPCODE
        );
    }

    if lane == "server->proxy" && opcode == SMSG_AUTH_CHALLENGE_OPCODE {
        state.server_auth_challenge_count += 1;
        println!(
            "proxy.world.auth.server_auth_challenge count={} lane={} idx={}",
            state.server_auth_challenge_count, lane, idx
        );
        if state.server_auth_challenge_count > 1
            && !state.client_auth_session_seen
            && !state.loop_reported
        {
            state.loop_reported = true;
            eprintln!(
                "proxy.world.auth.loop_detected repeated_smsg_auth_challenge=true missing_client_auth_session=true challenge_count={}",
                state.server_auth_challenge_count
            );
        }
    }
}

async fn update_auth_rewrite_state_from_server_packet(
    lane: &'static str,
    packet: &WorldPacket,
    auth_rewrite: &Arc<Mutex<AuthRewriteState>>,
) {
    if lane != "server->proxy" {
        return;
    }

    if packet.opcode == SMSG_AUTH_RESPONSE_OPCODE && !packet.body.is_empty() {
        let status = packet.body[0];
        println!(
            "proxy.world.auth.server_auth_response status=0x{:02x} body_len={}",
            status,
            packet.body.len()
        );
    }

    if packet.opcode != SMSG_AUTH_CHALLENGE_OPCODE || packet.body.len() < 8 {
        return;
    }

    let mut seed = [0u8; 4];
    seed.copy_from_slice(&packet.body[4..8]);
    let mut state = auth_rewrite.lock().await;
    state.server_seed = Some(seed);
    println!(
        "proxy.world.auth.server_seed_captured opcode=0x{:04x} seed={:02x}{:02x}{:02x}{:02x}",
        packet.opcode, seed[0], seed[1], seed[2], seed[3]
    );
}

async fn maybe_rewrite_client_auth_session(
    packet: &mut WorldPacket,
    lane: &'static str,
    auth_rewrite: &Arc<Mutex<AuthRewriteState>>,
) {
    if lane != "client->proxy" || packet.opcode != CMSG_AUTH_SESSION_OPCODE {
        return;
    }

    let state = auth_rewrite.lock().await;
    let Some(server_seed) = state.server_seed else {
        eprintln!("proxy.world.auth.rewrite_skipped reason=missing_server_seed");
        return;
    };

    match rewrite_cmsg_auth_session_digest(
        &mut packet.body,
        server_seed,
        &state.server_key,
        &state.expected_account,
    ) {
        Ok(account) => {
            println!(
                "proxy.world.auth.rewrite_cmsg_auth_session account={} opcode=0x{:04x}",
                account, packet.opcode
            );
        }
        Err(err) => {
            eprintln!(
                "proxy.world.auth.cmsg_auth_session_prefix {}",
                hex_prefix(&packet.body, 96)
            );
            log_account_candidates(&packet.body);
            eprintln!("proxy.world.auth.rewrite_failed error={err:#}");
        }
    }
}

fn rewrite_cmsg_auth_session_digest(
    body: &mut [u8],
    server_seed: [u8; 4],
    session_key: &[u8],
    expected_account: &str,
) -> anyhow::Result<String> {
    use sha1::{Digest, Sha1};

    if body.len() < 9 {
        anyhow::bail!("CMSG_AUTH_SESSION body too short");
    }

    // Most clients use account at offset 8, but some variants shift it.
    let (account_start, account_end) = detect_auth_account_span(body, expected_account)?;
    let account = std::str::from_utf8(&body[account_start..account_end])?.to_uppercase();
    let cursor = account_end + 1;

    // unknown2 (4) + client_seed (4) + unknown3 (8) + server_id (4) + unknown4 (8)
    let required_after_account = 4 + 4 + 8 + 4 + 8 + 20;
    if body.len() < cursor + required_after_account {
        anyhow::bail!("CMSG_AUTH_SESSION body truncated before digest");
    }
    let client_seed_offset = cursor + 4;
    let digest_offset = cursor + 28;
    let client_seed = &body[client_seed_offset..client_seed_offset + 4];

    let digest = Sha1::new()
        .chain(account.as_bytes())
        .chain([0u8; 4])
        .chain(client_seed)
        .chain(server_seed)
        .chain(session_key)
        .finalize();

    body[digest_offset..digest_offset + 20].copy_from_slice(&digest);
    println!(
        "proxy.world.auth.rewrite_offsets account_start={} account_end={} client_seed_offset={} digest_offset={}",
        account_start, account_end, client_seed_offset, digest_offset
    );
    Ok(account)
}

fn detect_auth_account_span(body: &[u8], expected_account: &str) -> anyhow::Result<(usize, usize)> {
    let expected_upper = expected_account.to_uppercase();
    if !expected_upper.is_empty() {
        let needle = expected_upper.as_bytes();
        if let Some(start) = body
            .windows(needle.len() + 1)
            .position(|w| &w[..needle.len()] == needle && w[needle.len()] == 0)
        {
            return Ok((start, start + needle.len()));
        }
    }

    let mut best: Option<(usize, usize)> = None;
    for start in [8usize, 12, 16] {
        if let Some(end) = find_valid_account_cstring(body, start) {
            best = pick_better_span(best, (start, end));
        }
    }

    let scan_limit = body.len().min(96);
    for start in 0..scan_limit {
        if let Some(end) = find_valid_account_cstring(body, start) {
            best = pick_better_span(best, (start, end));
        }
    }

    if let Some(span) = best {
        return Ok(span);
    }

    anyhow::bail!("unable to locate account string in CMSG_AUTH_SESSION");
}

fn pick_better_span(
    current: Option<(usize, usize)>,
    candidate: (usize, usize),
) -> Option<(usize, usize)> {
    match current {
        Some((s, e)) if (e - s) >= (candidate.1 - candidate.0) => Some((s, e)),
        _ => Some(candidate),
    }
}

fn find_valid_account_cstring(body: &[u8], start: usize) -> Option<usize> {
    if start >= body.len() {
        return None;
    }
    let rel_end = body[start..].iter().position(|v| *v == 0)?;
    if rel_end == 0 || rel_end > 32 {
        return None;
    }
    let end = start + rel_end;
    let raw = &body[start..end];
    if raw.iter().all(|b| b.is_ascii_alphanumeric() || *b == b'_') {
        Some(end)
    } else {
        None
    }
}

fn log_account_candidates(body: &[u8]) {
    let mut parts = Vec::new();
    for start in [8usize, 12, 16, 20, 24, 28, 32] {
        let candidate = find_valid_account_cstring(body, start)
            .and_then(|end| {
                std::str::from_utf8(&body[start..end])
                    .ok()
                    .map(|s| s.to_string())
            })
            .unwrap_or_else(|| "<none>".to_string());
        parts.push(format!("{start}:{candidate}"));
    }
    eprintln!("proxy.world.auth.account_candidates {}", parts.join(" "));
}

fn hex_prefix(bytes: &[u8], max_len: usize) -> String {
    bytes
        .iter()
        .take(max_len)
        .map(|b| format!("{:02x}", b))
        .collect::<Vec<_>>()
        .join("")
}

fn hex_all(bytes: &[u8]) -> String {
    bytes
        .iter()
        .map(|b| format!("{:02x}", b))
        .collect::<Vec<_>>()
        .join("")
}

#[derive(Debug)]
enum AgentControlCommand {
    Enable(bool),
    SetGoal(String),
    ClearGoal,
    OfferTool(AgentToolInvocation),
    ExecuteTool {
        tool: AgentToolInvocation,
        reply: oneshot::Sender<AgentToolResult>,
    },
    Status {
        reply: oneshot::Sender<serde_json::Value>,
    },
}

const CONTROL_PROTOCOL_VERSION: u32 = 1;

#[derive(Debug, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case")]
enum ControlRequest {
    /// Structured wrapper around the existing raw injection control port.
    Inject {
        opcode: String,
        body_hex: String,
    },
    /// Enable/disable the in-proxy agent loop.
    AgentEnable {
        enabled: bool,
    },
    SetGoal {
        goal: String,
    },
    ClearGoal {},
    Status {},
    Observation {},
    Tool {
        tool: AgentToolCallWire,
    },
    ToolExecute {
        tool: AgentToolCallWire,
    },
}

#[derive(Debug)]
enum ControlInput {
    Legacy(WorldPacket),
    Json(ControlRequest),
}

fn parse_opcode_u16(opcode: &str) -> anyhow::Result<u16> {
    let opcode = opcode.trim();
    if let Some(hex) = opcode
        .strip_prefix("0x")
        .or_else(|| opcode.strip_prefix("0X"))
    {
        return Ok(
            u16::from_str_radix(hex, 16).with_context(|| format!("invalid opcode hex {opcode}"))?
        );
    }
    Ok(opcode
        .parse::<u16>()
        .with_context(|| format!("invalid opcode {opcode}"))?)
}

fn parse_control_input_line(line: &str) -> anyhow::Result<ControlInput> {
    let trimmed = line.trim();
    if trimmed.starts_with('{') {
        let mut v: serde_json::Value =
            serde_json::from_str(trimmed).with_context(|| "invalid json control request")?;

        let version = v.get("version").and_then(|v| v.as_u64()).map(|v| v as u32);
        if let Some(version) = version {
            if version != CONTROL_PROTOCOL_VERSION {
                anyhow::bail!(
                    "unsupported control protocol version: {} (expected {})",
                    version,
                    CONTROL_PROTOCOL_VERSION
                );
            }
        }

        if let serde_json::Value::Object(obj) = &mut v {
            obj.remove("version");
        }

        let req: ControlRequest =
            serde_json::from_value(v).with_context(|| "invalid json control request")?;
        return Ok(ControlInput::Json(req));
    }
    Ok(ControlInput::Legacy(parse_control_line(trimmed)?))
}

async fn serve_control(
    listener: Arc<TcpListener>,
    upstream_tx: mpsc::Sender<WorldPacket>,
    downstream_tx: mpsc::Sender<WorldPacket>,
    injection_guard: Arc<Mutex<InjectionGuardState>>,
    world_state: Arc<Mutex<WorldState>>,
    agent_tx: Option<mpsc::Sender<AgentControlCommand>>,
) -> anyhow::Result<()> {
    let control_obs_builder = Arc::new(Mutex::new(AgentObservationBuilder::default()));
    loop {
        let (socket, addr) = listener.accept().await?;
        println!("proxy.control.accepted client={addr}");

        let upstream = upstream_tx.clone();
        let downstream = downstream_tx.clone();
        let guard = injection_guard.clone();
        let ws = world_state.clone();
        let obs_builder = control_obs_builder.clone();
        let agent_tx = agent_tx.clone();
        tokio::spawn(async move {
            let (read, mut write) = tokio::io::split(socket);
            let mut lines = BufReader::new(read).lines();
            while let Ok(Some(line)) = lines.next_line().await {
                let trimmed = line.trim();
                if trimmed.is_empty() {
                    continue;
                }

                let input = match parse_control_input_line(trimmed) {
                    Ok(input) => input,
                    Err(err) => {
                        eprintln!("proxy.control.bad_line error={err:#} line={trimmed}");
                        let _ = write
                            .write_all(
                                format!(
                                    "{{\"ok\":false,\"error\":{}}}\n",
                                    serde_json::to_string(&format!("{err:#}"))
                                        .unwrap_or("\"error\"".to_string())
                                )
                                .as_bytes(),
                            )
                            .await;
                        continue;
                    }
                };

                match input {
                    ControlInput::Legacy(packet) => {
                        let packet = match apply_injection_guard(packet, &guard).await {
                            Some(packet) => packet,
                            None => continue,
                        };
                        if upstream.send(packet.clone()).await.is_err() {
                            break;
                        }

                        // Opt-in only: raw control-port injection is already sharp; echoing it to the
                        // client can freeze/disconnect the client.
                        let unsafe_echo = std::env::var("RUSTY_BOT_UNSAFE_ECHO_INJECTED_TO_CLIENT")
                            .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
                            .unwrap_or(false);
                        if unsafe_echo {
                            let _ = downstream.send(packet).await;
                        }
                    }
                    ControlInput::Json(req) => {
                        let reply = handle_control_json(
                            req,
                            &upstream,
                            &downstream,
                            &guard,
                            &ws,
                            &obs_builder,
                            agent_tx.as_ref(),
                        )
                        .await;
                        match reply {
                            Ok(value) => {
                                let line = format!("{}\n", value);
                                let _ = write.write_all(line.as_bytes()).await;
                            }
                            Err(err) => {
                                let line = format!(
                                    "{{\"ok\":false,\"error\":{}}}\n",
                                    serde_json::to_string(&format!("{err:#}"))
                                        .unwrap_or("\"error\"".to_string())
                                );
                                let _ = write.write_all(line.as_bytes()).await;
                            }
                        }
                    }
                }
            }
        });
    }
}

async fn handle_control_json(
    req: ControlRequest,
    upstream: &mpsc::Sender<WorldPacket>,
    downstream: &mpsc::Sender<WorldPacket>,
    injection_guard: &Arc<Mutex<InjectionGuardState>>,
    world_state: &Arc<Mutex<WorldState>>,
    obs_builder: &Arc<Mutex<AgentObservationBuilder>>,
    agent_tx: Option<&mpsc::Sender<AgentControlCommand>>,
) -> anyhow::Result<String> {
    match req {
        ControlRequest::Inject { opcode, body_hex } => {
            let opcode = parse_opcode_u16(&opcode)? as u32;
            let body = decode_hex(&body_hex)?;
            let packet = WorldPacket { opcode, body };

            let packet = apply_injection_guard(packet, injection_guard)
                .await
                .ok_or_else(|| anyhow::anyhow!("suppressed"))?;
            upstream
                .send(packet.clone())
                .await
                .map_err(|_| anyhow::anyhow!("upstream channel closed"))?;

            let unsafe_echo = std::env::var("RUSTY_BOT_UNSAFE_ECHO_INJECTED_TO_CLIENT")
                .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
                .unwrap_or(false);
            if unsafe_echo {
                let _ = downstream.send(packet).await;
            }

            Ok(serde_json::json!({ "ok": true, "op": "inject" }).to_string())
        }
        ControlRequest::AgentEnable { enabled } => {
            let Some(tx) = agent_tx else {
                anyhow::bail!("agent_control_unavailable");
            };
            tx.send(AgentControlCommand::Enable(enabled))
                .await
                .map_err(|_| anyhow::anyhow!("agent_control_channel_closed"))?;
            Ok(
                serde_json::json!({ "ok": true, "op": "agent_enable", "enabled": enabled })
                    .to_string(),
            )
        }
        ControlRequest::SetGoal { goal } => {
            let Some(tx) = agent_tx else {
                anyhow::bail!("agent_control_unavailable");
            };
            tx.send(AgentControlCommand::SetGoal(goal.clone()))
                .await
                .map_err(|_| anyhow::anyhow!("agent_control_channel_closed"))?;
            Ok(serde_json::json!({ "ok": true, "op": "set_goal" }).to_string())
        }
        ControlRequest::ClearGoal {} => {
            let Some(tx) = agent_tx else {
                anyhow::bail!("agent_control_unavailable");
            };
            tx.send(AgentControlCommand::ClearGoal)
                .await
                .map_err(|_| anyhow::anyhow!("agent_control_channel_closed"))?;
            Ok(serde_json::json!({ "ok": true, "op": "clear_goal" }).to_string())
        }
        ControlRequest::Status {} => {
            let Some(tx) = agent_tx else {
                anyhow::bail!("agent_control_unavailable");
            };
            let (reply_tx, reply_rx) = oneshot::channel();
            tx.send(AgentControlCommand::Status { reply: reply_tx })
                .await
                .map_err(|_| anyhow::anyhow!("agent_control_channel_closed"))?;
            let v = reply_rx
                .await
                .map_err(|_| anyhow::anyhow!("agent_status_reply_dropped"))?;
            Ok(v.to_string())
        }
        ControlRequest::Observation {} => {
            let now = Instant::now();
            let guard = injection_guard.lock().await;
            let self_guid = guard.last_self_guid.unwrap_or(0);
            let client_correction_seen_recently = guard
                .last_client_correction_at
                .map(|t| now.duration_since(t) < Duration::from_secs(2))
                .unwrap_or(false);
            drop(guard);

            let ws = world_state.lock().await;
            let mut b = obs_builder.lock().await;
            let obs = b.build(
                &ws,
                AgentObservationInputs {
                    self_guid,
                    client_correction_seen_recently,
                },
            );

            Ok(serde_json::json!({
                "ok": true,
                "op": "observation",
                "observation": obs
            })
            .to_string())
        }
        ControlRequest::Tool { tool } => {
            let Some(tx) = agent_tx else {
                anyhow::bail!("agent_control_unavailable");
            };
            let inv = AgentToolInvocation::try_from(tool)
                .map_err(|e| anyhow::anyhow!("invalid tool: {e}"))?;
            tx.send(AgentControlCommand::OfferTool(inv))
                .await
                .map_err(|_| anyhow::anyhow!("agent_control_channel_closed"))?;
            Ok(serde_json::json!({ "ok": true, "op": "tool" }).to_string())
        }
        ControlRequest::ToolExecute { tool } => {
            let Some(tx) = agent_tx else {
                anyhow::bail!("agent_control_unavailable");
            };
            let inv = AgentToolInvocation::try_from(tool)
                .map_err(|e| anyhow::anyhow!("invalid tool: {e}"))?;

            // Immediate execution is intended for safe discrete actions (stop/idle/jump/emote).
            // Continuous movement should go through the normal executor loop.
            if inv.is_continuous() {
                anyhow::bail!("tool_execute does not support continuous tools");
            }

            let (reply_tx, reply_rx) = oneshot::channel();
            tx.send(AgentControlCommand::ExecuteTool {
                tool: inv,
                reply: reply_tx,
            })
            .await
            .map_err(|_| anyhow::anyhow!("agent_control_channel_closed"))?;

            let res = reply_rx
                .await
                .map_err(|_| anyhow::anyhow!("agent_execute_reply_dropped"))?;
            Ok(serde_json::json!({ "ok": true, "op": "tool_execute", "result": res }).to_string())
        }
    }
}

fn parse_control_line(line: &str) -> anyhow::Result<WorldPacket> {
    let mut parts = line.split_whitespace();
    let opcode_hex = parts
        .next()
        .ok_or_else(|| anyhow::anyhow!("missing opcode hex"))?;
    let body_hex = parts
        .next()
        .ok_or_else(|| anyhow::anyhow!("missing body hex"))?;

    let opcode = u16::from_str_radix(opcode_hex.trim_start_matches("0x"), 16)
        .with_context(|| format!("invalid opcode hex {opcode_hex}"))?;
    let body = decode_hex(body_hex)?;
    Ok(WorldPacket {
        opcode: opcode as u32,
        body,
    })
}

#[cfg(test)]
mod control_port_tests {
    use super::*;

    #[test]
    fn opcode_parser_accepts_hex_and_decimal() {
        assert_eq!(parse_opcode_u16("0x00a9").unwrap(), 0x00A9);
        assert_eq!(parse_opcode_u16("169").unwrap(), 169);
    }

    #[test]
    fn parse_control_input_line_json_and_legacy() {
        let json = r#"{"op":"status"}"#;
        let input = parse_control_input_line(json).unwrap();
        assert!(matches!(
            input,
            ControlInput::Json(ControlRequest::Status {})
        ));

        let json_v1 = r#"{"version":1,"op":"status"}"#;
        let input = parse_control_input_line(json_v1).unwrap();
        assert!(matches!(
            input,
            ControlInput::Json(ControlRequest::Status {})
        ));

        let json_bad_ver = r#"{"version":999,"op":"status"}"#;
        assert!(parse_control_input_line(json_bad_ver).is_err());

        let legacy = "0x00a9 deadbeef";
        let input = parse_control_input_line(legacy).unwrap();
        assert!(matches!(input, ControlInput::Legacy(_)));
    }

    #[test]
    fn parse_control_input_line_inject_json_round_trips_packet_fields() {
        let json = r#"{"op":"inject","opcode":"0x0001","body_hex":"deadbeef"}"#;
        let input = parse_control_input_line(json).unwrap();
        match input {
            ControlInput::Json(ControlRequest::Inject { opcode, body_hex }) => {
                assert_eq!(parse_opcode_u16(&opcode).unwrap(), 1);
                assert_eq!(decode_hex(&body_hex).unwrap(), vec![0xde, 0xad, 0xbe, 0xef]);
            }
            other => panic!("unexpected input: {other:?}"),
        }
    }

    #[test]
    fn parse_control_input_line_tool_json() {
        let json = r#"{"op":"tool","tool":{"name":"request_idle","arguments":{}}}"#;
        let input = parse_control_input_line(json).unwrap();
        assert!(matches!(
            input,
            ControlInput::Json(ControlRequest::Tool { .. })
        ));
    }

    #[test]
    fn parse_control_input_line_tool_execute_json() {
        let json = r#"{"op":"tool_execute","tool":{"name":"request_idle","arguments":{}}}"#;
        let input = parse_control_input_line(json).unwrap();
        assert!(matches!(
            input,
            ControlInput::Json(ControlRequest::ToolExecute { .. })
        ));
    }
}

#[cfg(test)]
mod tool_packet_tests {
    use super::*;

    #[test]
    fn build_set_selection_packet_layout() {
        let guid = 0x0102030405060708u64;
        let p = build_cmsg_set_selection(guid);
        assert_eq!(p.opcode, Opcode::CMSG_SET_SELECTION);
        assert_eq!(p.body, guid.to_le_bytes().to_vec());
    }

    #[test]
    fn build_gossip_hello_packet_layout() {
        let guid = 0x0102030405060708u64;
        let p = build_cmsg_gossip_hello(guid);
        assert_eq!(p.opcode, Opcode::CMSG_GOSSIP_HELLO);
        assert_eq!(p.body, guid.to_le_bytes().to_vec());
    }

    #[test]
    fn build_attackswing_packet_uses_packed_guid() {
        let guid = 0x0102030405060708u64;
        let p = build_cmsg_attackswing(guid);
        assert_eq!(p.opcode, Opcode::CMSG_ATTACKSWING);
        assert_eq!(
            p.body,
            vec![0xff, 0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01]
        );
    }

    #[test]
    fn pick_nearest_npc_guid_picks_closest_and_honors_entry_filter() {
        let mut ws = WorldState::new();
        let self_guid = 1u64;
        let mut self_state = PlayerCurrentState::new(self_guid);
        self_state.position.x = 0.0;
        self_state.position.y = 0.0;
        self_state.position.z = 0.0;
        ws.players.insert(self_guid, self_state);

        let mut npc1 = rusty_bot_core::world::npc_state::NpcCurrentState::new(10, 100);
        npc1.position.x = 1.0;
        let mut npc2 = rusty_bot_core::world::npc_state::NpcCurrentState::new(11, 100);
        npc2.position.x = 2.0;
        let mut npc3 = rusty_bot_core::world::npc_state::NpcCurrentState::new(12, 200);
        npc3.position.x = 0.5;
        ws.npcs.insert(npc1.guid, npc1);
        ws.npcs.insert(npc2.guid, npc2);
        ws.npcs.insert(npc3.guid, npc3);

        // No filter: closest overall is npc3.
        assert_eq!(
            ProxyAgentApi::pick_nearest_npc_guid(&ws, self_guid, None),
            Some(12)
        );
        // Filter to entry=100: closest of npc1/npc2 is npc1.
        assert_eq!(
            ProxyAgentApi::pick_nearest_npc_guid(&ws, self_guid, Some(100)),
            Some(10)
        );
        // Filter to missing entry: none.
        assert_eq!(
            ProxyAgentApi::pick_nearest_npc_guid(&ws, self_guid, Some(999)),
            None
        );
    }
}

async fn record_client_movement_observation(
    packet: &WorldPacket,
    injection_guard: &Arc<Mutex<InjectionGuardState>>,
    world_state: &Arc<Mutex<WorldState>>,
) {
    let Ok(opcode) = u16::try_from(packet.opcode) else {
        return;
    };
    if !is_world_move_opcode(opcode) {
        return;
    }

    let mut state = injection_guard.lock().await;
    state.last_client_move_at = Some(Instant::now());
    update_client_move_mask(&mut state.client_move_mask, opcode);
    // Always keep a raw movement packet template. Parsing can fail on some movement variants;
    // the demo injector should still be able to attempt reuse (or at least log useful state).
    state.last_client_move_packet = Some(packet.clone());

    if let Ok((guid, movement_info)) = try_parse_movement_payload(&packet.body) {
        state.last_self_guid.get_or_insert(guid.0);

        {
            let mut ws = world_state.lock().await;
            let player = ws
                .players
                .entry(guid.0)
                .or_insert_with(|| PlayerCurrentState::new(guid.0));
            player.position.x = movement_info.location.point.x;
            player.position.y = movement_info.location.point.y;
            player.position.z = movement_info.location.point.z;
            player.position.orientation = movement_info.location.direction;
            player.movement_flags = movement_info.movement_flags.bits();
            player.timestamp = movement_info.time as u64;
        }

        if let Some(demo_packet) = state.last_demo_packet.as_ref() {
            if let Ok((demo_guid, demo_mi)) = try_parse_movement_payload(&demo_packet.body) {
                if demo_guid == guid {
                    let dx = movement_info.location.point.x - demo_mi.location.point.x;
                    let dy = movement_info.location.point.y - demo_mi.location.point.y;
                    let dz = movement_info.location.point.z - demo_mi.location.point.z;
                    let dist_sq = dx * dx + dy * dy + dz * dz;
                    if dist_sq > 0.25 {
                        state.last_client_correction_at = Some(Instant::now());
                    }
                }
            }
        }
        state.last_client_move_time = Some(movement_info.time);
    }
}

async fn record_server_world_observation(
    packet: &WorldPacket,
    world_state: &Arc<Mutex<WorldState>>,
) {
    const SMSG_UPDATE_OBJECT: u16 = 0x00A9;
    const SMSG_MESSAGECHAT: u16 = 0x0096;
    const SMSG_ATTACKERSTATEUPDATE: u16 = 0x014A;

    let Ok(opcode) = u16::try_from(packet.opcode) else {
        return;
    };

    let mut ws = world_state.lock().await;
    match opcode {
        SMSG_UPDATE_OBJECT => {
            if let Err(err) = ws.apply_update_object(&packet.body) {
                eprintln!(
                    "proxy.world.state.update_object_failed error={err:#} body_len={}",
                    packet.body.len()
                );
            }
        }
        SMSG_MESSAGECHAT => {
            if let Some(msg) = try_parse_smsg_messagechat(&packet.body) {
                ws.add_chat_message(msg);
            }
        }
        SMSG_ATTACKERSTATEUPDATE => {
            // Keep this crude for now; better parsing can be added when needed.
            ws.add_combat_message(format!(
                "SMSG_ATTACKERSTATEUPDATE len={}",
                packet.body.len()
            ));
        }
        _ => {}
    }
    ws.increment_tick();
}

fn try_parse_smsg_messagechat(payload: &[u8]) -> Option<String> {
    use byteorder::{LittleEndian, ReadBytesExt};
    use std::io::Cursor;

    let mut cur = Cursor::new(payload);
    let _chat_type = ReadBytesExt::read_u8(&mut cur).ok()?;
    let _language = ReadBytesExt::read_u32::<LittleEndian>(&mut cur).ok()?;
    let _sender_guid = ReadBytesExt::read_u64::<LittleEndian>(&mut cur).ok()?;
    let _receiver_guid = ReadBytesExt::read_u64::<LittleEndian>(&mut cur).ok()?;

    let channel_name = read_cstring_cursor(&mut cur).unwrap_or_default();
    let sender_name = read_cstring_cursor(&mut cur).unwrap_or_default();
    let message = read_cstring_cursor(&mut cur).unwrap_or_default();
    let _chat_tag = ReadBytesExt::read_u8(&mut cur).ok().unwrap_or(0);

    if message.is_empty() {
        return None;
    }
    if !channel_name.is_empty() {
        Some(format!("[{}] {}: {}", channel_name, sender_name, message))
    } else if !sender_name.is_empty() {
        Some(format!("{}: {}", sender_name, message))
    } else {
        Some(message)
    }
}

fn read_cstring_cursor(cur: &mut std::io::Cursor<&[u8]>) -> Option<String> {
    use std::io::Read;
    let mut buf = Vec::new();
    loop {
        let mut byte = [0u8; 1];
        if Read::read_exact(cur, &mut byte).is_err() {
            return None;
        }
        if byte[0] == 0 {
            break;
        }
        buf.push(byte[0]);
        if buf.len() > 4 * 1024 {
            return None;
        }
    }
    String::from_utf8(buf).ok()
}

// Legacy demo injector removed: the in-proxy agent loop is the only runner.

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum InjectCommandOutcome {
    Injected { opcode: u32, body_len: usize },
    Suppressed,
    MissingTemplate,
    RateLimited,
}

#[derive(Debug)]
struct RateLimiter {
    llm_calls: std::collections::VecDeque<std::time::Instant>,
    injections: std::collections::VecDeque<std::time::Instant>,
    max_llm_calls_per_min: usize,
    max_injections_per_sec: usize,
}

impl RateLimiter {
    fn new(max_llm_calls_per_min: usize, max_injections_per_sec: usize) -> Self {
        Self {
            llm_calls: std::collections::VecDeque::new(),
            injections: std::collections::VecDeque::new(),
            max_llm_calls_per_min,
            max_injections_per_sec,
        }
    }

    fn allow_llm_call(&mut self, now: std::time::Instant) -> bool {
        let window = Duration::from_secs(60);
        while self
            .llm_calls
            .front()
            .map(|t| now.saturating_duration_since(*t) > window)
            .unwrap_or(false)
        {
            self.llm_calls.pop_front();
        }
        if self.llm_calls.len() >= self.max_llm_calls_per_min {
            return false;
        }
        self.llm_calls.push_back(now);
        true
    }

    fn allow_injection(&mut self, now: std::time::Instant) -> bool {
        let window = Duration::from_secs(1);
        while self
            .injections
            .front()
            .map(|t| now.saturating_duration_since(*t) > window)
            .unwrap_or(false)
        {
            self.injections.pop_front();
        }
        if self.injections.len() >= self.max_injections_per_sec {
            return false;
        }
        self.injections.push_back(now);
        true
    }
}

struct MovementTemplateInjector {
    upstream_tx: mpsc::Sender<WorldPacket>,
    downstream_tx: mpsc::Sender<WorldPacket>,
    injection_guard: Arc<Mutex<InjectionGuardState>>,
    echo_to_client: bool,
    limiter: Option<Arc<Mutex<RateLimiter>>>,
}

impl MovementTemplateInjector {
    fn new(
        upstream_tx: mpsc::Sender<WorldPacket>,
        downstream_tx: mpsc::Sender<WorldPacket>,
        injection_guard: Arc<Mutex<InjectionGuardState>>,
        echo_to_client: bool,
        limiter: Option<Arc<Mutex<RateLimiter>>>,
    ) -> Self {
        Self {
            upstream_tx,
            downstream_tx,
            injection_guard,
            echo_to_client,
            limiter,
        }
    }

    async fn get_template(&self) -> Option<WorldPacket> {
        let state = self.injection_guard.lock().await;
        state
            .last_client_move_packet
            .clone()
            .or(state.last_demo_packet.clone())
    }

    async fn build_movement_packet_for_command(&self, cmd: &str) -> Option<WorldPacket> {
        // Keep using the existing demo builder (it already handles the movement time template and emotes).
        prepare_demo_packet(cmd, &self.injection_guard).await
    }

    async fn apply_guard(&self, packet: WorldPacket) -> Option<WorldPacket> {
        apply_injection_guard(packet, &self.injection_guard).await
    }

    async fn send(&self, packet: WorldPacket) -> anyhow::Result<()> {
        if let Some(limiter) = self.limiter.as_ref() {
            let ok = limiter
                .lock()
                .await
                .allow_injection(std::time::Instant::now());
            if !ok {
                anyhow::bail!("rate_limited");
            }
        }
        send_injected_packet(
            packet,
            &self.upstream_tx,
            &self.downstream_tx,
            self.echo_to_client,
        )
        .await
    }

    async fn inject_command(&self, cmd: &str) -> anyhow::Result<InjectCommandOutcome> {
        if self.get_template().await.is_none() && !cmd.starts_with("emote ") {
            return Ok(InjectCommandOutcome::MissingTemplate);
        }

        let Some(packet) = self.build_movement_packet_for_command(cmd).await else {
            return Ok(InjectCommandOutcome::MissingTemplate);
        };
        let Some(packet) = self.apply_guard(packet).await else {
            return Ok(InjectCommandOutcome::Suppressed);
        };
        let opcode = packet.opcode;
        let body_len = packet.body.len();
        match self.send(packet).await {
            Ok(()) => {}
            Err(err) if format!("{err:#}").contains("rate_limited") => {
                return Ok(InjectCommandOutcome::RateLimited);
            }
            Err(err) => return Err(err),
        }
        Ok(InjectCommandOutcome::Injected { opcode, body_len })
    }
}

struct ProxyAgentApi {
    upstream_tx: mpsc::Sender<WorldPacket>,
    downstream_tx: mpsc::Sender<WorldPacket>,
    injection_guard: Arc<Mutex<InjectionGuardState>>,
    world_state: Arc<Mutex<WorldState>>,
    observation_builder: Mutex<AgentObservationBuilder>,
    echo_to_client: bool,
    limiter: Arc<Mutex<RateLimiter>>,
}

impl ProxyAgentApi {
    fn pick_nearest_npc_guid(
        ws: &WorldState,
        self_guid: u64,
        entry: Option<u32>,
    ) -> Option<u64> {
        let self_pos = ws.players.get(&self_guid).map(|p| p.position.clone())?;
        let mut best: Option<(u64, f32)> = None;
        for npc in ws.npcs.values() {
            if let Some(entry) = entry {
                if npc.entry != entry {
                    continue;
                }
            }
            let dx = npc.position.x - self_pos.x;
            let dy = npc.position.y - self_pos.y;
            let dz = npc.position.z - self_pos.z;
            let dist_sq = dx * dx + dy * dy + dz * dz;
            match best {
                None => best = Some((npc.guid, dist_sq)),
                Some((_, best_sq)) if dist_sq < best_sq => best = Some((npc.guid, dist_sq)),
                _ => {}
            }
        }
        best.map(|(g, _)| g)
    }

    async fn send_packet(&self, packet: WorldPacket) -> anyhow::Result<AgentToolStatus> {
        let ok = self
            .limiter
            .lock()
            .await
            .allow_injection(std::time::Instant::now());
        if !ok {
            return Ok(AgentToolStatus::Retryable);
        }

        let packet = apply_injection_guard(packet, &self.injection_guard).await;
        let Some(packet) = packet else {
            return Ok(AgentToolStatus::Retryable);
        };
        self.upstream_tx
            .send(packet.clone())
            .await
            .map_err(|_| anyhow::anyhow!("upstream channel closed"))?;

        // Never echo to the client by default for non-movement packets (unsafe). This matches
        // the existing send_injected_packet behavior for upstream-only opcodes.
        if self.echo_to_client {
            let _ = self.downstream_tx.send(packet).await;
        }

        Ok(AgentToolStatus::Ok)
    }

    fn tool_to_demo_command(tool: &AgentToolCall) -> Vec<String> {
        use rusty_bot_core::agent::wire::{MoveDirection, StopKind, TurnDirection};
        match tool {
            AgentToolCall::RequestIdle => vec!["move stop".to_string()],
            AgentToolCall::RequestJump => vec!["jump".to_string()],
            AgentToolCall::RequestEmote(args) => vec![format!("emote {}", args.key)],
            AgentToolCall::RequestMove(args) => {
                let cmd = match args.direction {
                    MoveDirection::Forward => "move forward",
                    MoveDirection::Backward => "move backward",
                    MoveDirection::Left => "move left",
                    MoveDirection::Right => "move right",
                };
                vec![cmd.to_string()]
            }
            AgentToolCall::RequestTurn(args) => {
                let cmd = match args.direction {
                    TurnDirection::Left => "turn left",
                    TurnDirection::Right => "turn right",
                };
                vec![cmd.to_string()]
            }
            AgentToolCall::RequestStop(args) => match args.kind {
                StopKind::Move => vec!["move stop".to_string()],
                StopKind::Turn => vec!["turn stop".to_string()],
                StopKind::Strafe => vec!["strafe stop".to_string()],
                StopKind::All => vec![
                    "turn stop".to_string(),
                    "strafe stop".to_string(),
                    "move stop".to_string(),
                ],
            },
            AgentToolCall::TargetGuid(_)
            | AgentToolCall::TargetNearestNpc(_)
            | AgentToolCall::Interact(_)
            | AgentToolCall::Cast(_) => vec![],
        }
    }
}

impl AgentGameApi for ProxyAgentApi {
    fn observe<'a>(
        &'a self,
    ) -> std::pin::Pin<
        Box<
            dyn std::future::Future<
                    Output = anyhow::Result<rusty_bot_core::agent::observation::Observation>,
                > + Send
                + 'a,
        >,
    > {
        Box::pin(async move {
            let now = Instant::now();
            let guard = self.injection_guard.lock().await;
            let self_guid = guard.last_self_guid.unwrap_or(0);
            let client_correction_seen_recently = guard
                .last_client_correction_at
                .map(|t| now.duration_since(t) < Duration::from_secs(2))
                .unwrap_or(false);
            drop(guard);

            let ws = self.world_state.lock().await;
            let mut b = self.observation_builder.lock().await;
            Ok(b.build(
                &ws,
                AgentObservationInputs {
                    self_guid,
                    client_correction_seen_recently,
                },
            ))
        })
    }

    fn execute_tool<'a>(
        &'a self,
        tool: AgentToolInvocation,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = anyhow::Result<AgentToolResult>> + Send + 'a>,
    > {
        Box::pin(async move {
            if tool.requires_confirm() && !tool.confirm {
                return Ok(AgentToolResult {
                    status: AgentToolStatus::Failed,
                    reason: "confirm_required".to_string(),
                    facts: serde_json::Value::Null,
                });
            }

            match &tool.call {
                AgentToolCall::TargetGuid(args) => {
                    let status = self.send_packet(build_cmsg_set_selection(args.guid)).await?;
                    let reason = if status == AgentToolStatus::Ok {
                        "set_selection".to_string()
                    } else {
                        "retryable".to_string()
                    };
                    return Ok(AgentToolResult {
                        status,
                        reason,
                        facts: serde_json::json!({ "guid": args.guid }),
                    });
                }
                AgentToolCall::TargetNearestNpc(args) => {
                    let self_guid = self.injection_guard.lock().await.last_self_guid.unwrap_or(0);
                    let ws = self.world_state.lock().await;
                    let Some(guid) =
                        Self::pick_nearest_npc_guid(&ws, self_guid, args.entry)
                    else {
                        return Ok(AgentToolResult {
                            status: AgentToolStatus::Failed,
                            reason: "no_npc_found".to_string(),
                            facts: serde_json::json!({ "entry": args.entry }),
                        });
                    };
                    drop(ws);
                    let status = self.send_packet(build_cmsg_set_selection(guid)).await?;
                    let reason = if status == AgentToolStatus::Ok {
                        "set_selection".to_string()
                    } else {
                        "retryable".to_string()
                    };
                    return Ok(AgentToolResult {
                        status,
                        reason,
                        facts: serde_json::json!({ "guid": guid, "entry": args.entry }),
                    });
                }
                AgentToolCall::Interact(args) => {
                    let status = self.send_packet(build_cmsg_gossip_hello(args.guid)).await?;
                    let reason = if status == AgentToolStatus::Ok {
                        "gossip_hello".to_string()
                    } else {
                        "retryable".to_string()
                    };
                    return Ok(AgentToolResult {
                        status,
                        reason,
                        facts: serde_json::json!({ "guid": args.guid }),
                    });
                }
                AgentToolCall::Cast(args) => {
                    // V0 combat: we don't have action bar state, so "cast" is implemented as a
                    // best-effort attackswing (autoattack) against an explicitly provided guid.
                    let Some(guid) = args.guid else {
                        return Ok(AgentToolResult {
                            status: AgentToolStatus::Failed,
                            reason: "cast_missing_guid".to_string(),
                            facts: serde_json::json!({ "slot": args.slot }),
                        });
                    };
                    let status = self.send_packet(build_cmsg_attackswing(guid)).await?;
                    let reason = if status == AgentToolStatus::Ok {
                        "attackswing".to_string()
                    } else {
                        "retryable".to_string()
                    };
                    return Ok(AgentToolResult {
                        status,
                        reason,
                        facts: serde_json::json!({ "guid": guid, "slot": args.slot, "impl": "attackswing_v0" }),
                    });
                }
                _ => {}
            }

            let cmds = Self::tool_to_demo_command(&tool.call);
            if cmds.is_empty() {
                return Ok(AgentToolResult {
                    status: AgentToolStatus::Failed,
                    reason: "no_command".to_string(),
                    facts: serde_json::Value::Null,
                });
            }

            let injector = MovementTemplateInjector::new(
                self.upstream_tx.clone(),
                self.downstream_tx.clone(),
                self.injection_guard.clone(),
                self.echo_to_client,
                Some(self.limiter.clone()),
            );
            for cmd in cmds {
                match injector.inject_command(&cmd).await? {
                    InjectCommandOutcome::Injected { .. } => {}
                    InjectCommandOutcome::Suppressed => {
                        return Ok(AgentToolResult {
                            status: AgentToolStatus::Retryable,
                            reason: "injection_suppressed".to_string(),
                            facts: serde_json::json!({ "cmd": cmd }),
                        });
                    }
                    InjectCommandOutcome::MissingTemplate => {
                        return Ok(AgentToolResult {
                            status: AgentToolStatus::Retryable,
                            reason: "missing_movement_template".to_string(),
                            facts: serde_json::json!({ "cmd": cmd }),
                        });
                    }
                    InjectCommandOutcome::RateLimited => {
                        return Ok(AgentToolResult {
                            status: AgentToolStatus::Retryable,
                            reason: "rate_limited".to_string(),
                            facts: serde_json::json!({ "cmd": cmd }),
                        });
                    }
                }
            }

            Ok(AgentToolResult {
                status: AgentToolStatus::Ok,
                reason: "injected".to_string(),
                facts: serde_json::Value::Null,
            })
        })
    }
}

#[derive(Debug)]
struct ProxyLlmClient {
    client: reqwest::Client,
    endpoint: String,
    model: String,
    limiter: Arc<Mutex<RateLimiter>>,
}

#[derive(Debug)]
struct LlmPollFailed(reqwest::Error);

impl std::fmt::Display for LlmPollFailed {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "llm_poll_failed: {}", self.0)
    }
}

impl std::error::Error for LlmPollFailed {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.0)
    }
}

impl AgentLlmClient for ProxyLlmClient {
    fn complete<'a>(
        &'a self,
        prompt: String,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = anyhow::Result<String>> + Send + 'a>>
    {
        Box::pin(async move {
            // LLM call rate limiting is handled here so the harness only consumes a token when it
            // actually needs to poll the model.
            let ok = self
                .limiter
                .lock()
                .await
                .allow_llm_call(std::time::Instant::now());
            if !ok {
                return Err(anyhow::Error::new(AgentLlmCallSuppressed));
            }

            let resp = self
                .client
                .post(&self.endpoint)
                .json(&serde_json::json!({
                    "model": self.model,
                    "prompt": prompt,
                    "stream": false
                }))
                .send()
                .await
                .map_err(|e| anyhow::Error::new(LlmPollFailed(e)))?;

            let resp = resp
                .error_for_status()
                .map_err(|e| anyhow::Error::new(LlmPollFailed(e)))?;

            let payload: serde_json::Value = resp
                .json()
                .await
                .map_err(|e| anyhow::Error::new(LlmPollFailed(e)))?;

            let script = payload
                .get("response")
                .and_then(serde_json::Value::as_str)
                .or_else(|| {
                    payload
                        .get("message")
                        .and_then(|m| m.get("content"))
                        .and_then(serde_json::Value::as_str)
                })
                .unwrap_or("")
                .to_string();

            Ok(script)
        })
    }
}

async fn run_agent_llm_injector(
    upstream_tx: mpsc::Sender<WorldPacket>,
    downstream_tx: mpsc::Sender<WorldPacket>,
    injection_guard: Arc<Mutex<InjectionGuardState>>,
    world_state: Arc<Mutex<WorldState>>,
    mut control_rx: mpsc::Receiver<AgentControlCommand>,
) -> anyhow::Result<()> {
    let start_enabled = std::env::var("RUSTY_BOT_AGENT_ENABLED")
        .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
        .unwrap_or(false);

    let endpoint = std::env::var("RUSTY_BOT_LLM_ENDPOINT")
        .unwrap_or_else(|_| "http://127.0.0.1:11435/api/generate".to_string());
    let model = std::env::var("RUSTY_BOT_LLM_MODEL").unwrap_or_else(|_| "mock".to_string());
    let use_vision = std::env::var("RUSTY_BOT_AGENT_USE_VISION")
        .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
        .unwrap_or(true);
    let system_prompt = std::env::var("RUSTY_BOT_LLM_SYSTEM_PROMPT").unwrap_or_else(|_| {
        "You control a WoW character. Choose exactly one tool call per tick based on STATE_JSON. Prefer safe, minimal actions."
            .to_string()
    });
    let goal = std::env::var("RUSTY_BOT_GOAL").ok();
    let echo_to_client = std::env::var("RUSTY_BOT_UNSAFE_ECHO_INJECTED_TO_CLIENT")
        .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
        .unwrap_or(false);
    let max_llm_calls_per_min: usize = std::env::var("RUSTY_BOT_LLM_MAX_CALLS_PER_MIN")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(60);
    let max_injections_per_sec: usize = std::env::var("RUSTY_BOT_INJECT_MAX_PER_SEC")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(25);

    println!(
        "proxy.bot.agent started enabled={} endpoint={} model={} use_vision={}",
        start_enabled, endpoint, model, use_vision
    );

    let limiter = Arc::new(Mutex::new(RateLimiter::new(
        max_llm_calls_per_min,
        max_injections_per_sec,
    )));
    let api = ProxyAgentApi {
        upstream_tx,
        downstream_tx,
        injection_guard: injection_guard.clone(),
        world_state: world_state.clone(),
        observation_builder: Mutex::new(AgentObservationBuilder::default()),
        echo_to_client,
        limiter: limiter.clone(),
    };

    let client = reqwest::Client::builder()
        .timeout(Duration::from_millis(1200))
        .build()?;
    let llm = ProxyLlmClient {
        client,
        endpoint: endpoint.clone(),
        model: model.clone(),
        limiter: limiter.clone(),
    };
    let mut tick = tokio::time::interval(Duration::from_millis(350));
    tick.set_missed_tick_behavior(MissedTickBehavior::Skip);

    let mut agent = AgentLoop::new(system_prompt);
    if let Some(goal) = goal {
        agent.memory.set_goal(goal);
    }
    let mut enabled = start_enabled;

    loop {
        tokio::select! {
            _ = tick.tick() => {
                if !enabled {
                    continue;
                }

                let prompt_suffix = if use_vision {
                    let guid = injection_guard.lock().await.last_self_guid.unwrap_or(0);
                    let ws = world_state.lock().await;
                    let vision = generate_vision_prompt(&ws, guid);
                    Some(format!("\n[LEGACY_VISION]\n{vision}"))
                } else {
                    None
                };

                let cfg = AgentHarnessConfig {
                    enable_repair: true,
                    prompt_suffix,
                };

                let now = std::time::Instant::now();
                let out = agent_tick(&mut agent, &api, &llm, cfg, now).await;
                match out {
                    Ok(AgentHarnessOutcome::Completed { tool, result }) => {
                        println!(
                            "proxy.bot.agent complete tool={tool:?} status={:?} reason={}",
                            result.status, result.reason
                        );
                    }
                    Ok(AgentHarnessOutcome::Executed { .. })
                    | Ok(AgentHarnessOutcome::Offered { .. })
                    | Ok(AgentHarnessOutcome::Observed) => {}
                    Err(err) => {
                        if err.is::<LlmPollFailed>() {
                            eprintln!("proxy.bot.agent poll_failed error={err:#}");
                            // When the LLM is down, do not keep issuing movement. Prefer hard stops.
                            for stop in [
                                AgentToolInvocation {
                                    call: AgentToolCall::RequestStop(
                                        rusty_bot_core::agent::wire::RequestStopArgs {
                                            kind: rusty_bot_core::agent::wire::StopKind::Turn,
                                        },
                                    ),
                                    confirm: false,
                                },
                                AgentToolInvocation {
                                    call: AgentToolCall::RequestStop(
                                        rusty_bot_core::agent::wire::RequestStopArgs {
                                            kind: rusty_bot_core::agent::wire::StopKind::Strafe,
                                        },
                                    ),
                                    confirm: false,
                                },
                                AgentToolInvocation {
                                    call: AgentToolCall::RequestStop(
                                        rusty_bot_core::agent::wire::RequestStopArgs {
                                            kind: rusty_bot_core::agent::wire::StopKind::Move,
                                        },
                                    ),
                                    confirm: false,
                                },
                            ] {
                                let _ = api.execute_tool(stop).await;
                            }
                            continue;
                        }
                        return Err(err);
                    }
                }
            }
            cmd = control_rx.recv() => {
                let Some(cmd) = cmd else {
                    // Control channel closed; keep running.
                    continue;
                };
                match cmd {
                    AgentControlCommand::Enable(next) => {
                        enabled = next;
                        if !enabled {
                            // Stop any continuous inputs immediately, then reset executor state so we don't
                            // restart a queued action if re-enabled later.
                            for stop in [
                                AgentToolInvocation {
                                    call: AgentToolCall::RequestStop(
                                        rusty_bot_core::agent::wire::RequestStopArgs {
                                            kind: rusty_bot_core::agent::wire::StopKind::Turn,
                                        },
                                    ),
                                    confirm: false,
                                },
                                AgentToolInvocation {
                                    call: AgentToolCall::RequestStop(
                                        rusty_bot_core::agent::wire::RequestStopArgs {
                                            kind: rusty_bot_core::agent::wire::StopKind::Strafe,
                                        },
                                    ),
                                    confirm: false,
                                },
                                AgentToolInvocation {
                                    call: AgentToolCall::RequestStop(
                                        rusty_bot_core::agent::wire::RequestStopArgs {
                                            kind: rusty_bot_core::agent::wire::StopKind::Move,
                                        },
                                    ),
                                    confirm: false,
                                },
                            ] {
                                let _ = api.execute_tool(stop).await;
                            }
                            agent.executor = rusty_bot_core::agent::executor::Executor::default();
                        }
                    }
                    AgentControlCommand::SetGoal(goal) => {
                        agent.memory.set_goal(goal);
                    }
                    AgentControlCommand::ClearGoal => {
                        agent.memory.clear_goal();
                    }
                    AgentControlCommand::OfferTool(tool) => {
                        agent.executor.offer_llm_tool(tool);
                    }
                    AgentControlCommand::ExecuteTool { tool, reply } => {
                        let mut res = match api.execute_tool(tool.clone()).await {
                            Ok(res) => res,
                            Err(err) => AgentToolResult {
                                status: AgentToolStatus::Failed,
                                reason: format!("execute_failed: {err:#}"),
                                facts: serde_json::Value::Null,
                            },
                        };

                        // Record it for visibility/debugging; these are still "actions taken".
                        agent.memory.record(tool, res.clone());

                        // For discrete tools, treat retryable as failed; there is no executor retry path here.
                        if res.status == AgentToolStatus::Retryable {
                            res.status = AgentToolStatus::Failed;
                            res.reason = format!("retryable_in_tool_execute: {}", res.reason);
                        }

                        let _ = reply.send(res);
                    }
                    AgentControlCommand::Status { reply } => {
                        let _ = reply.send(serde_json::json!({
                            "ok": true,
                            "enabled": enabled,
                            "goal": agent.memory.goal.clone(),
                            "goal_id": agent.memory.goal_id,
                            "goal_state": agent.memory.goal_state,
                            "goal_state_reason": agent.memory.goal_state_reason,
                            "last_error": agent.memory.last_error.clone(),
                            "executor_state": format!("{:?}", agent.executor.state),
                            "history_len": agent.memory.history.len(),
                        }));
                    }
                }
            }
        }
    }
}

fn text_emote_id(name: &str) -> Option<u32> {
    // Partial list; extend as needed.
    match name {
        "wave" => Some(101),
        "hello" => Some(55),
        "bye" => Some(19),
        "cheer" => Some(21),
        "dance" => Some(34),
        "laugh" => Some(60),
        "clap" => Some(24),
        "salute" => Some(78),
        _ => None,
    }
}

fn build_cmsg_text_emote(text_emote: u32, emote_num: u32, target_guid: u64) -> WorldPacket {
    // Common WotLK layout (client->server): text_emote(u32), emote_num(u32), guid(u64).
    // If `target_guid` is 0, the server treats it as "no target" (varies by core).
    let mut body = Vec::with_capacity(4 + 4 + 8);
    body.extend_from_slice(&text_emote.to_le_bytes());
    body.extend_from_slice(&emote_num.to_le_bytes());
    body.extend_from_slice(&target_guid.to_le_bytes());
    WorldPacket {
        opcode: Opcode::CMSG_TEXT_EMOTE as u32,
        body,
    }
}

fn build_cmsg_set_selection(target_guid: u64) -> WorldPacket {
    // WotLK layout: Guid(u64).
    let mut body = Vec::with_capacity(8);
    body.extend_from_slice(&target_guid.to_le_bytes());
    WorldPacket {
        opcode: Opcode::CMSG_SET_SELECTION,
        body,
    }
}

fn build_cmsg_gossip_hello(target_guid: u64) -> WorldPacket {
    // WotLK layout: Guid(u64).
    let mut body = Vec::with_capacity(8);
    body.extend_from_slice(&target_guid.to_le_bytes());
    WorldPacket {
        opcode: Opcode::CMSG_GOSSIP_HELLO,
        body,
    }
}

fn build_cmsg_attackswing(target_guid: u64) -> WorldPacket {
    // WotLK layout: PackedGuid.
    let mut body = Vec::with_capacity(9);
    let mut cur = Cursor::new(&mut body);
    // BinWrite impl expects a Seek-able writer. Cursor<Vec<u8>> works.
    let _ = PackedGuid(target_guid).write_options(&mut cur, Endian::Little, ());
    WorldPacket {
        opcode: Opcode::CMSG_ATTACKSWING,
        body,
    }
}

async fn prepare_demo_packet(
    command: &str,
    injection_guard: &Arc<Mutex<InjectionGuardState>>,
) -> Option<WorldPacket> {
    if let Some(arg) = command.strip_prefix("emote ") {
        let name = arg.trim();
        let id = text_emote_id(name)?;

        // Prefer last seen movement GUID (usually "self" for the real client).
        let target_guid = {
            let state = injection_guard.lock().await;
            state
                .last_client_move_packet
                .as_ref()
                .and_then(|p| try_parse_movement_payload(&p.body).ok().map(|(g, _)| g.0))
                .unwrap_or(0)
        };

        return Some(build_cmsg_text_emote(id, 0, target_guid));
    }

    let mut state = injection_guard.lock().await;
    let now = Instant::now();
    let delta_ms = state
        .last_demo_inject_at
        .map(|t| now.saturating_duration_since(t).as_millis() as u32)
        .unwrap_or(200)
        .clamp(120, 2_000);
    let template = state
        .last_client_move_packet
        .clone()
        .or(state.last_demo_packet.clone())?;
    let (packet, next_time) =
        build_demo_packet_from_template(&template, command, state.last_client_move_time, delta_ms)?;
    if let Some(next_time) = next_time {
        state.last_client_move_time = Some(next_time);
    }
    state.last_demo_packet = Some(packet.clone());
    state.last_demo_inject_at = Some(now);
    Some(packet)
}

fn build_demo_packet_from_template(
    template: &WorldPacket,
    command: &str,
    last_time: Option<u32>,
    delta_ms: u32,
) -> Option<(WorldPacket, Option<u32>)> {
    let opcode = map_demo_command_to_opcode(command)? as u32;

    let parsed = try_parse_movement_payload(&template.body);
    if parsed.is_err() && command.eq_ignore_ascii_case("jump") {
        // Jump is the one demo opcode where the server is very likely to expect
        // a specific payload shape. If we can't parse the template, do not guess.
        println!(
            "proxy.bot.demo jump_template_unparseable template_opcode=0x{:04x} template_body_len={} action=drop",
            template.opcode,
            template.body.len(),
        );
        return None;
    }

    if let Ok((guid, mut movement_info)) = parsed {
        apply_demo_command_to_movement(&mut movement_info, command)?;
        demo_advance_kinematics(&mut movement_info, &command.to_ascii_lowercase(), delta_ms);
        let next_time = last_time
            .unwrap_or(movement_info.time)
            .wrapping_add(delta_ms);
        movement_info.time = next_time;
        let body = pack_movement_payload(guid, &movement_info).ok()?;

        if command.eq_ignore_ascii_case("jump") {
            match try_parse_movement_payload(&body) {
                Ok((_g, parsed_mi)) => {
                    let ok = parsed_mi.movement_flags.contains(MovementFlags::JUMPING)
                        && parsed_mi.jump_info.is_some();
                    if !ok {
                        println!(
                            "proxy.bot.demo jump_payload_invalid opcode=0x{:04x} jumping_flag={} jump_info_present={} action=drop",
                            opcode,
                            parsed_mi.movement_flags.contains(MovementFlags::JUMPING),
                            parsed_mi.jump_info.is_some(),
                        );
                        return None;
                    }
                }
                Err(_) => {
                    println!(
                        "proxy.bot.demo jump_payload_unparseable opcode=0x{:04x} body_len={} action=drop",
                        opcode,
                        body.len(),
                    );
                    return None;
                }
            }
        }

        return Some((WorldPacket { opcode, body }, Some(next_time)));
    }

    Some((
        WorldPacket {
            opcode,
            body: template.body.clone(),
        },
        last_time,
    ))
}

fn map_demo_command_to_opcode(command: &str) -> Option<u16> {
    match command.to_ascii_lowercase().as_str() {
        // Use the same start/stop opcodes as a real client would. Some cores treat
        // HEARTBEAT as a pure position update and do not apply movement-state changes from it.
        "move forward" => Some(Opcode::MSG_MOVE_START_FORWARD),
        "move backward" => Some(Opcode::MSG_MOVE_START_BACKWARD),
        "move stop" => Some(Opcode::MSG_MOVE_STOP),
        "move left" => Some(Opcode::MSG_MOVE_START_STRAFE_LEFT),
        "move right" => Some(Opcode::MSG_MOVE_START_STRAFE_RIGHT),
        "strafe stop" => Some(Opcode::MSG_MOVE_STOP_STRAFE),
        "turn left" => Some(Opcode::MSG_MOVE_START_TURN_LEFT),
        "turn right" => Some(Opcode::MSG_MOVE_START_TURN_RIGHT),
        "turn stop" => Some(Opcode::MSG_MOVE_STOP_TURN),
        "jump" => Some(Opcode::MSG_MOVE_JUMP),
        _ => None,
    }
}

fn demo_advance_kinematics(movement_info: &mut MovementInfo, command: &str, delta_ms: u32) {
    // Tiny, conservative kinematics. This is intentionally simple and should remain
    // bounded so any server-side validation/corrections can take effect.
    let secs = (delta_ms as f32 / 1000.0).clamp(0.05, 0.8);
    let yaw = movement_info.location.direction;

    // Slow speed reduces "tunneling" through collision checks (if any).
    let move_speed = 1.8_f32; // yards/sec
    let turn_speed = 1.6_f32; // rad/sec

    match command {
        "turn left" => {
            movement_info.location.direction = yaw + turn_speed * secs;
        }
        "turn right" => {
            movement_info.location.direction = yaw - turn_speed * secs;
        }
        "turn stop" => {}
        "move forward" | "move backward" | "move left" | "move right" => {
            let dist = move_speed
                * secs
                * if command == "move backward" {
                    -1.0
                } else {
                    1.0
                };
            let (dx, dy) = match command {
                "move forward" | "move backward" => (yaw.cos(), yaw.sin()),
                "move left" => (
                    (yaw + std::f32::consts::FRAC_PI_2).cos(),
                    (yaw + std::f32::consts::FRAC_PI_2).sin(),
                ),
                "move right" => (
                    (yaw - std::f32::consts::FRAC_PI_2).cos(),
                    (yaw - std::f32::consts::FRAC_PI_2).sin(),
                ),
                _ => (0.0, 0.0),
            };

            movement_info.location.point.x += dx * dist;
            movement_info.location.point.y += dy * dist;
        }
        _ => {}
    }
}

fn apply_demo_command_to_movement(movement_info: &mut MovementInfo, command: &str) -> Option<()> {
    match command.to_ascii_lowercase().as_str() {
        "move forward" => {
            movement_info.movement_flags.remove(
                MovementFlags::BACKWARD
                    | MovementFlags::STRAFE_LEFT
                    | MovementFlags::STRAFE_RIGHT
                    | MovementFlags::LEFT
                    | MovementFlags::RIGHT
                    | MovementFlags::PENDING_FORWARD
                    | MovementFlags::PENDING_BACKWARD
                    | MovementFlags::PENDING_STOP,
            );
            movement_info.movement_flags.insert(MovementFlags::FORWARD);
            movement_info
                .movement_flags
                .remove(MovementFlags::JUMPING | MovementFlags::FALLING_FAR);
            movement_info.jump_info = None;
        }
        "move backward" => {
            movement_info.movement_flags.remove(
                MovementFlags::FORWARD
                    | MovementFlags::STRAFE_LEFT
                    | MovementFlags::STRAFE_RIGHT
                    | MovementFlags::LEFT
                    | MovementFlags::RIGHT
                    | MovementFlags::PENDING_FORWARD
                    | MovementFlags::PENDING_BACKWARD
                    | MovementFlags::PENDING_STOP,
            );
            movement_info.movement_flags.insert(MovementFlags::BACKWARD);
            movement_info
                .movement_flags
                .remove(MovementFlags::JUMPING | MovementFlags::FALLING_FAR);
            movement_info.jump_info = None;
        }
        "move stop" => {
            movement_info.movement_flags.remove(
                MovementFlags::FORWARD
                    | MovementFlags::BACKWARD
                    | MovementFlags::STRAFE_LEFT
                    | MovementFlags::STRAFE_RIGHT
                    | MovementFlags::LEFT
                    | MovementFlags::RIGHT
                    | MovementFlags::PENDING_FORWARD
                    | MovementFlags::PENDING_BACKWARD
                    | MovementFlags::PENDING_STOP,
            );
            movement_info
                .movement_flags
                .remove(MovementFlags::JUMPING | MovementFlags::FALLING_FAR);
            movement_info.jump_info = None;
        }
        "move left" => {
            // Some clients/cores set NO_STRAFE depending on control scheme. For demo "move left/right"
            // we want real strafing, not a forced turn.
            movement_info
                .movement_extra_flags
                .remove(MovementExtraFlags::NO_STRAFE);
            movement_info.movement_flags.remove(
                MovementFlags::STRAFE_RIGHT
                    | MovementFlags::FORWARD
                    | MovementFlags::BACKWARD
                    | MovementFlags::LEFT
                    | MovementFlags::RIGHT
                    | MovementFlags::PENDING_FORWARD
                    | MovementFlags::PENDING_BACKWARD
                    | MovementFlags::PENDING_STOP
                    | MovementFlags::PENDING_STRAFE_LEFT
                    | MovementFlags::PENDING_STRAFE_RIGHT
                    | MovementFlags::PENDING_STRAFE_STOP,
            );
            movement_info
                .movement_flags
                .insert(MovementFlags::STRAFE_LEFT);
            movement_info
                .movement_flags
                .remove(MovementFlags::JUMPING | MovementFlags::FALLING_FAR);
            movement_info.jump_info = None;
        }
        "move right" => {
            movement_info
                .movement_extra_flags
                .remove(MovementExtraFlags::NO_STRAFE);
            movement_info.movement_flags.remove(
                MovementFlags::STRAFE_LEFT
                    | MovementFlags::FORWARD
                    | MovementFlags::BACKWARD
                    | MovementFlags::LEFT
                    | MovementFlags::RIGHT
                    | MovementFlags::PENDING_FORWARD
                    | MovementFlags::PENDING_BACKWARD
                    | MovementFlags::PENDING_STOP
                    | MovementFlags::PENDING_STRAFE_LEFT
                    | MovementFlags::PENDING_STRAFE_RIGHT
                    | MovementFlags::PENDING_STRAFE_STOP,
            );
            movement_info
                .movement_flags
                .insert(MovementFlags::STRAFE_RIGHT);
            movement_info
                .movement_flags
                .remove(MovementFlags::JUMPING | MovementFlags::FALLING_FAR);
            movement_info.jump_info = None;
        }
        "strafe stop" => {
            movement_info.movement_flags.remove(
                MovementFlags::STRAFE_LEFT
                    | MovementFlags::STRAFE_RIGHT
                    | MovementFlags::PENDING_STRAFE_LEFT
                    | MovementFlags::PENDING_STRAFE_RIGHT
                    | MovementFlags::PENDING_STRAFE_STOP,
            );
        }
        "turn left" => {
            movement_info.movement_flags.remove(
                MovementFlags::RIGHT
                    | MovementFlags::STRAFE_LEFT
                    | MovementFlags::STRAFE_RIGHT
                    | MovementFlags::PENDING_STRAFE_LEFT
                    | MovementFlags::PENDING_STRAFE_RIGHT
                    | MovementFlags::PENDING_STRAFE_STOP,
            );
            movement_info.movement_flags.insert(MovementFlags::LEFT);
        }
        "turn right" => {
            movement_info.movement_flags.remove(
                MovementFlags::LEFT
                    | MovementFlags::STRAFE_LEFT
                    | MovementFlags::STRAFE_RIGHT
                    | MovementFlags::PENDING_STRAFE_LEFT
                    | MovementFlags::PENDING_STRAFE_RIGHT
                    | MovementFlags::PENDING_STRAFE_STOP,
            );
            movement_info.movement_flags.insert(MovementFlags::RIGHT);
        }
        "turn stop" => {
            movement_info
                .movement_flags
                .remove(MovementFlags::LEFT | MovementFlags::RIGHT);
        }
        "jump" => {
            movement_info.movement_flags.insert(MovementFlags::JUMPING);
            movement_info
                .movement_extra_flags
                .remove(MovementExtraFlags::NO_JUMPING);
            // In WotLK movement packets, setting JUMPING requires including JumpInfo in the payload.
            // If we reuse a non-jump template and only flip the flag, the server will try to parse
            // JumpInfo and throw a ByteBufferException due to truncated payload.
            if movement_info.jump_info.is_none() {
                movement_info.jump_info = Some(JumpInfo {
                    vertical_speed: 7.0,
                    sin_angle: 0.0,
                    cos_angle: 1.0,
                    horizontal_speed: 0.0,
                });
            }
        }
        _ => return None,
    }
    Some(())
}

async fn apply_injection_guard(
    mut packet: WorldPacket,
    injection_guard: &Arc<Mutex<InjectionGuardState>>,
) -> Option<WorldPacket> {
    let Ok(opcode) = u16::try_from(packet.opcode) else {
        return Some(packet);
    };
    if !is_world_move_opcode(opcode) {
        return Some(packet);
    }

    let mut state = injection_guard.lock().await;
    let client_active_recently = state
        .last_client_move_at
        .map(|t| t.elapsed() < Duration::from_millis(250))
        .unwrap_or(false);
    let client_correction_recently = state
        .last_client_correction_at
        .map(|t| t.elapsed() < Duration::from_millis(180))
        .unwrap_or(false);

    if client_active_recently && state.client_move_mask != 0 {
        state.suppressed_count = state.suppressed_count.saturating_add(1);
        if state.suppressed_count <= 50 || state.suppressed_count.is_multiple_of(100) {
            println!(
                "proxy.control.suppressed opcode=0x{:04x} reason=client-active mask={} count={}",
                packet.opcode, state.client_move_mask, state.suppressed_count
            );
        }
        return None;
    }
    if client_correction_recently {
        state.suppressed_count = state.suppressed_count.saturating_add(1);
        if state.suppressed_count <= 50 || state.suppressed_count.is_multiple_of(100) {
            println!(
                "proxy.control.suppressed opcode=0x{:04x} reason=client-correction count={}",
                packet.opcode, state.suppressed_count
            );
        }
        return None;
    }

    if let Some(base_time) = state.last_client_move_time {
        if let Ok((guid, mut movement_info)) = try_parse_movement_payload(&packet.body) {
            let desired = base_time.wrapping_add(50);
            if movement_info.time.wrapping_sub(desired) > (u32::MAX / 2)
                || movement_info.time < desired
            {
                movement_info.time = desired;
                if let Ok(body) = pack_movement_payload(guid, &movement_info) {
                    packet.body = body;
                }
            }
        }
    }

    Some(packet)
}

fn update_client_move_mask(mask: &mut u8, opcode: u16) {
    const MOVE_FWD_BACK: u8 = 0b001;
    const MOVE_STRAFE: u8 = 0b010;
    const MOVE_TURN: u8 = 0b100;

    match opcode {
        Opcode::MSG_MOVE_START_FORWARD | Opcode::MSG_MOVE_START_BACKWARD => {
            *mask |= MOVE_FWD_BACK;
        }
        Opcode::MSG_MOVE_STOP => {
            *mask &= !MOVE_FWD_BACK;
        }
        Opcode::MSG_MOVE_START_STRAFE_LEFT | Opcode::MSG_MOVE_START_STRAFE_RIGHT => {
            *mask |= MOVE_STRAFE;
        }
        Opcode::MSG_MOVE_STOP_STRAFE => {
            *mask &= !MOVE_STRAFE;
        }
        Opcode::MSG_MOVE_START_TURN_LEFT | Opcode::MSG_MOVE_START_TURN_RIGHT => {
            *mask |= MOVE_TURN;
        }
        Opcode::MSG_MOVE_STOP_TURN => {
            *mask &= !MOVE_TURN;
        }
        _ => {}
    }
}

fn is_world_move_opcode(opcode: u16) -> bool {
    matches!(
        opcode,
        Opcode::MSG_MOVE_START_FORWARD
            | Opcode::MSG_MOVE_START_BACKWARD
            | Opcode::MSG_MOVE_START_STRAFE_RIGHT
            | Opcode::MSG_MOVE_START_STRAFE_LEFT
            | Opcode::MSG_MOVE_JUMP
            | Opcode::MSG_MOVE_HEARTBEAT
            | Opcode::MSG_MOVE_START_TURN_LEFT
            | Opcode::MSG_MOVE_START_TURN_RIGHT
            | Opcode::MSG_MOVE_STOP
            | Opcode::MSG_MOVE_STOP_STRAFE
            | Opcode::MSG_MOVE_STOP_TURN
            | Opcode::MSG_MOVE_START_PITCH_UP
            | Opcode::MSG_MOVE_START_PITCH_DOWN
            | Opcode::MSG_MOVE_STOP_PITCH
            | Opcode::MSG_MOVE_FALL_LAND
            | Opcode::MSG_MOVE_SET_PITCH
            | Opcode::MSG_MOVE_START_SWIM
            | Opcode::MSG_MOVE_STOP_SWIM
            | Opcode::MSG_MOVE_SET_FACING
    )
}

fn try_parse_movement_payload(body: &[u8]) -> anyhow::Result<(PackedGuid, MovementInfo)> {
    let mut cursor = Cursor::new(body);
    let guid = PackedGuid::read_options(&mut cursor, Endian::Little, ())
        .context("read packed guid from movement body")?;
    let movement_info = MovementInfo::read_options(&mut cursor, Endian::Little, ())
        .context("read movement info from movement body")?;
    Ok((guid, movement_info))
}

fn pack_movement_payload(
    guid: PackedGuid,
    movement_info: &MovementInfo,
) -> anyhow::Result<Vec<u8>> {
    let mut out = Vec::with_capacity(64);
    let mut cursor = Cursor::new(&mut out);
    guid.write_options(&mut cursor, Endian::Little, ())
        .context("write packed guid")?;
    movement_info
        .write_options(&mut cursor, Endian::Little, ())
        .context("write movement info")?;
    Ok(out)
}

async fn read_client_login_challenge(stream: &mut TcpStream) -> anyhow::Result<Vec<u8>> {
    let mut opcode = [0u8; 1];
    stream.read_exact(&mut opcode).await?;
    if opcode[0] != LOGIN_CHALLENGE_OP {
        anyhow::bail!(
            "Unexpected client opcode {}, expected LOGIN_CHALLENGE",
            opcode[0]
        );
    }

    let mut unknown = [0u8; 1];
    stream.read_exact(&mut unknown).await?;

    let mut size = [0u8; 2];
    stream.read_exact(&mut size).await?;
    let body_len = u16::from_le_bytes(size) as usize;
    println!(
        "proxy.login.client_challenge opcode={} unknown=0x{:02x} size_raw={:02x}{:02x} body_len={}",
        opcode[0], unknown[0], size[0], size[1], body_len
    );

    let mut body = vec![0u8; body_len];
    stream.read_exact(&mut body).await?;

    let mut out = Vec::with_capacity(1 + 1 + 2 + body_len);
    out.push(opcode[0]);
    out.extend_from_slice(&unknown);
    out.extend_from_slice(&size);
    out.extend_from_slice(&body);
    Ok(out)
}

async fn read_upstream_challenge(stream: &mut TcpStream) -> anyhow::Result<UpstreamChallenge> {
    let mut opcode = [0u8; 1];
    stream.read_exact(&mut opcode).await?;
    if opcode[0] != LOGIN_CHALLENGE_OP {
        anyhow::bail!(
            "Unexpected upstream opcode {}, expected LOGIN_CHALLENGE",
            opcode[0]
        );
    }

    let mut head = [0u8; 35];
    stream.read_exact(&mut head).await?;
    let mut cursor = Cursor::new(&head);
    let _unknown = ReadBytesExt::read_u8(&mut cursor)?;
    let code = ReadBytesExt::read_u8(&mut cursor)?;
    if code != 0 {
        anyhow::bail!("Upstream login challenge error code={code}");
    }
    let mut server_ephemeral = [0u8; 32];
    Read::read_exact(&mut cursor, &mut server_ephemeral)?;
    let g_len = ReadBytesExt::read_u8(&mut cursor)? as usize;

    let mut g = vec![0u8; g_len];
    stream.read_exact(&mut g).await?;

    let mut n_len = [0u8; 1];
    stream.read_exact(&mut n_len).await?;
    let n_len = n_len[0] as usize;
    let mut n = vec![0u8; n_len];
    stream.read_exact(&mut n).await?;

    let mut tail = [0u8; 49];
    stream.read_exact(&mut tail).await?;
    let mut tail_cursor = Cursor::new(&tail);
    let mut salt = [0u8; 32];
    Read::read_exact(&mut tail_cursor, &mut salt)?;
    let mut _version_challenge = [0u8; 16];
    Read::read_exact(&mut tail_cursor, &mut _version_challenge)?;
    let _unknown2 = ReadBytesExt::read_u8(&mut tail_cursor)?;

    Ok(UpstreamChallenge {
        n,
        g,
        server_ephemeral,
        salt,
    })
}

async fn send_downstream_challenge(
    stream: &mut TcpStream,
    upstream_challenge: &UpstreamChallenge,
    downstream_srp: &SrpServer,
) -> anyhow::Result<()> {
    let mut out = Vec::with_capacity(120);
    out.push(LOGIN_CHALLENGE_OP);
    out.push(0);
    out.push(0);
    out.extend_from_slice(&downstream_srp.challenge_ephemeral_padded());
    out.push(upstream_challenge.g.len() as u8);
    out.extend_from_slice(&upstream_challenge.g);
    out.push(upstream_challenge.n.len() as u8);
    out.extend_from_slice(&upstream_challenge.n);
    out.extend_from_slice(&downstream_srp.salt);
    out.extend_from_slice(&[0u8; 16]); // version challenge
    out.push(0);
    stream.write_all(&out).await?;
    Ok(())
}

async fn read_client_proof(stream: &mut TcpStream) -> anyhow::Result<([u8; 32], [u8; 20])> {
    let mut buf = [0u8; 75];
    stream.read_exact(&mut buf).await?;
    if buf[0] != LOGIN_PROOF_OP {
        anyhow::bail!("Unexpected client opcode {}, expected LOGIN_PROOF", buf[0]);
    }

    let mut a = [0u8; 32];
    a.copy_from_slice(&buf[1..33]);
    let mut m1 = [0u8; 20];
    m1.copy_from_slice(&buf[33..53]);
    Ok((a, m1))
}

async fn send_client_proof_ok(stream: &mut TcpStream, m2: [u8; 20]) -> anyhow::Result<()> {
    let mut out = Vec::with_capacity(32);
    out.push(LOGIN_PROOF_OP);
    out.push(0);
    out.extend_from_slice(&m2);
    out.extend_from_slice(&0u32.to_le_bytes());
    out.extend_from_slice(&0u32.to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes());
    stream.write_all(&out).await?;
    Ok(())
}

async fn send_upstream_proof(
    stream: &mut TcpStream,
    public_ephemeral: [u8; 32],
    client_proof: [u8; 20],
) -> anyhow::Result<()> {
    let mut out = Vec::with_capacity(75);
    out.push(LOGIN_PROOF_OP);
    out.extend_from_slice(&public_ephemeral);
    out.extend_from_slice(&client_proof);
    out.extend_from_slice(&CRC_HASH);
    out.push(0);
    out.push(0);
    stream.write_all(&out).await?;
    Ok(())
}

async fn read_upstream_proof_response(stream: &mut TcpStream) -> anyhow::Result<[u8; 20]> {
    let mut buf = [0u8; 32];
    stream.read_exact(&mut buf).await?;
    if buf[0] != LOGIN_PROOF_OP {
        anyhow::bail!(
            "Unexpected upstream opcode {}, expected LOGIN_PROOF",
            buf[0]
        );
    }
    let error = buf[1];
    if error != 0 {
        anyhow::bail!("Upstream login proof error code={error}");
    }
    let mut m2 = [0u8; 20];
    m2.copy_from_slice(&buf[2..22]);
    Ok(m2)
}

async fn read_client_realmlist_request(stream: &mut TcpStream) -> anyhow::Result<()> {
    let mut buf = [0u8; 5];
    stream.read_exact(&mut buf).await?;
    if buf[0] != REALM_LIST_OP {
        anyhow::bail!("Unexpected client opcode {}, expected REALM_LIST", buf[0]);
    }
    Ok(())
}

async fn send_upstream_realmlist_request(stream: &mut TcpStream) -> anyhow::Result<()> {
    let mut out = [0u8; 5];
    out[0] = REALM_LIST_OP;
    stream.write_all(&out).await?;
    Ok(())
}

async fn read_upstream_realmlist_response(stream: &mut TcpStream) -> anyhow::Result<Vec<u8>> {
    let mut opcode = [0u8; 1];
    stream.read_exact(&mut opcode).await?;
    if opcode[0] != REALM_LIST_OP {
        anyhow::bail!(
            "Unexpected upstream opcode {}, expected REALM_LIST",
            opcode[0]
        );
    }

    let mut size = [0u8; 2];
    stream.read_exact(&mut size).await?;
    let payload_len = u16::from_le_bytes(size) as usize;

    let mut payload = vec![0u8; payload_len];
    stream.read_exact(&mut payload).await?;

    let mut body = Vec::with_capacity(2 + payload_len);
    body.extend_from_slice(&size);
    body.extend_from_slice(&payload);
    Ok(body)
}

async fn send_client_realmlist_response(stream: &mut TcpStream, body: &[u8]) -> anyhow::Result<()> {
    stream.write_all(&[REALM_LIST_OP]).await?;
    stream.write_all(body).await?;
    Ok(())
}

async fn keep_login_bridge_alive(
    mut client: TcpStream,
    mut upstream: TcpStream,
    proxy_world_addr: &str,
) -> anyhow::Result<()> {
    loop {
        let mut opcode = [0u8; 1];
        if client.read_exact(&mut opcode).await.is_err() {
            println!("proxy.login.keepalive.end reason=client-closed");
            return Ok(());
        }

        if opcode[0] != REALM_LIST_OP {
            eprintln!(
                "proxy.login.keepalive.unhandled_client_opcode={} action=close",
                opcode[0]
            );
            return Ok(());
        }

        let mut rest = [0u8; 4];
        client.read_exact(&mut rest).await?;

        send_upstream_realmlist_request(&mut upstream).await?;
        let upstream_realmlist_body = read_upstream_realmlist_response(&mut upstream).await?;
        let (rewritten_realmlist_body, _) =
            rewrite_realmlist_addresses(&upstream_realmlist_body, proxy_world_addr)?;
        send_client_realmlist_response(&mut client, &rewritten_realmlist_body).await?;
        println!(
            "proxy.login.keepalive.realmlist_refreshed payload_len={}",
            rewritten_realmlist_body.len().saturating_sub(2)
        );
    }
}

fn rewrite_realmlist_addresses(
    body: &[u8],
    proxy_world_addr: &str,
) -> anyhow::Result<(Vec<u8>, String)> {
    if body.len() < 8 {
        anyhow::bail!("REALM_LIST body too short");
    }

    let unknown = &body[2..6];
    let realms_count = u16::from_le_bytes([body[6], body[7]]) as usize;
    let mut cursor = 8usize;

    let mut first_upstream_addr: Option<String> = None;
    let mut realms_out: Vec<u8> = Vec::new();

    for _ in 0..realms_count {
        let icon = read_byte(body, &mut cursor)?;
        let lock = read_byte(body, &mut cursor)?;
        let flags = read_byte(body, &mut cursor)?;
        let name = read_cstring(body, &mut cursor)?;
        let upstream_addr = read_cstring(body, &mut cursor)?;
        if first_upstream_addr.is_none() {
            first_upstream_addr = Some(upstream_addr.clone());
        }
        println!(
            "proxy.login.realm_rewrite name=\"{}\" upstream_addr={} rewritten_addr={}",
            name, upstream_addr, proxy_world_addr
        );

        let mut tail = [0u8; 7];
        let tail_len = tail.len();
        if cursor + tail_len > body.len() {
            anyhow::bail!("REALM_LIST entry tail truncated");
        }
        tail.copy_from_slice(&body[cursor..cursor + tail_len]);
        cursor += tail_len;

        let mut upstream_entry = Vec::new();
        upstream_entry.push(icon);
        upstream_entry.push(lock);
        upstream_entry.push(flags);
        upstream_entry.extend_from_slice(name.as_bytes());
        upstream_entry.push(0);
        upstream_entry.extend_from_slice(upstream_addr.as_bytes());
        upstream_entry.push(0);
        upstream_entry.extend_from_slice(&tail);

        let mut rewritten_entry = Vec::new();
        rewritten_entry.push(icon);
        rewritten_entry.push(lock);
        rewritten_entry.push(flags);
        rewritten_entry.extend_from_slice(name.as_bytes());
        rewritten_entry.push(0);
        rewritten_entry.extend_from_slice(proxy_world_addr.as_bytes());
        rewritten_entry.push(0);
        rewritten_entry.extend_from_slice(&tail);

        println!(
            "proxy.login.realm_entry_debug name=\"{}\" icon={} lock={} flags={} upstream_addr_raw=\"{}\" rewritten_addr_raw=\"{}\" upstream_entry_hex={} rewritten_entry_hex={}",
            name,
            icon,
            lock,
            flags,
            upstream_addr,
            proxy_world_addr,
            hex_all(&upstream_entry),
            hex_all(&rewritten_entry),
        );

        realms_out.push(icon);
        realms_out.push(lock);
        realms_out.push(flags);
        realms_out.extend_from_slice(name.as_bytes());
        realms_out.push(0);
        realms_out.extend_from_slice(proxy_world_addr.as_bytes());
        realms_out.push(0);
        realms_out.extend_from_slice(&tail);
    }

    let trailing = &body[cursor..];
    let mut rebuilt = Vec::with_capacity(body.len() + 64);
    rebuilt.extend_from_slice(&[0u8; 2]); // placeholder size
    rebuilt.extend_from_slice(unknown);
    rebuilt.extend_from_slice(&(realms_count as u16).to_le_bytes());
    rebuilt.extend_from_slice(&realms_out);
    rebuilt.extend_from_slice(trailing);

    let payload_len = rebuilt
        .len()
        .checked_sub(2)
        .ok_or_else(|| anyhow::anyhow!("realmlist rebuilt underflow"))?;
    if payload_len > u16::MAX as usize {
        anyhow::bail!("realmlist payload too large");
    }
    rebuilt[0..2].copy_from_slice(&(payload_len as u16).to_le_bytes());
    println!(
        "proxy.login.realm_rewrite_done realms={} payload_len={} proxy_world_addr={}",
        realms_count, payload_len, proxy_world_addr
    );

    Ok((
        rebuilt,
        first_upstream_addr.ok_or_else(|| anyhow::anyhow!("REALM_LIST had no realms"))?,
    ))
}

fn read_byte(body: &[u8], cursor: &mut usize) -> anyhow::Result<u8> {
    if *cursor >= body.len() {
        anyhow::bail!("Unexpected EOF");
    }
    let b = body[*cursor];
    *cursor += 1;
    Ok(b)
}

fn read_cstring(body: &[u8], cursor: &mut usize) -> anyhow::Result<String> {
    let start = *cursor;
    let rel = body[start..]
        .iter()
        .position(|v| *v == 0)
        .ok_or_else(|| anyhow::anyhow!("Missing NUL terminator"))?;
    let end = start + rel;
    *cursor = end + 1;
    let s = std::str::from_utf8(&body[start..end])?.to_string();
    Ok(s)
}

async fn read_server_world_packet(
    stream: &mut OwnedReadHalf,
    decryptor: &mut Decryptor,
    decrypt_active: &mut bool,
) -> anyhow::Result<WorldPacket> {
    let mut header = [0u8; 4];
    stream.read_exact(&mut header).await?;

    let mut header_vec = header.to_vec();
    if *decrypt_active {
        decryptor.decrypt(&mut header_vec[..1]);
    }
    let is_long_packet = (header_vec[0] & 0x80) != 0;
    if is_long_packet {
        let mut extra = [0u8; 1];
        stream.read_exact(&mut extra).await?;
        header_vec.push(extra[0]);
    }
    if *decrypt_active {
        decryptor.decrypt(&mut header_vec[1..]);
    }

    let mut cursor = Cursor::new(&header_vec);
    let size = if is_long_packet {
        cursor.read_u24::<BigEndian>()? as usize
    } else {
        ReadBytesExt::read_u16::<BigEndian>(&mut cursor)? as usize
    };
    let opcode = ReadBytesExt::read_u16::<LittleEndian>(&mut cursor)? as u32;
    let body_size = size
        .checked_sub(2)
        .ok_or_else(|| anyhow::anyhow!("invalid world packet size {size}"))?;

    let mut body = vec![0u8; body_size];
    stream.read_exact(&mut body).await?;

    if !*decrypt_active {
        *decrypt_active = true;
    }

    Ok(WorldPacket { opcode, body })
}

async fn write_server_world_packet(
    stream: &mut OwnedWriteHalf,
    packet: &WorldPacket,
    encryptor: &mut Decryptor,
    encrypt_active: &mut bool,
) -> anyhow::Result<()> {
    // Realm header size is opcode (2 bytes) + payload length.
    let size = (2 + packet.body.len()) as u16;
    let opcode = u16::try_from(packet.opcode)
        .map_err(|_| anyhow::anyhow!("server packet opcode out of range: 0x{:x}", packet.opcode))?;
    let mut header = Vec::with_capacity(4);
    header.extend_from_slice(&size.to_be_bytes());
    header.extend_from_slice(&opcode.to_le_bytes());

    if *encrypt_active {
        encryptor.decrypt(&mut header);
    }

    stream.write_all(&header).await?;
    stream.write_all(&packet.body).await?;

    if !*encrypt_active {
        *encrypt_active = true;
    }
    Ok(())
}

async fn read_client_world_packet(
    stream: &mut OwnedReadHalf,
    decryptor: &mut Encryptor,
    decrypt_active: &mut bool,
) -> anyhow::Result<WorldPacket> {
    let mut header = [0u8; 6];
    stream.read_exact(&mut header).await?;
    let raw_header = header;

    if *decrypt_active {
        decryptor.encrypt(&mut header);
    }

    let size = u16::from_be_bytes([header[0], header[1]]) as usize;
    let opcode = u32::from_le_bytes([header[2], header[3], header[4], header[5]]);
    if !(4..10240).contains(&size) {
        anyhow::bail!(
            "malformed client world header size={} opcode=0x{:08x} decrypt_active={} raw_header={} decoded_header={}",
            size,
            opcode,
            *decrypt_active,
            hex_all(&raw_header),
            hex_all(&header),
        );
    }
    let body_size = size
        .checked_sub(4)
        .ok_or_else(|| anyhow::anyhow!("invalid client world packet size {size}"))?;

    let mut body = vec![0u8; body_size];
    stream.read_exact(&mut body).await?;

    if !*decrypt_active {
        *decrypt_active = true;
    }

    Ok(WorldPacket { opcode, body })
}

async fn write_client_world_packet(
    stream: &mut OwnedWriteHalf,
    packet: &WorldPacket,
    encryptor: &mut Encryptor,
    encrypt_active: &mut bool,
) -> anyhow::Result<()> {
    // Client header size is opcode (4 bytes) + payload length.
    let size = (4 + packet.body.len()) as u16;
    let mut header = Vec::with_capacity(6);
    header.extend_from_slice(&size.to_be_bytes());
    header.extend_from_slice(&packet.opcode.to_le_bytes());

    if *encrypt_active {
        encryptor.encrypt(&mut header);
    }

    stream.write_all(&header).await?;
    stream.write_all(&packet.body).await?;

    if !*encrypt_active {
        *encrypt_active = true;
    }
    Ok(())
}

fn decode_hex(input: &str) -> anyhow::Result<Vec<u8>> {
    let clean = input.trim();
    if !clean.len().is_multiple_of(2) {
        anyhow::bail!("hex length must be even");
    }

    let mut out = Vec::with_capacity(clean.len() / 2);
    let bytes = clean.as_bytes();
    let mut i = 0usize;
    while i < bytes.len() {
        let hi = hex_nibble(bytes[i])?;
        let lo = hex_nibble(bytes[i + 1])?;
        out.push((hi << 4) | lo);
        i += 2;
    }
    Ok(out)
}

fn hex_nibble(ch: u8) -> anyhow::Result<u8> {
    match ch {
        b'0'..=b'9' => Ok(ch - b'0'),
        b'a'..=b'f' => Ok(ch - b'a' + 10),
        b'A'..=b'F' => Ok(ch - b'A' + 10),
        _ => anyhow::bail!("invalid hex character {}", ch as char),
    }
}

fn pad_to_32_bytes(bytes: Vec<u8>) -> [u8; 32] {
    let mut buffer = [0u8; 32];
    let len = std::cmp::min(32, bytes.len());
    buffer[..len].copy_from_slice(&bytes[..len]);
    buffer
}

fn trim_trailing_zeros(mut bytes: Vec<u8>) -> Vec<u8> {
    while let Some(0) = bytes.last().copied() {
        bytes.pop();
    }
    bytes
}

fn mod_floor(value: &BigInt, modulus: &BigInt) -> BigInt {
    ((value % modulus) + modulus) % modulus
}

fn calculate_x(account: &str, password: &str, salt: &[u8; 32]) -> BigInt {
    use sha1::{Digest, Sha1};

    let identity_hash = Sha1::new()
        .chain(format!("{}:{}", account, password).as_bytes())
        .finalize()
        .to_vec();

    let x = Sha1::new()
        .chain(salt)
        .chain(identity_hash)
        .finalize()
        .to_vec();

    BigInt::from_bytes_le(Sign::Plus, &x)
}

fn calculate_u(a: &BigInt, b: &BigInt) -> BigInt {
    use sha1::{Digest, Sha1};

    let u = Sha1::new()
        .chain(a.to_bytes_le().1)
        .chain(b.to_bytes_le().1)
        .finalize()
        .to_vec();
    BigInt::from_bytes_le(Sign::Plus, &u)
}

fn calculate_interleaved(s: BigInt) -> Vec<u8> {
    use sha1::{Digest, Sha1};

    let padded = pad_to_32_bytes(s.to_bytes_le().1);
    let (even, odd): (Vec<_>, Vec<_>) = padded
        .into_iter()
        .enumerate()
        .partition(|(i, _)| i % 2 == 0);

    let part1 = even.iter().map(|(_, v)| *v).collect::<Vec<u8>>();
    let part2 = odd.iter().map(|(_, v)| *v).collect::<Vec<u8>>();

    let hashed1 = Sha1::new().chain(part1).finalize();
    let hashed2 = Sha1::new().chain(part2).finalize();

    let mut session_key = Vec::with_capacity(40);
    for index in 0..hashed1.len() {
        session_key.push(hashed1[index]);
        session_key.push(hashed2[index]);
    }

    session_key
}

fn calculate_m1(
    modulus: &BigInt,
    generator: &BigInt,
    account: &str,
    salt: &[u8; 32],
    client_a: &BigInt,
    server_b: &BigInt,
    session_key: &[u8],
) -> [u8; 20] {
    use sha1::{Digest, Sha1};

    let n_hash = Sha1::new().chain(modulus.to_bytes_le().1).finalize();
    let g_hash = Sha1::new().chain(generator.to_bytes_le().1).finalize();
    let mut xor_hash = [0u8; 20];
    for idx in 0..20 {
        xor_hash[idx] = n_hash[idx] ^ g_hash[idx];
    }
    let account_hash = Sha1::new().chain(account.as_bytes()).finalize();

    let out = Sha1::new()
        .chain(xor_hash)
        .chain(account_hash)
        .chain(salt)
        .chain(client_a.to_bytes_le().1)
        .chain(server_b.to_bytes_le().1)
        .chain(session_key)
        .finalize()
        .to_vec();

    let mut m1 = [0u8; 20];
    m1.copy_from_slice(&out);
    m1
}

fn calculate_m2(client_a: &BigInt, client_m1: [u8; 20], session_key: &[u8]) -> [u8; 20] {
    use sha1::{Digest, Sha1};

    let out = Sha1::new()
        .chain(pad_to_32_bytes(client_a.to_bytes_le().1))
        .chain(client_m1)
        .chain(session_key)
        .finalize()
        .to_vec();
    let mut m2 = [0u8; 20];
    m2.copy_from_slice(&out);
    m2
}
