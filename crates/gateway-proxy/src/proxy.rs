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
use tokio::sync::{Mutex, mpsc};
use tokio::time::{Instant, MissedTickBehavior};

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

#[derive(Debug)]
struct PendingAction {
    cmd: String,
    issued_at: Instant,
    baseline_client_time: Option<u32>,
}

fn action_timeout_for(cmd: &str) -> Duration {
    if cmd.starts_with("emote ") || cmd == "emote" {
        Duration::from_millis(1800)
    } else if matches!(
        cmd,
        "move forward" | "move backward" | "move left" | "move right" | "turn left" | "turn right"
    ) {
        // Continuous actions: behave like holding a key for a bit.
        Duration::from_millis(1200)
    } else {
        Duration::from_millis(900)
    }
}

async fn send_injected_packet(
    packet: WorldPacket,
    upstream_tx: &mpsc::Sender<WorldPacket>,
    downstream_tx: &mpsc::Sender<WorldPacket>,
    echo_to_client: bool,
) -> anyhow::Result<()> {
    match route_for_opcode(packet.opcode) {
        InjectRoute::UpstreamOnly => {
            if echo_to_client {
                if let Ok(op_u16) = u16::try_from(packet.opcode) {
                    if is_world_move_opcode(op_u16) {
                        upstream_tx.send(packet.clone()).await?;
                        downstream_tx.send(packet).await?;
                        return Ok(());
                    }
                }
            }
            upstream_tx.send(packet).await?;
        }
        InjectRoute::Both => {
            upstream_tx.send(packet.clone()).await?;
            downstream_tx.send(packet).await?;
        }
    }
    Ok(())
}

#[derive(Debug, Clone, Copy)]
enum InjectRoute {
    UpstreamOnly,
    Both,
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

    // Default: preserve legacy behavior (send to both directions). This is useful
    // for manual testing via the control port.
    InjectRoute::Both
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
    pending_action: Option<PendingAction>,
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

    let control_task = tokio::spawn(serve_control(
        control_listener,
        upstream_tx.clone(),
        downstream_inject_tx.clone(),
        injection_guard.clone(),
    ));
    let demo_task = tokio::spawn(run_demo_llm_injector(
        upstream_tx.clone(),
        downstream_inject_tx.clone(),
        injection_guard.clone(),
        world_state.clone(),
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
    demo_task.abort();
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
    let demo_enabled = std::env::var("RUSTY_BOT_DEMO")
        .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
        .unwrap_or(false);
    let demo_suppress_client_movement = std::env::var("RUSTY_BOT_DEMO_SUPPRESS_CLIENT_MOVEMENT")
        .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
        // Default to allowing the user's real client to keep sending movement so:
        // - server-side corrections (walls, slopes) stay in effect
        // - the user can steer/turn while the demo bot runs
        .unwrap_or(false);
    if demo_suppress_client_movement {
        println!("proxy.bot.demo suppress_client_movement=true");
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

        if demo_enabled && demo_suppress_client_movement {
            if let Ok(op_u16) = u16::try_from(packet.opcode) {
                if is_world_move_opcode(op_u16) {
                    // Let the demo injector be the sole writer of movement to the server.
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

async fn serve_control(
    listener: Arc<TcpListener>,
    upstream_tx: mpsc::Sender<WorldPacket>,
    downstream_tx: mpsc::Sender<WorldPacket>,
    injection_guard: Arc<Mutex<InjectionGuardState>>,
) -> anyhow::Result<()> {
    loop {
        let (socket, addr) = listener.accept().await?;
        println!("proxy.control.accepted client={addr}");

        let upstream = upstream_tx.clone();
        let downstream = downstream_tx.clone();
        let guard = injection_guard.clone();
        tokio::spawn(async move {
            let mut lines = BufReader::new(socket).lines();
            while let Ok(Some(line)) = lines.next_line().await {
                let trimmed = line.trim();
                if trimmed.is_empty() {
                    continue;
                }

                match parse_control_line(trimmed) {
                    Ok(packet) => {
                        let packet = match apply_injection_guard(packet, &guard).await {
                            Some(packet) => packet,
                            None => continue,
                        };
                        match route_for_opcode(packet.opcode) {
                            InjectRoute::UpstreamOnly => {
                                if upstream.send(packet).await.is_err() {
                                    break;
                                }
                            }
                            InjectRoute::Both => {
                                if upstream.send(packet.clone()).await.is_err() {
                                    break;
                                }
                                if downstream.send(packet).await.is_err() {
                                    break;
                                }
                            }
                        }
                    }
                    Err(err) => {
                        eprintln!("proxy.control.bad_line error={err} line={trimmed}");
                    }
                }
            }
        });
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

async fn record_server_world_observation(packet: &WorldPacket, world_state: &Arc<Mutex<WorldState>>) {
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
                eprintln!("proxy.world.state.update_object_failed error={err:#} body_len={}", packet.body.len());
            }
        }
        SMSG_MESSAGECHAT => {
            if let Some(msg) = try_parse_smsg_messagechat(&packet.body) {
                ws.add_chat_message(msg);
            }
        }
        SMSG_ATTACKERSTATEUPDATE => {
            // Keep this crude for now; better parsing can be added when needed.
            ws.add_combat_message(format!("SMSG_ATTACKERSTATEUPDATE len={}", packet.body.len()));
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

async fn run_demo_llm_injector(
    upstream_tx: mpsc::Sender<WorldPacket>,
    downstream_tx: mpsc::Sender<WorldPacket>,
    injection_guard: Arc<Mutex<InjectionGuardState>>,
    world_state: Arc<Mutex<WorldState>>,
) -> anyhow::Result<()> {
    let enabled = std::env::var("RUSTY_BOT_DEMO")
        .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
        .unwrap_or(false);
    if !enabled {
        println!("proxy.bot.demo disabled");
        return Ok(());
    }

    let endpoint = std::env::var("RUSTY_BOT_LLM_ENDPOINT")
        .unwrap_or_else(|_| "http://127.0.0.1:11435/api/generate".to_string());
    let model = std::env::var("RUSTY_BOT_LLM_MODEL").unwrap_or_else(|_| "mock".to_string());
    let use_vision = std::env::var("RUSTY_BOT_DEMO_USE_VISION")
        .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
        .unwrap_or(true);
    let instruction = std::env::var("RUSTY_BOT_LLM_PROMPT").unwrap_or_else(|_| {
        "Return exactly one command and nothing else. Allowed: move forward, move backward, move left, move right, move stop, strafe stop, turn left, turn right, turn stop, jump, emote wave"
            .to_string()
    });
    println!("proxy.bot.demo enabled endpoint={endpoint} model={model}");
    let echo_to_client = std::env::var("RUSTY_BOT_DEMO_ECHO_TO_CLIENT")
        .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
        .unwrap_or(true);

    let client = reqwest::Client::builder()
        .timeout(Duration::from_millis(1200))
        .build()?;
    let mut tick = tokio::time::interval(Duration::from_millis(450));
    tick.set_missed_tick_behavior(MissedTickBehavior::Skip);
    let mut missing_template_logged = false;
    let mut last_emitted_cmd: Option<String> = None;
    let mut last_emitted_at: Option<Instant> = None;
    let mut last_jump_at: Option<Instant> = None;
    let mut pending_stop_to_issue: Option<String> = None;
    let mut last_emergency_stop_at: Option<Instant> = None;

    loop {
        tick.tick().await;
        let now = Instant::now();
        {
            let mut state = injection_guard.lock().await;
            if let Some(pending) = state.pending_action.as_ref() {
                let mut completed_reason: Option<&'static str> = None;
                let is_continuous_move = matches!(
                    pending.cmd.as_str(),
                    "move forward"
                        | "move backward"
                        | "move left"
                        | "move right"
                        | "turn left"
                        | "turn right"
                );
                if !is_continuous_move {
                    if let (Some(current), Some(baseline)) =
                        (state.last_client_move_time, pending.baseline_client_time)
                    {
                        if current != baseline {
                            completed_reason = Some("client-feedback");
                        }
                    }
                } else if state
                    .last_client_correction_at
                    .map(|t| t > pending.issued_at)
                    .unwrap_or(false)
                {
                    completed_reason = Some("client-correction");
                }
                if completed_reason.is_none()
                    && now.saturating_duration_since(pending.issued_at)
                        >= action_timeout_for(&pending.cmd)
                {
                    completed_reason = Some("timeout");
                }

                if let Some(reason) = completed_reason {
                    if let Some(done) = state.pending_action.take() {
                        println!(
                            "proxy.bot.demo action_complete cmd=\"{}\" reason={}",
                            done.cmd, reason
                        );
                        // Avoid "stuck" continuous inputs (e.g. turning) by issuing a stop after
                        // any continuous command completes. This keeps actions discrete and
                        // prevents a new action from overlapping.
                        let needs_stop = matches!(
                            done.cmd.as_str(),
                            "move forward"
                                | "move backward"
                                | "move left"
                                | "move right"
                                | "turn left"
                                | "turn right"
                        );
                        if needs_stop {
                            pending_stop_to_issue = Some(if done.cmd.starts_with("turn ") {
                                "turn stop".to_string()
                            } else {
                                "move stop".to_string()
                            });
                        }
                    }
                } else {
                    continue;
                }
            }
        }

        // If we owe a stop packet, emit it before polling the LLM for the next command.
        if let Some(stop_cmd) = pending_stop_to_issue.take() {
            if let Some(packet) = prepare_demo_packet(&stop_cmd, &injection_guard).await {
                if let Some(packet) = apply_injection_guard(packet, &injection_guard).await {
                    println!(
                        "proxy.bot.demo inject cmd=\"{}\" opcode=0x{:04x} body_len={}",
                        stop_cmd,
                        packet.opcode,
                        packet.body.len()
                    );
                    if let Err(err) = send_injected_packet(
                        packet,
                        &upstream_tx,
                        &downstream_tx,
                        echo_to_client,
                    )
                    .await
                    {
                        eprintln!("proxy.bot.demo stop_send_failed error={err:#}");
                        return Ok(());
                    }
                    let issued_at = Instant::now();
                    let mut state = injection_guard.lock().await;
                    state.pending_action = Some(PendingAction {
                        cmd: stop_cmd,
                        issued_at,
                        baseline_client_time: state.last_client_move_time,
                    });
                }
            }
            continue;
        }

        let prompt_str = if use_vision {
            let guid = injection_guard.lock().await.last_self_guid.unwrap_or(0);
            let mut ws = world_state.lock().await;
            ws.increment_tick();
            let vision = generate_vision_prompt(&ws, guid);
            format!("{vision}\n\n[INSTRUCTIONS]\n{instruction}")
        } else {
            instruction.clone()
        };

        let response = match client
            .post(&endpoint)
            .json(&serde_json::json!({
                "model": model,
                "prompt": prompt_str,
                "stream": false
            }))
            .send()
            .await
        {
            Ok(response) => response,
            Err(err) => {
                eprintln!("proxy.bot.demo poll_failed error={err:#}");
                // If the LLM is down/unreachable, immediately clear any continuous inputs so the
                // character doesn't get stuck running/turning.
                let now = Instant::now();
                let throttle_ok = last_emergency_stop_at
                    .map(|t| now.saturating_duration_since(t) >= Duration::from_millis(700))
                    .unwrap_or(true);
                if throttle_ok {
                    last_emergency_stop_at = Some(now);
                    pending_stop_to_issue = None;
                    last_emitted_cmd = None;
                    last_emitted_at = None;
                    {
                        let mut state = injection_guard.lock().await;
                        state.pending_action = None;
                    }
                    for cmd in ["turn stop", "strafe stop", "move stop"] {
                        if let Some(pkt) = prepare_demo_packet(cmd, &injection_guard).await {
                            if let Some(pkt) = apply_injection_guard(pkt, &injection_guard).await {
                                println!(
                                    "proxy.bot.demo emergency_stop cmd=\"{}\" opcode=0x{:04x} body_len={}",
                                    cmd, pkt.opcode, pkt.body.len()
                                );
                                let _ = send_injected_packet(
                                    pkt,
                                    &upstream_tx,
                                    &downstream_tx,
                                    echo_to_client,
                                )
                                .await;
                            }
                        }
                    }
                }
                continue;
            }
        };

        let payload: serde_json::Value = match response.error_for_status() {
            Ok(response) => match response.json().await {
                Ok(payload) => payload,
                Err(err) => {
                    eprintln!("proxy.bot.demo parse_failed error={err:#}");
                    let now = Instant::now();
                    let throttle_ok = last_emergency_stop_at
                        .map(|t| now.saturating_duration_since(t) >= Duration::from_millis(700))
                        .unwrap_or(true);
                    if throttle_ok {
                        last_emergency_stop_at = Some(now);
                        pending_stop_to_issue = None;
                        last_emitted_cmd = None;
                        last_emitted_at = None;
                        {
                            let mut state = injection_guard.lock().await;
                            state.pending_action = None;
                        }
                        for cmd in ["turn stop", "strafe stop", "move stop"] {
                            if let Some(pkt) = prepare_demo_packet(cmd, &injection_guard).await {
                                if let Some(pkt) = apply_injection_guard(pkt, &injection_guard).await {
                                    println!(
                                        "proxy.bot.demo emergency_stop cmd=\"{}\" opcode=0x{:04x} body_len={}",
                                        cmd, pkt.opcode, pkt.body.len()
                                    );
                                    let _ = send_injected_packet(
                                        pkt,
                                        &upstream_tx,
                                        &downstream_tx,
                                        echo_to_client,
                                    )
                                    .await;
                                }
                            }
                        }
                    }
                    continue;
                }
            },
            Err(err) => {
                eprintln!("proxy.bot.demo status_failed error={err:#}");
                let now = Instant::now();
                let throttle_ok = last_emergency_stop_at
                    .map(|t| now.saturating_duration_since(t) >= Duration::from_millis(700))
                    .unwrap_or(true);
                if throttle_ok {
                    last_emergency_stop_at = Some(now);
                    pending_stop_to_issue = None;
                    last_emitted_cmd = None;
                    last_emitted_at = None;
                    {
                        let mut state = injection_guard.lock().await;
                        state.pending_action = None;
                    }
                    for cmd in ["turn stop", "strafe stop", "move stop"] {
                        if let Some(pkt) = prepare_demo_packet(cmd, &injection_guard).await {
                            if let Some(pkt) = apply_injection_guard(pkt, &injection_guard).await {
                                println!(
                                    "proxy.bot.demo emergency_stop cmd=\"{}\" opcode=0x{:04x} body_len={}",
                                    cmd, pkt.opcode, pkt.body.len()
                                );
                                let _ = send_injected_packet(
                                    pkt,
                                    &upstream_tx,
                                    &downstream_tx,
                                    echo_to_client,
                                )
                                .await;
                            }
                        }
                    }
                }
                continue;
            }
        };

        let script = payload
            .get("response")
            .and_then(serde_json::Value::as_str)
            .or_else(|| {
                payload
                    .get("message")
                    .and_then(|m| m.get("content"))
                    .and_then(serde_json::Value::as_str)
            })
            .unwrap_or("");
        let Some(cmd) = sanitize_demo_command(script) else {
            continue;
        };
        let now = Instant::now();
        if cmd == "jump" {
            if last_jump_at
                .map(|t| now.saturating_duration_since(t) < Duration::from_millis(900))
                .unwrap_or(false)
            {
                continue;
            }
        } else if last_emitted_cmd.as_deref() == Some(cmd.as_str()) {
            let refresh_due = last_emitted_at
                .map(|t| now.saturating_duration_since(t) >= Duration::from_secs(2))
                .unwrap_or(true);
            if !refresh_due {
                continue;
            }
        }
        let packet = prepare_demo_packet(&cmd, &injection_guard).await;
        let Some(packet) = packet else {
            if !missing_template_logged {
                println!("proxy.bot.demo waiting_for_client_movement_template");
                missing_template_logged = true;
            }
            continue;
        };
        let packet = match apply_injection_guard(packet, &injection_guard).await {
            Some(packet) => packet,
            None => continue,
        };

        missing_template_logged = false;
        println!(
            "proxy.bot.demo inject cmd=\"{}\" opcode=0x{:04x} body_len={}",
            cmd,
            packet.opcode,
            packet.body.len()
        );
        if let Err(err) =
            send_injected_packet(packet, &upstream_tx, &downstream_tx, echo_to_client).await
        {
            eprintln!("proxy.bot.demo send_failed error={err:#}");
            return Ok(());
        }
        if cmd == "jump" {
            last_jump_at = Some(now);
        }
        last_emitted_cmd = Some(cmd);
        last_emitted_at = Some(now);
        {
            let mut state = injection_guard.lock().await;
            state.pending_action = Some(PendingAction {
                cmd: last_emitted_cmd
                    .clone()
                    .unwrap_or_else(|| "unknown".to_string()),
                issued_at: now,
                baseline_client_time: state.last_client_move_time,
            });
        }
    }
}

fn sanitize_demo_command(script: &str) -> Option<String> {
    let mut non_empty = script.lines().map(str::trim).filter(|s| !s.is_empty());
    let raw = non_empty.next()?;
    if non_empty.next().is_some() {
        println!("proxy.bot.demo sanitize extra_lines_discarded=true");
    }
    let normalized = raw
        .to_ascii_lowercase()
        .replace('_', " ")
        .replace('-', " ")
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ");

    if let Some(arg) = normalized.strip_prefix("emote ") {
        let arg = arg.trim();
        if arg.is_empty() {
            return Some("emote wave".to_string());
        }
        // Only allow a single-word emote key (keeps the demo contract strict).
        if arg.split_whitespace().count() == 1 {
            return Some(format!("emote {}", arg));
        }
        return None;
    }

    match normalized.as_str() {
        "move forward" | "forward" | "walk forward" | "go forward" | "run forward" | "w" => {
            Some("move forward".to_string())
        }
        "move backward" | "backward" | "go backward" | "reverse" | "s" => {
            Some("move backward".to_string())
        }
        "move left" | "left" | "strafe left" | "q" => Some("move left".to_string()),
        "move right" | "right" | "strafe right" | "e" => {
            Some("move right".to_string())
        }
        "move stop" | "stop" | "idle" | "wait" | "hold" | "halt" | "x" => {
            Some("move stop".to_string())
        }
        "turn left" | "rotate left" | "a" => Some("turn left".to_string()),
        "turn right" | "rotate right" | "d" => Some("turn right".to_string()),
        "turn stop" | "stop turn" | "turn off" => Some("turn stop".to_string()),
        "jump" | "space" => Some("jump".to_string()),
        _ => None,
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
            let dist = move_speed * secs * if command == "move backward" { -1.0 } else { 1.0 };
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
            movement_info.movement_flags.remove(MovementFlags::LEFT | MovementFlags::RIGHT);
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
