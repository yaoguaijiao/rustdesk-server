//! 只读 NaCl TCP 协议探测；只连接 127.0.0.1:21116。
//!
//! 公开 Ed25519 key 只从 RUSTDESK_PROBE_SERVER_PUBLIC_KEY 环境变量读取。
//! 不读取配置、数据库、私钥或令牌，不注册节点，不执行任何负例或 fuzz。
//! 先在旧镜像和新镜像的隔离数据副本验证，再由操作者核对目标容器后使用。
//! 只验证服务器签名、合法密钥协商和双向加密查询，不验证远程桌面画面。
//!
//! 构建仅在 CI：会写 CI 的依赖缓存及 target；本机和服务器无需安装或编译。
//! cargo build --locked --release --example migration_tcp_probe \
//!   --target=x86_64-unknown-linux-musl
//!
//! 固定协议及接口：hbb_common d6b14975ffd35ed63528617a53795c479a6eaf13。

use hbb_common::{
    protobuf::Message,
    rendezvous_proto::{rendezvous_message::Union, KeyExchange, OnlineRequest, RendezvousMessage},
    tcp::FramedStream,
    tokio,
};
use sodiumoxide::crypto::{box_, secretbox, sign};
use std::{env, net::Ipv4Addr, process, time::Duration};

const PUBLIC_KEY_ENV: &str = "RUSTDESK_PROBE_SERVER_PUBLIC_KEY";
const PORT: u16 = 21116;
const TIMEOUT_MS: u64 = 5_000;
const MAX_PACKET: usize = 512;

type ProbeResult<T> = Result<T, &'static str>;

async fn receive(stream: &mut FramedStream, stage: &'static str) -> ProbeResult<RendezvousMessage> {
    let packet = stream
        .next_timeout(TIMEOUT_MS)
        .await
        .ok_or(stage)?
        .map_err(|_| stage)?;
    if packet.len() > MAX_PACKET {
        return Err("response_packet_too_large");
    }
    RendezvousMessage::parse_from_bytes(&packet).map_err(|_| "response_protobuf_invalid")
}

async fn probe() -> ProbeResult<()> {
    if env::args_os().len() != 1 {
        return Err("no_arguments_allowed_target_is_fixed_loopback");
    }
    if !cfg!(target_os = "linux") {
        return Err("linux_required");
    }
    sodiumoxide::init().map_err(|_| "sodium_initialization_failed")?;
    let encoded = env::var(PUBLIC_KEY_ENV).map_err(|_| "public_key_environment_missing")?;
    if encoded.trim().len() > 128 {
        return Err("public_key_format_invalid");
    }
    let decoded = base64::decode(encoded.trim()).map_err(|_| "public_key_format_invalid")?;
    let identity = sign::PublicKey::from_slice(&decoded).ok_or("public_key_length_invalid")?;

    // 不调用 FramedStream::new，避免 hbb_common Config / 代理配置的隐式访问。
    let socket = tokio::time::timeout(
        Duration::from_millis(TIMEOUT_MS),
        tokio::net::TcpStream::connect((Ipv4Addr::LOCALHOST, PORT)),
    )
    .await
    .map_err(|_| "tcp_connect_timeout")?
    .map_err(|_| "tcp_connect_failed")?;
    socket
        .set_nodelay(true)
        .map_err(|_| "tcp_configuration_failed")?;
    let local = socket.local_addr().map_err(|_| "tcp_address_failed")?;
    let mut stream = FramedStream::from(socket, local);
    stream.0.codec_mut().set_max_packet_length(MAX_PACKET);
    stream.set_send_timeout(TIMEOUT_MS);

    let phase1 = receive(&mut stream, "signed_key_receive_failed").await?;
    let exchange = match phase1.union {
        Some(Union::KeyExchange(exchange)) => exchange,
        _ => return Err("signed_key_message_missing"),
    };
    if exchange.keys.len() != 1
        || exchange.keys[0].len() != sign::SIGNATUREBYTES + box_::PUBLICKEYBYTES
    {
        return Err("signed_key_length_invalid");
    }
    let verified = sign::verify(&exchange.keys[0], &identity)
        .map_err(|_| "server_identity_signature_invalid")?;
    let server_box_key = box_::PublicKey::from_slice(&verified).ok_or("server_box_key_invalid")?;
    println!("PASS retained_public_key_verifies_server_signature");

    let (client_box_key, client_box_secret) = box_::gen_keypair();
    let symmetric = secretbox::gen_key();
    // 这是服务端既有协议的合法 box nonce，不能替换为 sealedbox 或其他 nonce。
    let nonce = box_::Nonce([0; box_::NONCEBYTES]);
    let boxed = box_::seal(&symmetric.0, &nonce, &server_box_key, &client_box_secret);
    if boxed.len() != secretbox::KEYBYTES + box_::MACBYTES {
        return Err("local_box_length_invalid");
    }
    let mut phase2 = RendezvousMessage::new();
    phase2.set_key_exchange(KeyExchange {
        keys: vec![client_box_key.0.to_vec().into(), boxed.into()],
        ..Default::default()
    });
    stream
        .send(&phase2)
        .await
        .map_err(|_| "legal_key_exchange_send_failed")?;
    stream.set_key(symmetric);

    // 只查询随机标识的在线位图，绝不发送 RegisterPk 或 RegisterPeer。
    let random = sodiumoxide::randombytes::randombytes(16);
    let missing_id = format!("migration-tcp-probe-{}", base64::encode(random));
    let mut request = RendezvousMessage::new();
    request.set_online_request(OnlineRequest {
        peers: vec![missing_id],
        ..Default::default()
    });
    stream
        .send(&request)
        .await
        .map_err(|_| "encrypted_query_send_failed")?;
    let response = receive(&mut stream, "encrypted_response_receive_or_decrypt_failed").await?;
    match response.union {
        Some(Union::OnlineResponse(response))
            if response.states.len() == 1 && response.states[0] == 0 => {}
        _ => return Err("encrypted_online_response_invalid"),
    }
    println!("PASS nacl_tcp_legal_key_exchange_and_bidirectional_encryption");
    println!("STATS target=127.0.0.1:21116 registration=none database_writes=none desktop_session=not_tested");
    Ok(())
}

#[tokio::main(flavor = "current_thread")]
async fn main() {
    if let Err(stage) = probe().await {
        // 固定诊断不包含公钥、临时密钥、服务端原始报文或动态错误文本。
        eprintln!("FAIL {stage}");
        process::exit(1);
    }
}
