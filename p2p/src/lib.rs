use clap::ValueEnum;
use coin::meets_difficulty;
use coin::{Block, BlockHeader, Blockchain, TransactionExt, compute_merkle_root};
use coin_proto::{
    Chain, GetBlock, GetChain, GetPeers, Handshake, NodeMessage, Peers, Ping, Pong, Transaction,
};
use hex;
use miner::{mine_block, mine_block_threads};
use rand::rngs::OsRng;
use sha2::Digest;
use secp256k1::{self, Secp256k1};
use serde_json;
use std::collections::{HashMap, HashSet};
use std::net::{SocketAddr, ToSocketAddrs as StdToSocketAddrs};
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, lookup_host};
use tokio::sync::{Mutex, mpsc};
use tokio::time::{Duration, Instant, timeout};

pub mod config;

const DEFAULT_MAX_MSGS_PER_SEC: u32 = 10;
const DEFAULT_MAX_PEERS: usize = 32;
const MAX_MSG_BYTES: usize = 1024 * 1024; // 1 MiB
const MAX_TIME_DRIFT_SECS: i64 = 2 * 60 * 60; // 2 hours

/// Send a length-prefixed JSON-RPC message over the socket
async fn write_msg(socket: &mut TcpStream, msg: &NodeMessage) -> tokio::io::Result<()> {
    let buf = serde_json::to_vec(msg)
        .map_err(|e| tokio::io::Error::new(tokio::io::ErrorKind::InvalidData, e))?;
    let len = (buf.len() as u32).to_be_bytes();
    socket.write_all(&len).await?;
    socket.write_all(&buf).await?;
    Ok(())
}

/// Read a length-prefixed JSON-RPC message from the socket
async fn read_msg(socket: &mut TcpStream) -> tokio::io::Result<NodeMessage> {
    let mut len_buf = [0u8; 4];
    socket.read_exact(&mut len_buf).await?;
    let len = u32::from_be_bytes(len_buf) as usize;
    if len > MAX_MSG_BYTES {
        return Err(tokio::io::Error::new(
            tokio::io::ErrorKind::InvalidData,
            "message too large",
        ));
    }
    let mut buf = vec![0u8; len];
    socket.read_exact(&mut buf).await?;
    Ok(serde_json::from_slice(&buf)
        .map_err(|e| tokio::io::Error::new(tokio::io::ErrorKind::InvalidData, e))?)
}

async fn read_with_timeout(socket: &mut TcpStream) -> tokio::io::Result<bool> {
    match timeout(Duration::from_secs(3), read_msg(socket)).await {
        Ok(Ok(_)) => Ok(true),
        Ok(Err(e)) => Err(e),
        Err(_) => Ok(false),
    }
}

async fn connect_with_proxy(
    addr: SocketAddr,
    proxy: Option<SocketAddr>,
) -> tokio::io::Result<TcpStream> {
    if let Some(p) = proxy {
        tokio_socks::tcp::Socks5Stream::connect(p, addr)
            .await
            .map(|s| s.into_inner())
            .map_err(|e| tokio::io::Error::new(tokio::io::ErrorKind::Other, e))
    } else {
        TcpStream::connect(addr).await
    }
}

fn load_or_create_key(path: &str) -> (secp256k1::SecretKey, secp256k1::PublicKey) {
    if let Ok(data) = std::fs::read(path) {
        if data.len() == 32 {
            if let Ok(sk) = secp256k1::SecretKey::from_slice(&data) {
                let secp = Secp256k1::new();
                let pk = secp256k1::PublicKey::from_secret_key(&secp, &sk);
                return (sk, pk);
            }
        }
    }
    let mut rng = OsRng;
    let sk = secp256k1::SecretKey::new(&mut rng);
    let secp = Secp256k1::new();
    let pk = secp256k1::PublicKey::from_secret_key(&secp, &sk);
    let _ = std::fs::write(path, sk.secret_bytes());
    (sk, pk)
}

fn sign_handshake(sk: &secp256k1::SecretKey, network_id: &str, version: u32) -> Vec<u8> {
    let mut hasher = sha2::Sha256::new();
    hasher.update(network_id.as_bytes());
    hasher.update(version.to_be_bytes());
    let hash = hasher.finalize();
    let secp = Secp256k1::new();
    let msg = secp256k1::Message::from_slice(&hash).expect("32 bytes");
    let sig = secp.sign_ecdsa_recoverable(&msg, sk);
    let (rec_id, data) = sig.serialize_compact();
    let mut out = Vec::with_capacity(65);
    out.push(rec_id.to_i32() as u8);
    out.extend_from_slice(&data);
    out
}

fn verify_handshake(h: &Handshake) -> bool {
    if h.public_key.len() != 33 || h.signature.len() != 65 {
        return false;
    }
    let pk = match secp256k1::PublicKey::from_slice(&h.public_key) {
        Ok(p) => p,
        Err(_) => return false,
    };
    let rec_id = match secp256k1::ecdsa::RecoveryId::from_i32(h.signature[0] as i32) {
        Ok(id) => id,
        Err(_) => return false,
    };
    let mut data = [0u8; 64];
    data.copy_from_slice(&h.signature[1..]);
    let sig = match secp256k1::ecdsa::RecoverableSignature::from_compact(&data, rec_id) {
        Ok(s) => s,
        Err(_) => return false,
    };
    let mut hasher = sha2::Sha256::new();
    hasher.update(h.network_id.as_bytes());
    hasher.update(h.version.to_be_bytes());
    let hash = hasher.finalize();
    let msg = secp256k1::Message::from_slice(&hash).expect("32 bytes");
    let secp = Secp256k1::new();
    match secp.recover_ecdsa(&msg, &sig) {
        Ok(p) => p == pk,
        Err(_) => false,
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, ValueEnum, serde::Deserialize)]
pub enum NodeType {
    Wallet,
    Miner,
    Verifier,
}

fn valid_block(chain: &Blockchain, block: &Block) -> bool {
    if block.header.previous_hash != chain.last_block_hash().unwrap_or_default() {
        return false;
    }
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;
    let ts = block.header.timestamp as i64;
    if (ts - now).abs() > MAX_TIME_DRIFT_SECS {
        return false;
    }
    if let Some(prev) = chain.all().last() {
        if ts <= prev.header.timestamp as i64 {
            return false;
        }
    }
    if !block.transactions.is_empty() {
        for tx in &block.transactions {
            if (!tx.sender.is_empty() && !coin::valid_address(&tx.sender))
                || !coin::valid_address(&tx.recipient)
            {
                return false;
            }
            if !tx.verify() {
                return false;
            }
        }
        let merkle = compute_merkle_root(&block.transactions);
        if merkle != block.header.merkle_root {
            return false;
        }
    }
    if let Ok(hash) = hex::decode(block.hash()) {
        meets_difficulty(&hash, block.header.difficulty)
    } else {
        false
    }
}

async fn broadcast_block_internal(
    peers: Arc<Mutex<HashSet<SocketAddr>>>,
    block: &Block,
    network_id: &str,
    version: u32,
    sk: &secp256k1::SecretKey,
    pk: &secp256k1::PublicKey,
    proxy: Option<SocketAddr>,
) {
    let list: Vec<SocketAddr> = peers.lock().await.iter().copied().collect();
    let msg = NodeMessage::Block(coin_proto::Block {
        header: coin_proto::BlockHeader {
            previous_hash: block.header.previous_hash.clone(),
            merkle_root: block.header.merkle_root.clone(),
            timestamp: block.header.timestamp,
            nonce: block.header.nonce,
            difficulty: block.header.difficulty,
        },
        transactions: block.transactions.clone(),
    });
    for addr in list {
        match connect_with_proxy(addr, proxy).await {
            Ok(mut stream) => {
                let hs = NodeMessage::Handshake(Handshake {
                    network_id: network_id.to_string(),
                    version,
                    public_key: pk.serialize().to_vec(),
                    signature: sign_handshake(sk, network_id, version),
                });
                if write_msg(&mut stream, &hs).await.is_err() {
                    peers.lock().await.remove(&addr);
                    continue;
                }
                if let Ok(resp) = read_msg(&mut stream).await {
                    match resp {
                        NodeMessage::Handshake(h)
                            if h.network_id == network_id
                                && h.version == version
                                && verify_handshake(&h) => {}
                        _ => {
                            peers.lock().await.remove(&addr);
                            continue;
                        }
                    }
                } else {
                    peers.lock().await.remove(&addr);
                    continue;
                }
                if write_msg(&mut stream, &msg).await.is_err() {
                    peers.lock().await.remove(&addr);
                }
            }
            Err(_) => {
                peers.lock().await.remove(&addr);
            }
        }
    }
}

/// Simple P2P node maintaining a peer address list and pinging peers
#[derive(Clone)]
pub struct Node {
    listeners: Vec<SocketAddr>,
    peers: Arc<Mutex<HashSet<SocketAddr>>>,
    msg_times: Arc<Mutex<HashMap<SocketAddr, (Instant, u32)>>>,
    ping_interval: Duration,
    node_type: NodeType,
    chain: Arc<Mutex<Blockchain>>,
    min_peers: usize,
    wallet_address: Option<String>,
    peers_file: String,
    tor_proxy: Option<SocketAddr>,
    network_id: String,
    protocol_version: u32,
    max_msgs_per_sec: u32,
    max_peers: usize,
    mining_threads: usize,
    node_key: secp256k1::SecretKey,
    node_pub: secp256k1::PublicKey,
    key_file: String,
    running: Arc<AtomicBool>,
}

impl Node {
    pub fn new(
        listeners: Vec<SocketAddr>,
        node_type: NodeType,
        min_peers: Option<usize>,
        wallet_address: Option<String>,
        peers_file: Option<String>,
        tor_proxy: Option<SocketAddr>,
        network_id: Option<String>,
        protocol_version: Option<u32>,
        max_msgs_per_sec: Option<u32>,
        max_peers: Option<usize>,
        mining_threads: Option<usize>,
    ) -> Self {
        let (node_key, node_pub) = load_or_create_key("node.key");
        Self {
            listeners,
            peers: Arc::new(Mutex::new(HashSet::new())),
            msg_times: Arc::new(Mutex::new(HashMap::new())),
            ping_interval: Duration::from_secs(5),
            node_type,
            chain: Arc::new(Mutex::new(Blockchain::new())),
            min_peers: min_peers.unwrap_or(1),
            wallet_address,
            peers_file: peers_file.unwrap_or_else(|| "peers.bin".to_string()),
            tor_proxy,
            network_id: network_id.unwrap_or_else(|| "coin".to_string()),
            protocol_version: protocol_version.unwrap_or(1),
            max_msgs_per_sec: max_msgs_per_sec.unwrap_or(DEFAULT_MAX_MSGS_PER_SEC),
            max_peers: max_peers.unwrap_or(DEFAULT_MAX_PEERS),
            mining_threads: mining_threads.unwrap_or_else(|| {
                std::thread::available_parallelism()
                    .map(|n| n.get())
                    .unwrap_or(1)
            }),
            node_key,
            node_pub,
            key_file: "node.key".to_string(),
            running: Arc::new(AtomicBool::new(true)),
        }
    }

    pub fn chain_handle(&self) -> Arc<Mutex<Blockchain>> {
        self.chain.clone()
    }

    async fn connect_stream(&self, addr: SocketAddr) -> tokio::io::Result<TcpStream> {
        connect_with_proxy(addr, self.tor_proxy).await
    }

    #[allow(dead_code)]
    pub fn with_interval(
        listeners: Vec<SocketAddr>,
        interval: Duration,
        node_type: NodeType,
        min_peers: Option<usize>,
        wallet_address: Option<String>,
        peers_file: Option<String>,
        tor_proxy: Option<SocketAddr>,
        network_id: Option<String>,
        protocol_version: Option<u32>,
        max_msgs_per_sec: Option<u32>,
        max_peers: Option<usize>,
        mining_threads: Option<usize>,
    ) -> Self {
        let (node_key, node_pub) = load_or_create_key("node.key");
        Self {
            listeners,
            peers: Arc::new(Mutex::new(HashSet::new())),
            msg_times: Arc::new(Mutex::new(HashMap::new())),
            ping_interval: interval,
            node_type,
            chain: Arc::new(Mutex::new(Blockchain::new())),
            min_peers: min_peers.unwrap_or(1),
            wallet_address,
            peers_file: peers_file.unwrap_or_else(|| "peers.bin".to_string()),
            tor_proxy,
            network_id: network_id.unwrap_or_else(|| "coin".to_string()),
            protocol_version: protocol_version.unwrap_or(1),
            max_msgs_per_sec: max_msgs_per_sec.unwrap_or(DEFAULT_MAX_MSGS_PER_SEC),
            max_peers: max_peers.unwrap_or(DEFAULT_MAX_PEERS),
            mining_threads: mining_threads.unwrap_or_else(|| {
                std::thread::available_parallelism()
                    .map(|n| n.get())
                    .unwrap_or(1)
            }),
            node_key,
            node_pub,
            key_file: "node.key".to_string(),
            running: Arc::new(AtomicBool::new(true)),
        }
    }

    pub fn node_type(&self) -> NodeType {
        self.node_type
    }

    pub fn shutdown(&self) {
        self.running.store(false, Ordering::SeqCst);
    }

    pub fn is_running(&self) -> bool {
        self.running.load(Ordering::SeqCst)
    }

    fn build_handshake(&self) -> Handshake {
        Handshake {
            network_id: self.network_id.clone(),
            version: self.protocol_version,
            public_key: self.node_pub.serialize().to_vec(),
            signature: sign_handshake(&self.node_key, &self.network_id, self.protocol_version),
        }
    }

    pub async fn status(&self) -> (usize, usize, usize) {
        let peers = self.peers.lock().await.len();
        let chain = self.chain.lock().await;
        let chain_len = chain.len();
        let mem_len = chain.mempool_len();
        (peers, chain_len, mem_len)
    }

    async fn load_peers(&self) {
        if let Ok(data) = tokio::fs::read(&self.peers_file).await {
            if let Ok(list) = bincode::deserialize::<Vec<SocketAddr>>(&data) {
                self.peers.lock().await.extend(list);
            }
        }
    }

    pub async fn save_peers(&self) -> tokio::io::Result<()> {
        let list: Vec<SocketAddr> = self.peers.lock().await.iter().cloned().collect();
        let data = bincode::serialize(&list)
            .map_err(|e| tokio::io::Error::new(tokio::io::ErrorKind::Other, e))?;
        tokio::fs::write(&self.peers_file, data).await
    }

    async fn restore_mempool(&self) {
        let _ = std::fs::remove_file("mempool.bin");
        let mut chain = self.chain.lock().await;
        let _ = chain.load_mempool("mempool.bin");
    }

    fn spawn_mempool_saver(&self) {
        let save_chain = self.chain.clone();
        let save_running = self.running.clone();
        tokio::spawn(async move {
            while save_running.load(Ordering::SeqCst) {
                {
                    let chain = save_chain.lock().await;
                    let _ = chain.save_mempool("mempool.bin");
                }
                tokio::time::sleep(Duration::from_secs(5)).await;
            }
        });
    }

    fn spawn_ping_loop(&self) {
        let peers = self.peers.clone();
        let interval = self.ping_interval;
        let nid = self.network_id.clone();
        let ver = self.protocol_version;
        let proxy = self.tor_proxy;
        let key = self.node_key.clone();
        let pubk = self.node_pub.clone();
        let running = self.running.clone();
        tokio::spawn(async move {
            loop {
                if !running.load(Ordering::SeqCst) {
                    break;
                }
                tokio::time::sleep(interval).await;
                let list: Vec<SocketAddr> = peers.lock().await.iter().copied().collect();
                for addr in list {
                    let peers = peers.clone();
                    let nid = nid.clone();
                    let ver = ver;
                    let running = running.clone();
                    let key = key.clone();
                    let pubk = pubk.clone();
                    tokio::spawn(async move {
                        if !running.load(Ordering::SeqCst) {
                            return;
                        }
                        if let Ok(mut stream) = connect_with_proxy(addr, proxy).await {
                            let hs = NodeMessage::Handshake(Handshake {
                                network_id: nid.clone(),
                                version: ver,
                                public_key: pubk.serialize().to_vec(),
                                signature: sign_handshake(&key, &nid, ver),
                            });
                            if write_msg(&mut stream, &hs).await.is_ok() {
                                if let Ok(resp) = read_msg(&mut stream).await {
                                    if matches!(resp, NodeMessage::Handshake(h) if verify_handshake(&h))
                                    {
                                        let ping = NodeMessage::Ping(Ping {});
                                        if write_msg(&mut stream, &ping).await.is_ok() {
                                            match read_with_timeout(&mut stream).await {
                                                Ok(true) => return,
                                                Ok(false) => (),
                                                Err(_) => (),
                                            }
                                        }
                                    }
                                }
                            }
                        }
                        peers.lock().await.remove(&addr);
                    });
                }
            }
        });
    }

    fn spawn_miner_loop(&self) {
        let peers = self.peers.clone();
        let chain = self.chain.clone();
        let min = self.min_peers;
        let reward = self
            .wallet_address
            .clone()
            .unwrap_or_else(|| "miner".to_string());
        let nid = self.network_id.clone();
        let ver = self.protocol_version;
        let threads = self.mining_threads;
        let proxy = self.tor_proxy;
        let node_key = self.node_key.clone();
        let node_pub = self.node_pub.clone();
        let running = self.running.clone();
        tokio::spawn(async move {
            loop {
                if !running.load(Ordering::SeqCst) {
                    break;
                }
                while peers.lock().await.len() < min {
                    tokio::time::sleep(Duration::from_millis(50)).await;
                }
                {
                    let mut chain = chain.lock().await;
                    if chain.len() == 0 || chain.mempool_len() > 0 {
                        let block = mine_block_threads(&mut chain, &reward, threads);
                        broadcast_block_internal(
                            peers.clone(),
                            &block,
                            &nid,
                            ver,
                            &node_key,
                            &node_pub,
                            proxy,
                        )
                        .await;
                    }
                }
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
        });
    }

    /// Start IPv4 and IPv6 listeners and return local addresses and receiver for incoming transactions
    pub async fn start(&self) -> tokio::io::Result<(Vec<SocketAddr>, mpsc::Receiver<Transaction>)> {
        self.running.store(true, Ordering::SeqCst);
        self.load_peers().await;

        self.restore_mempool().await;
        self.spawn_mempool_saver();

        let mut listeners = Vec::new();
        for addr in &self.listeners {
            listeners.push(TcpListener::bind(addr).await?);
        }
        let local_addrs: Vec<SocketAddr> =
            listeners.iter().map(|l| l.local_addr().unwrap()).collect();
        let (tx, rx) = mpsc::channel(8);
        let peers = self.peers.clone();
        let chain = self.chain.clone();
        let msg_times = self.msg_times.clone();
        let max = self.max_msgs_per_sec;
        let max_peers = self.max_peers;
        let network_id = self.network_id.clone();
        let protocol_version = self.protocol_version;
        let key = self.node_key.clone();
        let pubk = self.node_pub.clone();

        // accept loop for each listener
        for listener in listeners {
            let tx = tx.clone();
            let peers = peers.clone();
            let chain = chain.clone();
            let rates = msg_times.clone();
            let nid = network_id.clone();
            let ver = protocol_version;
            let max = max;
            let cap = max_peers;
            let running = self.running.clone();
            let key = key.clone();
            let pubk = pubk.clone();
            tokio::spawn(async move {
                loop {
                    if !running.load(Ordering::SeqCst) {
                        break;
                    }
                    if let Ok((mut socket, _addr)) = listener.accept().await {
                        if peers.lock().await.len() >= cap {
                            continue;
                        }
                        let tx = tx.clone();
                        let peers = peers.clone();
                        let chain = chain.clone();
                        let rates = rates.clone();
                        let nid = nid.clone();
                        let ver = ver;
                        let max = max;
                        let running = running.clone();
                        tokio::spawn(async move {
                            if !running.load(Ordering::SeqCst) {
                                return;
                            }
                            // expect handshake first
                            let msg = match read_msg(&mut socket).await {
                                Ok(m) => m,
                                Err(_) => return,
                            };
                            if let NodeMessage::Handshake(h) = msg {
                                if h.network_id != nid || h.version != ver || !verify_handshake(&h)
                                {
                                    return;
                                }
                            } else {
                                return;
                            }
                            if let Ok(a) = socket.peer_addr() {
                                let mut set = peers.lock().await;
                                if set.len() >= cap {
                                    return;
                                }
                                set.insert(a);
                                drop(set);
                                rates.lock().await.insert(a, (Instant::now(), 0));
                            }
                            let resp = NodeMessage::Handshake(Handshake {
                                network_id: nid.clone(),
                                version: ver,
                                public_key: pubk.serialize().to_vec(),
                                signature: sign_handshake(&key, &nid, ver),
                            });
                            if write_msg(&mut socket, &resp).await.is_err() {
                                return;
                            }
                            loop {
                                match read_msg(&mut socket).await {
                                    Ok(msg) => {
                                        if let Ok(a) = socket.peer_addr() {
                                            let mut rl = rates.lock().await;
                                            let entry = rl.entry(a).or_insert((Instant::now(), 0));
                                            let now = Instant::now();
                                            if now.duration_since(entry.0) >= Duration::from_secs(1)
                                            {
                                                entry.0 = now;
                                                entry.1 = 0;
                                            }
                                            entry.1 += 1;
                                            if entry.1 > max {
                                                peers.lock().await.remove(&a);
                                                rl.remove(&a);
                                                break;
                                            }
                                        }
                                        match msg {
                                            NodeMessage::Transaction(t) => {
                                                let mut chain = chain.lock().await;
                                                if chain.add_transaction(t.clone()) {
                                                    let _ = tx.send(t.clone()).await;
                                                }
                                            }
                                            NodeMessage::Ping(_) => {
                                                let resp = NodeMessage::Pong(Pong {});
                                                let _ = write_msg(&mut socket, &resp).await;
                                            }
                                            NodeMessage::Pong(_) => {}
                                            NodeMessage::GetPeers(_) => {
                                                let list: Vec<String> = peers
                                                    .lock()
                                                    .await
                                                    .iter()
                                                    .map(|a| a.to_string())
                                                    .collect();
                                                let msg = NodeMessage::Peers(Peers { addrs: list });
                                                let _ = write_msg(&mut socket, &msg).await;
                                            }
                                            NodeMessage::Peers(p) => {
                                                for s in p.addrs {
                                                    if let Ok(mut addrs) =
                                                        StdToSocketAddrs::to_socket_addrs(&s)
                                                    {
                                                        if let Some(addr) = addrs.next() {
                                                            peers.lock().await.insert(addr);
                                                        }
                                                    }
                                                }
                                            }
                                            NodeMessage::GetChain(_) => {
                                                let blocks = chain.lock().await.all();
                                                let rpc_blocks: Vec<coin_proto::Block> = blocks
                                                    .into_iter()
                                                    .map(|b| b.to_rpc())
                                                    .collect();
                                                let msg = NodeMessage::Chain(Chain {
                                                    blocks: rpc_blocks,
                                                });
                                                let _ = write_msg(&mut socket, &msg).await;
                                            }
                                            NodeMessage::GetBlock(g) => {
                                                let blocks = chain.lock().await.all();
                                                if let Some(b) =
                                                    blocks.into_iter().find(|b| b.hash() == g.hash)
                                                {
                                                    let msg = NodeMessage::Block(b.to_rpc());
                                                    let _ = write_msg(&mut socket, &msg).await;
                                                }
                                            }
                                            NodeMessage::Chain(c) => {
                                                let blocks: Vec<Block> = c
                                                    .blocks
                                                    .into_iter()
                                                    .filter_map(Block::from_rpc)
                                                    .collect();
                                                chain.lock().await.replace(blocks);
                                            }
                                            NodeMessage::Block(b) => {
                                                if let Some(block) = Block::from_rpc(b) {
                                                    let mut chain = chain.lock().await;
                                                    if valid_block(&chain, &block) {
                                                        chain.add_block(block);
                                                    }
                                                }
                                            }
                                            NodeMessage::Handshake(_) => {}
                                        }
                                    }
                                    Err(_) => break,
                                }
                            }
                            if let Ok(a) = socket.peer_addr() {
                                peers.lock().await.remove(&a);
                                rates.lock().await.remove(&a);
                            }
                        });
                    }
                }
            });
        }

        self.spawn_ping_loop();
        if self.node_type == NodeType::Miner {
            self.spawn_miner_loop();
        }

        Ok((local_addrs, rx))
    }

    /// Connect to another peer and request their addresses
    pub async fn connect<A: tokio::net::ToSocketAddrs>(&self, addr: A) -> tokio::io::Result<()> {
        let addr = lookup_host(addr).await?.next().ok_or_else(|| {
            tokio::io::Error::new(tokio::io::ErrorKind::InvalidInput, "invalid address")
        })?;
        let mut stream = self.connect_stream(addr).await?;
        let hs = NodeMessage::Handshake(self.build_handshake());
        write_msg(&mut stream, &hs).await?;
        let resp = read_msg(&mut stream).await?;
        match resp {
            NodeMessage::Handshake(h)
                if h.network_id == self.network_id
                    && h.version == self.protocol_version
                    && verify_handshake(&h) => {}
            _ => {
                return Err(tokio::io::Error::new(
                    tokio::io::ErrorKind::InvalidData,
                    "handshake mismatch",
                ));
            }
        }
        if let Ok(peer_addr) = stream.peer_addr() {
            self.peers.lock().await.insert(peer_addr);
        }
        let get = NodeMessage::GetPeers(GetPeers {});
        write_msg(&mut stream, &get).await?;
        Ok(())
    }

    /// Request blockchain data from a peer and replace local chain if theirs is longer
    pub async fn sync_from_peer<A: tokio::net::ToSocketAddrs>(
        &self,
        addr: A,
    ) -> tokio::io::Result<()> {
        let addr = lookup_host(addr).await?.next().ok_or_else(|| {
            tokio::io::Error::new(tokio::io::ErrorKind::InvalidInput, "invalid address")
        })?;
        let mut stream = self.connect_stream(addr).await?;
        let hs = NodeMessage::Handshake(self.build_handshake());
        write_msg(&mut stream, &hs).await?;
        let resp = read_msg(&mut stream).await?;
        match resp {
            NodeMessage::Handshake(h)
                if h.network_id == self.network_id
                    && h.version == self.protocol_version
                    && verify_handshake(&h) => {}
            _ => {
                return Err(tokio::io::Error::new(
                    tokio::io::ErrorKind::InvalidData,
                    "handshake mismatch",
                ));
            }
        }
        let get = NodeMessage::GetChain(GetChain {});
        write_msg(&mut stream, &get).await?;
        if let Ok(resp) = read_msg(&mut stream).await {
            if let NodeMessage::Chain(c) = resp {
                let blocks: Vec<Block> = c.blocks.into_iter().filter_map(Block::from_rpc).collect();
                if Blockchain::validate_chain(&blocks) {
                    self.chain.lock().await.replace(blocks);
                } else {
                    return Err(tokio::io::Error::new(
                        tokio::io::ErrorKind::InvalidData,
                        "invalid chain",
                    ));
                }
            }
        }
        Ok(())
    }

    pub async fn broadcast_block(&self, block: &Block) -> tokio::io::Result<()> {
        broadcast_block_internal(
            self.peers.clone(),
            block,
            &self.network_id,
            self.protocol_version,
            &self.node_key,
            &self.node_pub,
            self.tor_proxy,
        )
        .await;
        Ok(())
    }

    pub async fn peers(&self) -> Vec<SocketAddr> {
        self.peers.lock().await.iter().copied().collect()
    }

    pub async fn chain_len(&self) -> usize {
        self.chain.lock().await.len()
    }
}

/// Send a transaction to a peer
pub async fn send_transaction(addr: &str, tx_msg: &Transaction) -> tokio::io::Result<()> {
    let addr: SocketAddr = addr
        .parse()
        .map_err(|e| tokio::io::Error::new(tokio::io::ErrorKind::InvalidInput, e))?;
    let mut stream = connect_with_proxy(addr, None).await?;
    let mut rng = OsRng;
    let sk = secp256k1::SecretKey::new(&mut rng);
    let pk = secp256k1::PublicKey::from_secret_key(&Secp256k1::new(), &sk);
    let hs = NodeMessage::Handshake(Handshake {
        network_id: "coin".into(),
        version: 1,
        public_key: pk.serialize().to_vec(),
        signature: sign_handshake(&sk, "coin", 1),
    });
    write_msg(&mut stream, &hs).await?;
    let resp = read_msg(&mut stream).await?;
    match resp {
        NodeMessage::Handshake(h)
            if h.network_id == "coin" && h.version == 1 && verify_handshake(&h) => {}
        _ => {
            return Err(tokio::io::Error::new(
                tokio::io::ErrorKind::InvalidData,
                "handshake mismatch",
            ));
        }
    }
    let msg = NodeMessage::Transaction(tx_msg.clone());
    write_msg(&mut stream, &msg).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use coin::coinbase_transaction;
    use coin_wallet::Wallet;
    use hex_literal::hex;
    use std::net::SocketAddr;
    use tempfile;
    use tokio::time::{Duration, sleep};

    const A1: &str = "1BvgsfsZQVtkLS69NvGF8rw6NZW2ShJQHr";
    const A2: &str = "1B1TKfsCkW5LQ6R1kSXUx7hLt49m1kwz75";
    const SEED: [u8; 16] = hex!("000102030405060708090a0b0c0d0e0f");

    fn sign_for(path: &str, tx: &mut Transaction) {
        let wallet = Wallet::from_seed(&SEED).unwrap();
        let sk = wallet.derive_priv(path).unwrap().secret_key().clone();
        tx.sign(&sk);
    }

    #[tokio::test]
    async fn node_connects_and_pings() {
        let node = Node::with_interval(
            vec!["0.0.0.0:0".parse().unwrap()],
            Duration::from_millis(50),
            NodeType::Wallet,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
        );
        assert_eq!(node.node_type(), NodeType::Wallet);
        let (addrs, mut rx) = node.start().await.unwrap();
        let addr = addrs[0];
        {
            let mut chain = node.chain.lock().await;
            let reward = chain.block_subsidy();
            chain.add_block(Block {
                header: BlockHeader {
                    previous_hash: String::new(),
                    merkle_root: String::new(),
                    timestamp: 0,
                    nonce: 0,
                    difficulty: 0,
                },
                transactions: vec![coinbase_transaction(A1.clone(), reward)],
            });
        }
        node.connect(addr).await.unwrap();
        sleep(Duration::from_millis(200)).await;
        let peers = node.peers().await;
        assert!(peers.iter().any(|p| p.port() == addr.port()));
        let mut tx = Transaction {
            sender: A1.into(),
            recipient: A2.into(),
            amount: 1,
            fee: 0,
            signature: Vec::new(),
            encrypted_message: Vec::new(),
            inputs: vec![],
            outputs: vec![],
        };
        sign_for("m/0'/0/0", &mut tx);
        send_transaction(&addr.to_string(), &tx).await.unwrap();
        let rec = tokio::time::timeout(Duration::from_secs(1), rx.recv())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(rec, tx);
    }

    #[tokio::test]
    async fn peers_message_updates_list() {
        let node = Node::new(
            vec!["0.0.0.0:0".parse().unwrap()],
            NodeType::Wallet,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
        );
        let (addrs, _rx) = node.start().await.unwrap();
        let addr = addrs[0];
        let mut stream = TcpStream::connect(addr).await.unwrap();
        let mut rng = OsRng;
        let sk = secp256k1::SecretKey::new(&mut rng);
        let pk = secp256k1::PublicKey::from_secret_key(&Secp256k1::new(), &sk);
        let hs = NodeMessage::Handshake(Handshake {
            network_id: "coin".into(),
            version: 1,
            public_key: pk.serialize().to_vec(),
            signature: sign_handshake(&sk, "coin", 1),
        });
        write_msg(&mut stream, &hs).await.unwrap();
        let _ = read_msg(&mut stream).await.unwrap();
        let peers_msg = NodeMessage::Peers(Peers {
            addrs: vec!["127.0.0.1:12345".into()],
        });
        write_msg(&mut stream, &peers_msg).await.unwrap();
        sleep(Duration::from_millis(50)).await;
        let peers = node.peers().await;
        assert!(peers.iter().any(|p| p.port() == 12345));
    }

    #[tokio::test]
    async fn unreachable_peer_gets_dropped() {
        let node = Node::with_interval(
            vec!["0.0.0.0:0".parse().unwrap()],
            Duration::from_millis(50),
            NodeType::Wallet,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
        );
        let (_addrs, _rx) = node.start().await.unwrap();
        let unreachable: SocketAddr = "127.0.0.1:9".parse().unwrap();
        node.peers.lock().await.insert(unreachable);
        sleep(Duration::from_millis(200)).await;
        assert!(!node.peers().await.contains(&unreachable));
    }

    #[tokio::test]
    async fn sync_from_peer_updates_chain() {
        let node_a = Node::with_interval(
            vec!["0.0.0.0:0".parse().unwrap()],
            Duration::from_millis(50),
            NodeType::Verifier,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
        );
        let (addrs_a, _) = node_a.start().await.unwrap();
        let addr_a = addrs_a[0];
        {
            let mut chain = node_a.chain.lock().await;
            let mut tx = Transaction {
                sender: A1.into(),
                recipient: A2.into(),
                amount: 2,
                fee: 0,
                signature: Vec::new(),
                encrypted_message: Vec::new(),
                inputs: vec![],
                outputs: vec![],
            };
            sign_for("m/0'/0/0", &mut tx);
            chain.add_transaction(tx);
            let mut block = chain.candidate_block();
            block.header.difficulty = 0;
            chain.add_block(block);
        }

        let node_b = Node::with_interval(
            vec!["0.0.0.0:0".parse().unwrap()],
            Duration::from_millis(50),
            NodeType::Verifier,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
        );
        let (addrs_b, _) = node_b.start().await.unwrap();
        let addr_b = addrs_b[0];
        node_b.connect(addr_a).await.unwrap();
        node_b.sync_from_peer(addr_a).await.unwrap();
        assert_eq!(node_b.chain_len().await, 1);
        node_a.peers.lock().await.remove(&addr_b);
        node_b.peers.lock().await.remove(&addr_a);
    }

    #[tokio::test]
    async fn sync_from_peer_rejects_invalid_chain() {
        let node_a = Node::with_interval(
            vec!["0.0.0.0:0".parse().unwrap()],
            Duration::from_millis(50),
            NodeType::Verifier,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
        );
        let (addrs_a, _) = node_a.start().await.unwrap();
        let addr_a = addrs_a[0];
        {
            let mut chain = node_a.chain.lock().await;
            chain.add_block(Block {
                header: BlockHeader {
                    previous_hash: String::new(),
                    merkle_root: String::new(),
                    timestamp: 0,
                    nonce: 0,
                    difficulty: 0,
                },
                transactions: vec![Transaction {
                    sender: A1.into(),
                    recipient: A2.into(),
                    amount: 2,
                    fee: 0,
                    signature: Vec::new(),
                    encrypted_message: Vec::new(),
                    inputs: vec![],
                    outputs: vec![],
                }],
            });
        }

        let node_b = Node::with_interval(
            vec!["0.0.0.0:0".parse().unwrap()],
            Duration::from_millis(50),
            NodeType::Verifier,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
        );
        let (addrs_b, _) = node_b.start().await.unwrap();
        let addr_b = addrs_b[0];
        node_b.connect(addr_a).await.unwrap();
        assert!(node_b.sync_from_peer(addr_a).await.is_err());
        assert_eq!(node_b.chain_len().await, 0);
        node_a.peers.lock().await.remove(&addr_b);
        node_b.peers.lock().await.remove(&addr_a);
    }

    #[tokio::test]
    async fn chain_message_updates_chain() {
        let node = Node::new(
            vec!["0.0.0.0:0".parse().unwrap()],
            NodeType::Wallet,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
        );
        let (addrs, _rx) = node.start().await.unwrap();
        let addr = addrs[0];
        let mut stream = TcpStream::connect(addr).await.unwrap();
        let mut rng = OsRng;
        let sk = secp256k1::SecretKey::new(&mut rng);
        let pk = secp256k1::PublicKey::from_secret_key(&Secp256k1::new(), &sk);
        let hs = NodeMessage::Handshake(Handshake {
            network_id: "coin".into(),
            version: 1,
            public_key: pk.serialize().to_vec(),
            signature: sign_handshake(&sk, "coin", 1),
        });
        write_msg(&mut stream, &hs).await.unwrap();
        let _ = read_msg(&mut stream).await.unwrap();
        let mut tx = Transaction {
            sender: A1.into(),
            recipient: A2.into(),
            amount: 3,
            fee: 0,
            signature: Vec::new(),
            encrypted_message: Vec::new(),
            inputs: vec![],
            outputs: vec![],
        };
        sign_for("m/0'/0/0", &mut tx);
        let block = coin_proto::Block {
            header: coin_proto::BlockHeader {
                previous_hash: String::new(),
                merkle_root: "m".into(),
                timestamp: 0,
                nonce: 0,
                difficulty: 0,
            },
            transactions: vec![tx],
        };
        let chain_msg = NodeMessage::Chain(Chain {
            blocks: vec![block],
        });
        write_msg(&mut stream, &chain_msg).await.unwrap();
        sleep(Duration::from_millis(50)).await;
        assert_eq!(node.chain_len().await, 1);
    }

    #[tokio::test]
    async fn block_message_updates_chain() {
        let node = Node::new(
            vec!["0.0.0.0:0".parse().unwrap()],
            NodeType::Verifier,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
        );
        let (addrs, _rx) = node.start().await.unwrap();
        let addr = addrs[0];
        let mut stream = TcpStream::connect(addr).await.unwrap();
        let mut rng = OsRng;
        let sk = secp256k1::SecretKey::new(&mut rng);
        let pk = secp256k1::PublicKey::from_secret_key(&Secp256k1::new(), &sk);
        let hs = NodeMessage::Handshake(Handshake {
            network_id: "coin".into(),
            version: 1,
            public_key: pk.serialize().to_vec(),
            signature: sign_handshake(&sk, "coin", 1),
        });
        write_msg(&mut stream, &hs).await.unwrap();
        let _ = read_msg(&mut stream).await.unwrap();
        let mut tx = Transaction {
            sender: A1.into(),
            recipient: A2.into(),
            amount: 1,
            fee: 0,
            signature: Vec::new(),
            encrypted_message: Vec::new(),
            inputs: vec![],
            outputs: vec![],
        };
        sign_for("m/0'/0/0", &mut tx);
        let merkle = compute_merkle_root(&[tx.clone()]);
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let block_msg = NodeMessage::Block(coin_proto::Block {
            header: coin_proto::BlockHeader {
                previous_hash: String::new(),
                merkle_root: merkle,
                timestamp: now,
                nonce: 0,
                difficulty: 0,
            },
            transactions: vec![tx],
        });
        write_msg(&mut stream, &block_msg).await.unwrap();
        sleep(Duration::from_millis(50)).await;
        assert_eq!(node.chain_len().await, 1);
    }

    #[tokio::test]
    async fn broadcast_block_propagates() {
        let node_a = Node::with_interval(
            vec!["0.0.0.0:0".parse().unwrap()],
            Duration::from_millis(50),
            NodeType::Verifier,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
        );
        let (addrs_a, _) = node_a.start().await.unwrap();
        let addr_a = addrs_a[0];

        let node_b = Node::with_interval(
            vec!["0.0.0.0:0".parse().unwrap()],
            Duration::from_millis(50),
            NodeType::Verifier,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
        );
        let (addrs_b, _) = node_b.start().await.unwrap();
        let addr_b = addrs_b[0];

        node_a.peers.lock().await.insert(addr_b);

        let mut tx = Transaction {
            sender: A1.into(),
            recipient: A2.into(),
            amount: 2,
            fee: 0,
            signature: Vec::new(),
            encrypted_message: Vec::new(),
            inputs: vec![],
            outputs: vec![],
        };
        sign_for("m/0'/0/0", &mut tx);
        let merkle = compute_merkle_root(&[tx.clone()]);
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let block = Block {
            header: BlockHeader {
                previous_hash: String::new(),
                merkle_root: merkle,
                timestamp: now,
                nonce: 0,
                difficulty: 0,
            },
            transactions: vec![tx],
        };
        node_a.chain.lock().await.add_block(block.clone());
        node_a.broadcast_block(&block).await.unwrap();

        sleep(Duration::from_millis(100)).await;
        assert_eq!(node_b.chain_len().await, 1);

        node_a.peers.lock().await.remove(&addr_b);
        node_b.peers.lock().await.remove(&addr_a);
    }

    #[tokio::test]
    async fn validate_block_logic() {
        let mut chain = Blockchain::new();
        let mut tx0 = Transaction {
            sender: A1.into(),
            recipient: A2.into(),
            amount: 1,
            fee: 0,
            signature: Vec::new(),
            encrypted_message: Vec::new(),
            inputs: vec![],
            outputs: vec![],
        };
        sign_for("m/0'/0/0", &mut tx0);
        chain.add_transaction(tx0);
        let genesis = chain.candidate_block();
        chain.add_block(genesis.clone());

        let mut tx = Transaction {
            sender: A2.into(),
            recipient: A1.into(),
            amount: 2,
            fee: 0,
            signature: Vec::new(),
            encrypted_message: Vec::new(),
            inputs: vec![],
            outputs: vec![],
        };
        sign_for("m/0'/0/1", &mut tx);
        let merkle = compute_merkle_root(&[tx.clone()]);
        let block = Block {
            header: BlockHeader {
                previous_hash: genesis.hash(),
                merkle_root: merkle.clone(),
                timestamp: genesis.header.timestamp + 1,
                nonce: 0,
                difficulty: 0,
            },
            transactions: vec![tx.clone()],
        };

        assert!(valid_block(&chain, &block));

        let mut bad = block.clone();
        bad.header.merkle_root = String::new();
        assert!(!valid_block(&chain, &bad));
    }

    #[tokio::test]
    async fn reject_block_timestamp_future_and_past() {
        let mut chain = Blockchain::new();
        chain.add_block(chain.candidate_block());

        let mut tx = Transaction {
            sender: A2.into(),
            recipient: A1.into(),
            amount: 1,
            fee: 0,
            signature: Vec::new(),
            encrypted_message: Vec::new(),
            inputs: vec![],
            outputs: vec![],
        };
        sign_for("m/0'/0/1", &mut tx);
        let merkle = compute_merkle_root(&[tx.clone()]);
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let future_block = Block {
            header: BlockHeader {
                previous_hash: chain.last_block_hash().unwrap(),
                merkle_root: merkle.clone(),
                timestamp: now + (MAX_TIME_DRIFT_SECS as u64) + 1,
                nonce: 0,
                difficulty: 0,
            },
            transactions: vec![tx.clone()],
        };
        assert!(!valid_block(&chain, &future_block));

        let past_block = Block {
            header: BlockHeader {
                previous_hash: chain.last_block_hash().unwrap(),
                merkle_root: merkle.clone(),
                timestamp: now - (MAX_TIME_DRIFT_SECS as u64) - 1,
                nonce: 0,
                difficulty: 0,
            },
            transactions: vec![tx.clone()],
        };
        assert!(!valid_block(&chain, &past_block));
    }

    #[tokio::test]
    async fn reject_block_non_monotonic_timestamp() {
        let mut chain = Blockchain::new();
        let genesis = chain.candidate_block();
        chain.add_block(genesis.clone());

        let mut tx = Transaction {
            sender: A2.into(),
            recipient: A1.into(),
            amount: 1,
            fee: 0,
            signature: Vec::new(),
            encrypted_message: Vec::new(),
            inputs: vec![],
            outputs: vec![],
        };
        sign_for("m/0'/0/1", &mut tx);
        let merkle = compute_merkle_root(&[tx.clone()]);
        let block = Block {
            header: BlockHeader {
                previous_hash: genesis.hash(),
                merkle_root: merkle,
                timestamp: genesis.header.timestamp,
                nonce: 0,
                difficulty: 0,
            },
            transactions: vec![tx.clone()],
        };
        assert!(!valid_block(&chain, &block));
    }

    #[tokio::test]
    async fn miner_mines_genesis_block() {
        let miner = Node::with_interval(
            vec!["0.0.0.0:0".parse().unwrap()],
            Duration::from_millis(50),
            NodeType::Miner,
            Some(0),
            Some(A1.to_string()),
            None,
            None,
            None,
            None,
            None,
            None,
            None,
        );
        let (_addrs, _rx) = miner.start().await.unwrap();
        sleep(Duration::from_millis(200)).await;
        assert_eq!(miner.chain_len().await, 1);
    }

    #[tokio::test]
    async fn miner_mines_pending_tx() {
        let node = Node::with_interval(
            vec!["0.0.0.0:0".parse().unwrap()],
            Duration::from_millis(50),
            NodeType::Miner,
            Some(0),
            Some(A1.to_string()),
            None,
            None,
            None,
            None,
            None,
            None,
            None,
        );
        let (_addrs, _rx) = node.start().await.unwrap();
        {
            let mut chain = node.chain.lock().await;
            let reward = chain.block_subsidy();
            chain.add_block(Block {
                header: BlockHeader {
                    previous_hash: String::new(),
                    merkle_root: String::new(),
                    timestamp: 0,
                    nonce: 0,
                    difficulty: 0,
                },
                transactions: vec![coinbase_transaction(A1, reward)],
            });
            let mut tx = Transaction {
                sender: A1.into(),
                recipient: A2.into(),
                amount: 1,
                fee: 0,
                signature: Vec::new(),
                encrypted_message: Vec::new(),
                inputs: vec![],
                outputs: vec![],
            };
            sign_for("m/0'/0/0", &mut tx);
            chain.add_transaction(tx);
        }
        sleep(Duration::from_millis(200)).await;
        assert_eq!(node.chain_len().await, 2);
    }

    #[tokio::test]
    async fn miner_waits_for_peers() {
        let miner = Node::with_interval(
            vec!["0.0.0.0:0".parse().unwrap()],
            Duration::from_millis(50),
            NodeType::Miner,
            Some(1),
            Some(A1.to_string()),
            None,
            None,
            None,
            None,
            None,
            None,
            None,
        );
        let (_m_addrs, _rx) = miner.start().await.unwrap();
        {
            let mut chain = miner.chain.lock().await;
            let reward = chain.block_subsidy();
            chain.add_block(Block {
                header: BlockHeader {
                    previous_hash: String::new(),
                    merkle_root: String::new(),
                    timestamp: 0,
                    nonce: 0,
                    difficulty: 0,
                },
                transactions: vec![coinbase_transaction(A1, reward)],
            });
            let mut tx = Transaction {
                sender: A1.into(),
                recipient: A2.into(),
                amount: 1,
                fee: 0,
                signature: Vec::new(),
                encrypted_message: Vec::new(),
                inputs: vec![],
                outputs: vec![],
            };
            sign_for("m/0'/0/0", &mut tx);
            chain.add_transaction(tx);
        }
        sleep(Duration::from_millis(200)).await;
        // mining should wait for peers
        assert_eq!(miner.chain_len().await, 1);

        let peer = Node::with_interval(
            vec!["0.0.0.0:0".parse().unwrap()],
            Duration::from_millis(50),
            NodeType::Verifier,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
        );
        let (addrs, _) = peer.start().await.unwrap();
        miner.connect(addrs[0]).await.unwrap();
        sleep(Duration::from_millis(200)).await;
        assert_eq!(miner.chain_len().await, 2);
    }

    #[tokio::test]
    async fn load_and_save_peers() {
        let tmp = tempfile::NamedTempFile::new().unwrap();
        let file = tmp.path().to_string_lossy().to_string();
        let node = Node::with_interval(
            vec!["0.0.0.0:0".parse().unwrap()],
            Duration::from_millis(50),
            NodeType::Wallet,
            None,
            None,
            Some(file.clone()),
            None,
            None,
            None,
            None,
            None,
            None,
        );
        let (_addrs, _rx) = node.start().await.unwrap();
        let peer: SocketAddr = "127.0.0.1:12345".parse().unwrap();
        node.peers.lock().await.insert(peer);
        node.save_peers().await.unwrap();

        let node2 = Node::with_interval(
            vec!["0.0.0.0:0".parse().unwrap()],
            Duration::from_millis(50),
            NodeType::Wallet,
            None,
            None,
            Some(file.clone()),
            None,
            None,
            None,
            None,
            None,
            None,
        );
        let (_a2, _r2) = node2.start().await.unwrap();
        assert!(node2.peers().await.contains(&peer));
    }

    #[tokio::test]
    async fn mismatched_handshake_disconnects() {
        let node_a = Node::new(
            vec!["0.0.0.0:0".parse().unwrap()],
            NodeType::Wallet,
            None,
            None,
            None,
            None,
            Some("net1".into()),
            Some(1),
            None,
            None,
            None,
        );
        let (addrs, _) = node_a.start().await.unwrap();
        let addr = addrs[0];
        let node_b = Node::new(
            vec!["0.0.0.0:0".parse().unwrap()],
            NodeType::Wallet,
            None,
            None,
            None,
            None,
            Some("net2".into()),
            Some(1),
            None,
            None,
            None,
        );
        assert!(node_b.connect(addr).await.is_err());
        assert!(node_b.peers().await.is_empty());

        let node_c = Node::new(
            vec!["0.0.0.0:0".parse().unwrap()],
            NodeType::Wallet,
            None,
            None,
            None,
            None,
            Some("net1".into()),
            Some(2),
            None,
            None,
            None,
        );
        assert!(node_c.connect(addr).await.is_err());
        assert!(node_c.peers().await.is_empty());
    }

    #[tokio::test]
    async fn invalid_signature_disconnects() {
        let node = Node::new(
            vec!["0.0.0.0:0".parse().unwrap()],
            NodeType::Wallet,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
        );
        let (addrs, _) = node.start().await.unwrap();
        let addr = addrs[0];
        let mut stream = TcpStream::connect(addr).await.unwrap();
        let mut rng = OsRng;
        let sk = secp256k1::SecretKey::new(&mut rng);
        let pk = secp256k1::PublicKey::from_secret_key(&Secp256k1::new(), &sk);
        let mut sig = sign_handshake(&sk, "coin", 1);
        sig[0] ^= 0x01; // corrupt signature
        let hs = NodeMessage::Handshake(Handshake {
            network_id: "coin".into(),
            version: 1,
            public_key: pk.serialize().to_vec(),
            signature: sig,
        });
        write_msg(&mut stream, &hs).await.unwrap();
        let res = timeout(Duration::from_millis(100), read_msg(&mut stream)).await;
        assert!(res.is_err() || res.unwrap().is_err());
        assert!(node.peers().await.is_empty());
    }

    #[tokio::test]
    async fn valid_signature_allows_connection() {
        let node = Node::new(
            vec!["0.0.0.0:0".parse().unwrap()],
            NodeType::Wallet,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
        );
        let (addrs, _) = node.start().await.unwrap();
        let addr = addrs[0];
        let mut stream = TcpStream::connect(addr).await.unwrap();
        let mut rng = OsRng;
        let sk = secp256k1::SecretKey::new(&mut rng);
        let pk = secp256k1::PublicKey::from_secret_key(&Secp256k1::new(), &sk);
        let hs = NodeMessage::Handshake(Handshake {
            network_id: "coin".into(),
            version: 1,
            public_key: pk.serialize().to_vec(),
            signature: sign_handshake(&sk, "coin", 1),
        });
        write_msg(&mut stream, &hs).await.unwrap();
        match read_msg(&mut stream).await.unwrap() {
            NodeMessage::Handshake(_) => {}
            other => panic!("expected handshake, got {:?}", other),
        }
        assert_eq!(node.peers().await.len(), 1);
    }

    #[tokio::test]
    async fn rate_limit_disconnects_spammy_peer() {
        let node = Node::with_interval(
            vec!["0.0.0.0:0".parse().unwrap()],
            Duration::from_millis(50),
            NodeType::Verifier,
            None,
            None,
            None,
            None,
            None,
            None,
            Some(5),
            None,
            None,
        );
        let (addrs, _) = node.start().await.unwrap();
        let addr = addrs[0];
        let mut stream = TcpStream::connect(addr).await.unwrap();
        let mut rng = OsRng;
        let sk = secp256k1::SecretKey::new(&mut rng);
        let pk = secp256k1::PublicKey::from_secret_key(&Secp256k1::new(), &sk);
        let hs = NodeMessage::Handshake(Handshake {
            network_id: "coin".into(),
            version: 1,
            public_key: pk.serialize().to_vec(),
            signature: sign_handshake(&sk, "coin", 1),
        });
        write_msg(&mut stream, &hs).await.unwrap();
        let _ = read_msg(&mut stream).await.unwrap();
        for _ in 0..6 {
            let ping = NodeMessage::Ping(Ping {});
            write_msg(&mut stream, &ping).await.unwrap();
        }
        sleep(Duration::from_millis(100)).await;
        let mut closed = false;
        for _ in 0..10 {
            if read_msg(&mut stream).await.is_err() {
                closed = true;
                break;
            }
        }
        assert!(closed);
    }

    #[tokio::test]
    async fn reject_excess_incoming_peers() {
        let node = Node::new(
            vec!["0.0.0.0:0".parse().unwrap()],
            NodeType::Wallet,
            None,
            None,
            None,
            None,
            None,
            None,
            Some(1),
            None,
            None,
        );
        let (addrs, _) = node.start().await.unwrap();
        let addr = addrs[0];

        let mut s1 = TcpStream::connect(addr).await.unwrap();
        let mut rng = OsRng;
        let sk1 = secp256k1::SecretKey::new(&mut rng);
        let pk1 = secp256k1::PublicKey::from_secret_key(&Secp256k1::new(), &sk1);
        let hs = NodeMessage::Handshake(Handshake {
            network_id: "coin".into(),
            version: 1,
            public_key: pk1.serialize().to_vec(),
            signature: sign_handshake(&sk1, "coin", 1),
        });
        write_msg(&mut s1, &hs).await.unwrap();
        let _ = read_msg(&mut s1).await.unwrap();
        loop {
            if node.peers().await.len() == 1 {
                break;
            }
            sleep(Duration::from_millis(10)).await;
        }

        let mut s2 = TcpStream::connect(addr).await.unwrap();
        let sk2 = secp256k1::SecretKey::new(&mut rng);
        let pk2 = secp256k1::PublicKey::from_secret_key(&Secp256k1::new(), &sk2);
        let hs2 = NodeMessage::Handshake(Handshake {
            network_id: "coin".into(),
            version: 1,
            public_key: pk2.serialize().to_vec(),
            signature: sign_handshake(&sk2, "coin", 1),
        });
        write_msg(&mut s2, &hs2).await.unwrap();
        let _ = timeout(Duration::from_millis(100), read_msg(&mut s2)).await;
        assert!(node.peers().await.len() <= 2);
    }

    #[tokio::test]
    async fn get_block_returns_block() {
        let node = Node::new(
            vec!["0.0.0.0:0".parse().unwrap()],
            NodeType::Wallet,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
        );
        let (addrs, _) = node.start().await.unwrap();
        let addr = addrs[0];
        let (block, hash) = {
            let mut chain = node.chain.lock().await;
            let reward = chain.block_subsidy();
            let block = Block {
                header: BlockHeader {
                    previous_hash: String::new(),
                    merkle_root: String::new(),
                    timestamp: 0,
                    nonce: 0,
                    difficulty: 0,
                },
                transactions: vec![coinbase_transaction(A1, reward)],
            };
            let hash = block.hash();
            chain.add_block(block.clone());
            (block, hash)
        };

        let mut stream = TcpStream::connect(addr).await.unwrap();
        let mut rng = OsRng;
        let sk = secp256k1::SecretKey::new(&mut rng);
        let pk = secp256k1::PublicKey::from_secret_key(&Secp256k1::new(), &sk);
        let hs = NodeMessage::Handshake(Handshake {
            network_id: "coin".into(),
            version: 1,
            public_key: pk.serialize().to_vec(),
            signature: sign_handshake(&sk, "coin", 1),
        });
        write_msg(&mut stream, &hs).await.unwrap();
        let _ = read_msg(&mut stream).await.unwrap();

        let get = NodeMessage::GetBlock(GetBlock { hash });
        write_msg(&mut stream, &get).await.unwrap();
        match read_msg(&mut stream).await.unwrap() {
            NodeMessage::Block(b) => {
                let got = Block::from_rpc(b).unwrap();
                assert_eq!(got, block);
            }
            other => panic!("expected Block, got {:?}", other),
        }
    }

    #[tokio::test]
    async fn get_block_unknown_yields_no_response() {
        let node = Node::new(
            vec!["0.0.0.0:0".parse().unwrap()],
            NodeType::Wallet,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
        );
        let (addrs, _) = node.start().await.unwrap();
        let addr = addrs[0];
        {
            let mut chain = node.chain.lock().await;
            let reward = chain.block_subsidy();
            chain.add_block(Block {
                header: BlockHeader {
                    previous_hash: String::new(),
                    merkle_root: String::new(),
                    timestamp: 0,
                    nonce: 0,
                    difficulty: 0,
                },
                transactions: vec![coinbase_transaction(A1, reward)],
            });
        }

        let mut stream = TcpStream::connect(addr).await.unwrap();
        let mut rng = OsRng;
        let sk = secp256k1::SecretKey::new(&mut rng);
        let pk = secp256k1::PublicKey::from_secret_key(&Secp256k1::new(), &sk);
        let hs = NodeMessage::Handshake(Handshake {
            network_id: "coin".into(),
            version: 1,
            public_key: pk.serialize().to_vec(),
            signature: sign_handshake(&sk, "coin", 1),
        });
        write_msg(&mut stream, &hs).await.unwrap();
        let _ = read_msg(&mut stream).await.unwrap();

        let get = NodeMessage::GetBlock(GetBlock {
            hash: "deadbeef".into(),
        });
        write_msg(&mut stream, &get).await.unwrap();
        let res = timeout(Duration::from_millis(100), read_msg(&mut stream)).await;
        assert!(res.is_err() || res.unwrap().is_err());
    }

    #[tokio::test]
    async fn reject_oversized_message() {
        let node = Node::new(
            vec!["0.0.0.0:0".parse().unwrap()],
            NodeType::Wallet,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
        );
        let (addrs, _) = node.start().await.unwrap();
        let addr = addrs[0];

        let mut stream = TcpStream::connect(addr).await.unwrap();
        let mut rng = OsRng;
        let sk = secp256k1::SecretKey::new(&mut rng);
        let pk = secp256k1::PublicKey::from_secret_key(&Secp256k1::new(), &sk);
        let hs = NodeMessage::Handshake(Handshake {
            network_id: "coin".into(),
            version: 1,
            public_key: pk.serialize().to_vec(),
            signature: sign_handshake(&sk, "coin", 1),
        });
        write_msg(&mut stream, &hs).await.unwrap();
        let _ = read_msg(&mut stream).await.unwrap();

        let len = ((MAX_MSG_BYTES as u32) + 1).to_be_bytes();
        stream.write_all(&len).await.unwrap();
        let res = timeout(Duration::from_millis(100), read_msg(&mut stream)).await;
        assert!(res.is_err() || res.unwrap().is_err());
    }

    #[tokio::test]
    async fn invalid_proxy_yields_error() {
        let _ = std::fs::remove_file("mempool.bin");
        let node_a = Node::with_interval(
            vec!["0.0.0.0:0".parse().unwrap()],
            Duration::from_millis(10),
            NodeType::Wallet,
            None,
            None,
            None,
            Some("127.0.0.1:1".parse().unwrap()),
            None,
            None,
            None,
            None,
            None,
        );
        let node_b = Node::with_interval(
            vec!["0.0.0.0:0".parse().unwrap()],
            Duration::from_millis(10),
            NodeType::Wallet,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
        );
        let (addrs_b, _) = node_b.start().await.unwrap();
        let addr_b = addrs_b[0];
        assert!(node_a.connect(addr_b).await.is_err());
    }

    #[tokio::test]
    async fn connect_without_proxy() {
        let _ = std::fs::remove_file("mempool.bin");
        let node_a = Node::with_interval(
            vec!["0.0.0.0:0".parse().unwrap()],
            Duration::from_millis(10),
            NodeType::Wallet,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
        );
        let node_b = Node::with_interval(
            vec!["0.0.0.0:0".parse().unwrap()],
            Duration::from_millis(10),
            NodeType::Wallet,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
        );
        let (addrs_b, _) = node_b.start().await.unwrap();
        let addr_b = addrs_b[0];
        assert!(node_a.connect(addr_b).await.is_ok());
    }
}
