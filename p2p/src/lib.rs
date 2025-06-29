use clap::ValueEnum;
use coin::meets_difficulty;
use coin::{Block, BlockHeader, Blockchain, TransactionExt};
use coin_proto::proto::{
    Chain, GetChain, GetPeers, Handshake, NodeMessage, Peers, Ping, Pong, Transaction,
};
use hex;
use miner::mine_block;
use prost::Message;
use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet};
use std::net::{SocketAddr, ToSocketAddrs};
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{Mutex, mpsc};
use tokio::time::{Duration, Instant, timeout};

pub mod config;

const DEFAULT_MAX_MSGS_PER_SEC: u32 = 10;
const DEFAULT_MAX_PEERS: usize = 32;
const MAX_MSG_BYTES: usize = 1024 * 1024; // 1 MiB

/// Send a length-prefixed protobuf message over the socket
async fn write_msg(socket: &mut TcpStream, msg: &NodeMessage) -> tokio::io::Result<()> {
    let mut buf = Vec::new();
    msg.encode(&mut buf)
        .map_err(|e| tokio::io::Error::new(tokio::io::ErrorKind::InvalidData, e))?;
    let len = (buf.len() as u32).to_be_bytes();
    socket.write_all(&len).await?;
    socket.write_all(&buf).await?;
    Ok(())
}

/// Read a length-prefixed protobuf message from the socket
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
    Ok(NodeMessage::decode(&buf[..])
        .map_err(|e| tokio::io::Error::new(tokio::io::ErrorKind::InvalidData, e))?)
}

async fn read_with_timeout(socket: &mut TcpStream) -> tokio::io::Result<bool> {
    match timeout(Duration::from_secs(3), read_msg(socket)).await {
        Ok(Ok(_)) => Ok(true),
        Ok(Err(e)) => Err(e),
        Err(_) => Ok(false),
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
    let mut hasher = Sha256::new();
    for tx in &block.transactions {
        if (!tx.sender.is_empty() && !coin::valid_address(&tx.sender))
            || !coin::valid_address(&tx.recipient)
        {
            return false;
        }
        if !tx.verify() {
            return false;
        }
        hasher.update(tx.hash());
    }
    let merkle = hex::encode(hasher.finalize());
    if merkle != block.header.merkle_root {
        return false;
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
) {
    let list: Vec<SocketAddr> = peers.lock().await.iter().copied().collect();
    let msg = NodeMessage {
        msg: Some(coin_proto::proto::node_message::Msg::Block(
            coin_proto::proto::Block {
                header: Some(coin_proto::proto::BlockHeader {
                    previous_hash: block.header.previous_hash.clone(),
                    merkle_root: block.header.merkle_root.clone(),
                    timestamp: block.header.timestamp,
                    nonce: block.header.nonce,
                    difficulty: block.header.difficulty,
                }),
                transactions: block.transactions.clone(),
            },
        )),
    };
    for addr in list {
        match TcpStream::connect(addr).await {
            Ok(mut stream) => {
                let hs = NodeMessage {
                    msg: Some(coin_proto::proto::node_message::Msg::Handshake(Handshake {
                        network_id: network_id.to_string(),
                        version,
                    })),
                };
                if write_msg(&mut stream, &hs).await.is_err() {
                    peers.lock().await.remove(&addr);
                    continue;
                }
                if let Ok(resp) = read_msg(&mut stream).await {
                    match resp.msg {
                        Some(coin_proto::proto::node_message::Msg::Handshake(h))
                            if h.network_id == network_id && h.version == version => {}
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
    peers_file: Option<String>,
    network_id: String,
    protocol_version: u32,
    max_msgs_per_sec: u32,
    max_peers: usize,
    running: Arc<AtomicBool>,
}

impl Node {
    pub fn new(
        listeners: Vec<SocketAddr>,
        node_type: NodeType,
        min_peers: Option<usize>,
        wallet_address: Option<String>,
        peers_file: Option<String>,
        network_id: Option<String>,
        protocol_version: Option<u32>,
        max_msgs_per_sec: Option<u32>,
        max_peers: Option<usize>,
    ) -> Self {
        Self {
            listeners,
            peers: Arc::new(Mutex::new(HashSet::new())),
            msg_times: Arc::new(Mutex::new(HashMap::new())),
            ping_interval: Duration::from_secs(5),
            node_type,
            chain: Arc::new(Mutex::new(Blockchain::new())),
            min_peers: min_peers.unwrap_or(1),
            wallet_address,
            peers_file,
            network_id: network_id.unwrap_or_else(|| "coin".to_string()),
            protocol_version: protocol_version.unwrap_or(1),
            max_msgs_per_sec: max_msgs_per_sec.unwrap_or(DEFAULT_MAX_MSGS_PER_SEC),
            max_peers: max_peers.unwrap_or(DEFAULT_MAX_PEERS),
            running: Arc::new(AtomicBool::new(true)),
        }
    }

    pub fn chain_handle(&self) -> Arc<Mutex<Blockchain>> {
        self.chain.clone()
    }

    #[allow(dead_code)]
    pub fn with_interval(
        listeners: Vec<SocketAddr>,
        interval: Duration,
        node_type: NodeType,
        min_peers: Option<usize>,
        wallet_address: Option<String>,
        peers_file: Option<String>,
        network_id: Option<String>,
        protocol_version: Option<u32>,
        max_msgs_per_sec: Option<u32>,
        max_peers: Option<usize>,
    ) -> Self {
        Self {
            listeners,
            peers: Arc::new(Mutex::new(HashSet::new())),
            msg_times: Arc::new(Mutex::new(HashMap::new())),
            ping_interval: interval,
            node_type,
            chain: Arc::new(Mutex::new(Blockchain::new())),
            min_peers: min_peers.unwrap_or(1),
            wallet_address,
            peers_file,
            network_id: network_id.unwrap_or_else(|| "coin".to_string()),
            protocol_version: protocol_version.unwrap_or(1),
            max_msgs_per_sec: max_msgs_per_sec.unwrap_or(DEFAULT_MAX_MSGS_PER_SEC),
            max_peers: max_peers.unwrap_or(DEFAULT_MAX_PEERS),
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

    pub async fn status(&self) -> (usize, usize, usize) {
        let peers = self.peers.lock().await.len();
        let chain = self.chain.lock().await;
        let chain_len = chain.len();
        let mem_len = chain.mempool_len();
        (peers, chain_len, mem_len)
    }

    async fn load_peers(&self) {
        if let Some(path) = &self.peers_file {
            if let Ok(data) = tokio::fs::read_to_string(path).await {
                for line in data.lines() {
                    if let Ok(mut addrs) = line.to_socket_addrs() {
                        if let Some(addr) = addrs.next() {
                            self.peers.lock().await.insert(addr);
                        }
                    }
                }
            }
        }
    }

    pub async fn save_peers(&self) -> tokio::io::Result<()> {
        if let Some(path) = &self.peers_file {
            let list: Vec<String> = self
                .peers
                .lock()
                .await
                .iter()
                .map(|a| a.to_string())
                .collect();
            tokio::fs::write(path, list.join("\n")).await?;
        }
        Ok(())
    }

    /// Start IPv4 and IPv6 listeners and return local addresses and receiver for incoming transactions
    pub async fn start(&self) -> tokio::io::Result<(Vec<SocketAddr>, mpsc::Receiver<Transaction>)> {
        self.running.store(true, Ordering::SeqCst);
        self.load_peers().await;

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
                            if let Some(coin_proto::proto::node_message::Msg::Handshake(h)) =
                                msg.msg
                            {
                                if h.network_id != nid || h.version != ver {
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
                            let resp = NodeMessage {
                                msg: Some(coin_proto::proto::node_message::Msg::Handshake(
                                    Handshake {
                                        network_id: nid.clone(),
                                        version: ver,
                                    },
                                )),
                            };
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
                                        if let Some(m) = msg.msg {
                                            match m {
                                                coin_proto::proto::node_message::Msg::Transaction(t) => {
                                                    let mut chain = chain.lock().await;
                                                    if chain.add_transaction(t.clone()) {
                                                        let _ = tx.send(t.clone()).await;
                                                    }
                                                }
                                                coin_proto::proto::node_message::Msg::Ping(_) => {
                                                    let resp = NodeMessage {
                                                        msg: Some(
                                                            coin_proto::proto::node_message::Msg::Pong(Pong {}),
                                                        ),
                                                    };
                                                    let _ = write_msg(&mut socket, &resp).await;
                                                }
                                                coin_proto::proto::node_message::Msg::Pong(_) => {}
                                                coin_proto::proto::node_message::Msg::GetPeers(_) => {
                                                    let list: Vec<String> = peers
                                                        .lock()
                                                        .await
                                                        .iter()
                                                        .map(|a| a.to_string())
                                                        .collect();
                                                    let msg = NodeMessage {
                                                        msg: Some(
                                                            coin_proto::proto::node_message::Msg::Peers(Peers { addrs: list }),
                                                        ),
                                                    };
                                                    let _ = write_msg(&mut socket, &msg).await;
                                                }
                                                coin_proto::proto::node_message::Msg::Peers(p) => {
                                                    for s in p.addrs {
                                                        if let Ok(mut addrs) = s.to_socket_addrs() {
                                                            if let Some(addr) = addrs.next() {
                                                                peers.lock().await.insert(addr);
                                                            }
                                                        }
                                                    }
                                                }
                                                coin_proto::proto::node_message::Msg::GetChain(_) => {
                                                    let blocks = chain.lock().await.all();
                                                    let proto_blocks: Vec<coin_proto::proto::Block> = blocks
                                                        .into_iter()
                                                        .map(|b| coin_proto::proto::Block {
                                                            header: Some(coin_proto::proto::BlockHeader {
                                                                previous_hash: b.header.previous_hash,
                                                                merkle_root: b.header.merkle_root,
                                                                timestamp: b.header.timestamp,
                                                                nonce: b.header.nonce,
                                                                difficulty: b.header.difficulty,
                                                            }),
                                                            transactions: b.transactions,
                                                        })
                                                        .collect();
                                                    let msg = NodeMessage {
                                                        msg: Some(coin_proto::proto::node_message::Msg::Chain(Chain {
                                                            blocks: proto_blocks,
                                                        })),
                                                    };
                                                    let _ = write_msg(&mut socket, &msg).await;
                                                }
                                                coin_proto::proto::node_message::Msg::Chain(c) => {
                                                    let blocks: Vec<Block> = c
                                                        .blocks
                                                        .into_iter()
                                                        .filter_map(|pb| {
                                                            pb.header.map(|h| Block {
                                                                header: BlockHeader {
                                                                    previous_hash: h.previous_hash,
                                                                    merkle_root: h.merkle_root,
                                                                    timestamp: h.timestamp,
                                                                    nonce: h.nonce,
                                                                    difficulty: h.difficulty,
                                                                },
                                                                transactions: pb.transactions,
                                                            })
                                                        })
                                                        .collect();
                                                    chain.lock().await.replace(blocks);
                                                }
                                                coin_proto::proto::node_message::Msg::Block(b) => {
                                                    if let Some(h) = b.header {
                                                        let block = Block {
                                                            header: BlockHeader {
                                                                previous_hash: h.previous_hash,
                                                                merkle_root: h.merkle_root,
                                                                timestamp: h.timestamp,
                                                                nonce: h.nonce,
                                                                difficulty: h.difficulty,
                                                            },
                                                            transactions: b.transactions,
                                                        };
                                                        let mut chain = chain.lock().await;
                                                        if valid_block(&chain, &block) {
                                                            chain.add_block(block);
                                                        }
                                                    }
                                                }
                                                coin_proto::proto::node_message::Msg::Handshake(_) => {}
                                            }
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

        // periodic ping loop
        let peers = self.peers.clone();
        let interval = self.ping_interval;
        let nid = self.network_id.clone();
        let ver = self.protocol_version;
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
                    tokio::spawn(async move {
                        if !running.load(Ordering::SeqCst) {
                            return;
                        }
                        if let Ok(mut stream) = TcpStream::connect(addr).await {
                            let hs = NodeMessage {
                                msg: Some(coin_proto::proto::node_message::Msg::Handshake(
                                    Handshake {
                                        network_id: nid.clone(),
                                        version: ver,
                                    },
                                )),
                            };
                            if write_msg(&mut stream, &hs).await.is_ok() {
                                if let Ok(resp) = read_msg(&mut stream).await {
                                    if matches!(
                                        resp.msg,
                                        Some(coin_proto::proto::node_message::Msg::Handshake(_))
                                    ) {
                                        let ping = NodeMessage {
                                            msg: Some(coin_proto::proto::node_message::Msg::Ping(
                                                Ping {},
                                            )),
                                        };
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

        if self.node_type == NodeType::Miner {
            let peers = self.peers.clone();
            let chain = self.chain.clone();
            let min = self.min_peers;
            let reward = self
                .wallet_address
                .clone()
                .unwrap_or_else(|| "miner".to_string());
            let nid = self.network_id.clone();
            let ver = self.protocol_version;
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
                            let block = mine_block(&mut chain, &reward);
                            broadcast_block_internal(peers.clone(), &block, &nid, ver).await;
                        }
                    }
                    tokio::time::sleep(Duration::from_millis(50)).await;
                }
            });
        }

        Ok((local_addrs, rx))
    }

    /// Connect to another peer and request their addresses
    pub async fn connect<A: tokio::net::ToSocketAddrs>(&self, addr: A) -> tokio::io::Result<()> {
        let mut stream = TcpStream::connect(addr).await?;
        let hs = NodeMessage {
            msg: Some(coin_proto::proto::node_message::Msg::Handshake(Handshake {
                network_id: self.network_id.clone(),
                version: self.protocol_version,
            })),
        };
        write_msg(&mut stream, &hs).await?;
        let resp = read_msg(&mut stream).await?;
        match resp.msg {
            Some(coin_proto::proto::node_message::Msg::Handshake(h))
                if h.network_id == self.network_id && h.version == self.protocol_version => {}
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
        let get = NodeMessage {
            msg: Some(coin_proto::proto::node_message::Msg::GetPeers(GetPeers {})),
        };
        write_msg(&mut stream, &get).await?;
        Ok(())
    }

    /// Request blockchain data from a peer and replace local chain if theirs is longer
    pub async fn sync_from_peer<A: tokio::net::ToSocketAddrs>(
        &self,
        addr: A,
    ) -> tokio::io::Result<()> {
        let mut stream = TcpStream::connect(addr).await?;
        let hs = NodeMessage {
            msg: Some(coin_proto::proto::node_message::Msg::Handshake(Handshake {
                network_id: self.network_id.clone(),
                version: self.protocol_version,
            })),
        };
        write_msg(&mut stream, &hs).await?;
        let resp = read_msg(&mut stream).await?;
        match resp.msg {
            Some(coin_proto::proto::node_message::Msg::Handshake(h))
                if h.network_id == self.network_id && h.version == self.protocol_version => {}
            _ => {
                return Err(tokio::io::Error::new(
                    tokio::io::ErrorKind::InvalidData,
                    "handshake mismatch",
                ));
            }
        }
        let get = NodeMessage {
            msg: Some(coin_proto::proto::node_message::Msg::GetChain(GetChain {})),
        };
        write_msg(&mut stream, &get).await?;
        if let Ok(resp) = read_msg(&mut stream).await {
            if let Some(coin_proto::proto::node_message::Msg::Chain(c)) = resp.msg {
                let blocks: Vec<Block> = c
                    .blocks
                    .into_iter()
                    .filter_map(|pb| {
                        pb.header.map(|h| Block {
                            header: BlockHeader {
                                previous_hash: h.previous_hash,
                                merkle_root: h.merkle_root,
                                timestamp: h.timestamp,
                                nonce: h.nonce,
                                difficulty: h.difficulty,
                            },
                            transactions: pb.transactions,
                        })
                    })
                    .collect();
                self.chain.lock().await.replace(blocks);
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
    let mut stream = TcpStream::connect(addr).await?;
    let hs = NodeMessage {
        msg: Some(coin_proto::proto::node_message::Msg::Handshake(Handshake {
            network_id: "coin".into(),
            version: 1,
        })),
    };
    write_msg(&mut stream, &hs).await?;
    let resp = read_msg(&mut stream).await?;
    match resp.msg {
        Some(coin_proto::proto::node_message::Msg::Handshake(h))
            if h.network_id == "coin" && h.version == 1 => {}
        _ => {
            return Err(tokio::io::Error::new(
                tokio::io::ErrorKind::InvalidData,
                "handshake mismatch",
            ));
        }
    }
    let msg = NodeMessage {
        msg: Some(coin_proto::proto::node_message::Msg::Transaction(
            tx_msg.clone(),
        )),
    };
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
        );
        let (addrs, _rx) = node.start().await.unwrap();
        let addr = addrs[0];
        let mut stream = TcpStream::connect(addr).await.unwrap();
        let hs = NodeMessage {
            msg: Some(coin_proto::proto::node_message::Msg::Handshake(Handshake {
                network_id: "coin".into(),
                version: 1,
            })),
        };
        write_msg(&mut stream, &hs).await.unwrap();
        let _ = read_msg(&mut stream).await.unwrap();
        let peers_msg = NodeMessage {
            msg: Some(coin_proto::proto::node_message::Msg::Peers(Peers {
                addrs: vec!["127.0.0.1:12345".into()],
            })),
        };
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
            };
            sign_for("m/0'/0/0", &mut tx);
            chain.add_transaction(tx);
            let block = chain.candidate_block();
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
        );
        let (addrs, _rx) = node.start().await.unwrap();
        let addr = addrs[0];
        let mut stream = TcpStream::connect(addr).await.unwrap();
        let hs = NodeMessage {
            msg: Some(coin_proto::proto::node_message::Msg::Handshake(Handshake {
                network_id: "coin".into(),
                version: 1,
            })),
        };
        write_msg(&mut stream, &hs).await.unwrap();
        let _ = read_msg(&mut stream).await.unwrap();
        let mut tx = Transaction {
            sender: A1.into(),
            recipient: A2.into(),
            amount: 3,
            fee: 0,
            signature: Vec::new(),
            encrypted_message: Vec::new(),
        };
        sign_for("m/0'/0/0", &mut tx);
        let block = coin_proto::proto::Block {
            header: Some(coin_proto::proto::BlockHeader {
                previous_hash: String::new(),
                merkle_root: "m".into(),
                timestamp: 0,
                nonce: 0,
                difficulty: 0,
            }),
            transactions: vec![tx],
        };
        let chain_msg = NodeMessage {
            msg: Some(coin_proto::proto::node_message::Msg::Chain(Chain {
                blocks: vec![block],
            })),
        };
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
        );
        let (addrs, _rx) = node.start().await.unwrap();
        let addr = addrs[0];
        let mut stream = TcpStream::connect(addr).await.unwrap();
        let hs = NodeMessage {
            msg: Some(coin_proto::proto::node_message::Msg::Handshake(Handshake {
                network_id: "coin".into(),
                version: 1,
            })),
        };
        write_msg(&mut stream, &hs).await.unwrap();
        let _ = read_msg(&mut stream).await.unwrap();
        let mut tx = Transaction {
            sender: A1.into(),
            recipient: A2.into(),
            amount: 1,
            fee: 0,
            signature: Vec::new(),
            encrypted_message: Vec::new(),
        };
        sign_for("m/0'/0/0", &mut tx);
        let mut h = Sha256::new();
        h.update(tx.hash());
        let merkle = hex::encode(h.finalize());
        let block_msg = NodeMessage {
            msg: Some(coin_proto::proto::node_message::Msg::Block(
                coin_proto::proto::Block {
                    header: Some(coin_proto::proto::BlockHeader {
                        previous_hash: String::new(),
                        merkle_root: merkle,
                        timestamp: 0,
                        nonce: 0,
                        difficulty: 0,
                    }),
                    transactions: vec![tx],
                },
            )),
        };
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
        };
        sign_for("m/0'/0/0", &mut tx);
        let mut h = Sha256::new();
        h.update(tx.hash());
        let merkle = hex::encode(h.finalize());
        let block = Block {
            header: BlockHeader {
                previous_hash: String::new(),
                merkle_root: merkle,
                timestamp: 0,
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
        };
        sign_for("m/0'/0/1", &mut tx);
        let mut h = Sha256::new();
        h.update(tx.hash());
        let merkle = hex::encode(h.finalize());
        let block = Block {
            header: BlockHeader {
                previous_hash: genesis.hash(),
                merkle_root: merkle.clone(),
                timestamp: 1,
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
            Some("net1".into()),
            Some(1),
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
            Some("net2".into()),
            Some(1),
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
            Some("net1".into()),
            Some(2),
            None,
            None,
        );
        assert!(node_c.connect(addr).await.is_err());
        assert!(node_c.peers().await.is_empty());
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
            Some(5),
            None,
        );
        let (addrs, _) = node.start().await.unwrap();
        let addr = addrs[0];
        let mut stream = TcpStream::connect(addr).await.unwrap();
        let hs = NodeMessage {
            msg: Some(coin_proto::proto::node_message::Msg::Handshake(Handshake {
                network_id: "coin".into(),
                version: 1,
            })),
        };
        write_msg(&mut stream, &hs).await.unwrap();
        let _ = read_msg(&mut stream).await.unwrap();
        for _ in 0..6 {
            let ping = NodeMessage {
                msg: Some(coin_proto::proto::node_message::Msg::Ping(Ping {})),
            };
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
        );
        let (addrs, _) = node.start().await.unwrap();
        let addr = addrs[0];

        let mut s1 = TcpStream::connect(addr).await.unwrap();
        let hs = NodeMessage {
            msg: Some(coin_proto::proto::node_message::Msg::Handshake(Handshake {
                network_id: "coin".into(),
                version: 1,
            })),
        };
        write_msg(&mut s1, &hs).await.unwrap();
        let _ = read_msg(&mut s1).await.unwrap();

        let mut s2 = TcpStream::connect(addr).await.unwrap();
        write_msg(&mut s2, &hs).await.unwrap();
        let res = timeout(Duration::from_millis(100), read_msg(&mut s2)).await;
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
        );
        let (addrs, _) = node.start().await.unwrap();
        let addr = addrs[0];

        let mut stream = TcpStream::connect(addr).await.unwrap();
        let hs = NodeMessage {
            msg: Some(coin_proto::proto::node_message::Msg::Handshake(Handshake {
                network_id: "coin".into(),
                version: 1,
            })),
        };
        write_msg(&mut stream, &hs).await.unwrap();
        let _ = read_msg(&mut stream).await.unwrap();

        let len = ((MAX_MSG_BYTES as u32) + 1).to_be_bytes();
        stream.write_all(&len).await.unwrap();
        let res = timeout(Duration::from_millis(100), read_msg(&mut stream)).await;
        assert!(res.is_err() || res.unwrap().is_err());
    }
}
