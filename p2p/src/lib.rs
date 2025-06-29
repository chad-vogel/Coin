use clap::ValueEnum;
use coin::{Block, BlockHeader, Blockchain, TransactionExt};
use coin_proto::proto::{Chain, GetChain, GetPeers, NodeMessage, Peers, Ping, Pong, Transaction};
use hex;
use miner::mine_block;
use prost::Message;
use sha2::{Digest, Sha256};
use std::collections::HashSet;
use std::net::{SocketAddr, ToSocketAddrs};
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{Mutex, mpsc};
use tokio::time::{Duration, timeout};

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

#[derive(Clone, Copy, Debug, PartialEq, Eq, ValueEnum)]
pub enum NodeType {
    Wallet,
    Miner,
    Verifier,
}

fn meets_difficulty(hash: &[u8], difficulty: u32) -> bool {
    for i in 0..difficulty {
        if hash.get(i as usize).copied().unwrap_or(0) != 0 {
            return false;
        }
    }
    true
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

async fn broadcast_block_internal(peers: Arc<Mutex<HashSet<SocketAddr>>>, block: &Block) {
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
pub struct Node {
    port: u16,
    peers: Arc<Mutex<HashSet<SocketAddr>>>,
    ping_interval: Duration,
    node_type: NodeType,
    chain: Arc<Mutex<Blockchain>>,
    min_peers: usize,
}

impl Node {
    pub fn new(port: u16, node_type: NodeType, min_peers: Option<usize>) -> Self {
        Self {
            port,
            peers: Arc::new(Mutex::new(HashSet::new())),
            ping_interval: Duration::from_secs(5),
            node_type,
            chain: Arc::new(Mutex::new(Blockchain::new())),
            min_peers: min_peers.unwrap_or(1),
        }
    }

    pub fn chain_handle(&self) -> Arc<Mutex<Blockchain>> {
        self.chain.clone()
    }

    #[allow(dead_code)]
    pub fn with_interval(
        port: u16,
        interval: Duration,
        node_type: NodeType,
        min_peers: Option<usize>,
    ) -> Self {
        Self {
            port,
            peers: Arc::new(Mutex::new(HashSet::new())),
            ping_interval: interval,
            node_type,
            chain: Arc::new(Mutex::new(Blockchain::new())),
            min_peers: min_peers.unwrap_or(1),
        }
    }

    pub fn node_type(&self) -> NodeType {
        self.node_type
    }

    /// Start IPv4 and IPv6 listeners and return local addresses and receiver for incoming transactions
    pub async fn start(&self) -> tokio::io::Result<(Vec<SocketAddr>, mpsc::Receiver<Transaction>)> {
        let addr_v4 = format!("0.0.0.0:{}", self.port);
        let addr_v6 = format!("[::]:{}", self.port);
        let listener_v4 = TcpListener::bind(&addr_v4).await?;
        let listener_v6 = TcpListener::bind(&addr_v6).await?;
        let local_addrs = vec![listener_v4.local_addr()?, listener_v6.local_addr()?];
        let (tx, rx) = mpsc::channel(8);
        let peers = self.peers.clone();
        let chain = self.chain.clone();

        // accept loop for each listener
        for listener in [listener_v4, listener_v6] {
            let tx = tx.clone();
            let peers = peers.clone();
            let chain = chain.clone();
            tokio::spawn(async move {
                loop {
                    if let Ok((mut socket, _addr)) = listener.accept().await {
                        let tx = tx.clone();
                        let peers = peers.clone();
                        let chain = chain.clone();
                        tokio::spawn(async move {
                            loop {
                                match read_msg(&mut socket).await {
                                    Ok(msg) => {
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
                                            }
                                        }
                                    }
                                    Err(_) => break,
                                }
                            }
                        });
                    }
                }
            });
        }

        // periodic ping loop
        let peers = self.peers.clone();
        let interval = self.ping_interval;
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(interval).await;
                let list: Vec<SocketAddr> = peers.lock().await.iter().copied().collect();
                for addr in list {
                    let peers = peers.clone();
                    tokio::spawn(async move {
                        if let Ok(mut stream) = TcpStream::connect(addr).await {
                            let ping = NodeMessage {
                                msg: Some(coin_proto::proto::node_message::Msg::Ping(Ping {})),
                            };
                            if write_msg(&mut stream, &ping).await.is_ok() {
                                match read_with_timeout(&mut stream).await {
                                    Ok(true) => return,
                                    Ok(false) => (),
                                    Err(_) => (),
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
            tokio::spawn(async move {
                loop {
                    while peers.lock().await.len() < min {
                        tokio::time::sleep(Duration::from_millis(50)).await;
                    }
                    {
                        let mut chain = chain.lock().await;
                        if chain.mempool_len() > 0 {
                            let block = mine_block(&mut chain, "miner");
                            broadcast_block_internal(peers.clone(), &block).await;
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
        if let Ok(peer_addr) = stream.peer_addr() {
            self.peers.lock().await.insert(peer_addr);
        }
        let get = NodeMessage {
            msg: Some(coin_proto::proto::node_message::Msg::GetPeers(GetPeers {})),
        };
        write_msg(&mut stream, &get).await?;
        // we don't wait for response here
        Ok(())
    }

    /// Request blockchain data from a peer and replace local chain if theirs is longer
    pub async fn sync_from_peer<A: tokio::net::ToSocketAddrs>(
        &self,
        addr: A,
    ) -> tokio::io::Result<()> {
        let mut stream = TcpStream::connect(addr).await?;
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
        broadcast_block_internal(self.peers.clone(), block).await;
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
        let node = Node::with_interval(0, Duration::from_millis(50), NodeType::Wallet, None);
        assert_eq!(node.node_type(), NodeType::Wallet);
        let (addrs, mut rx) = node.start().await.unwrap();
        let addr = addrs[0];
        {
            let mut chain = node.chain.lock().await;
            chain.add_block(Block {
                header: BlockHeader {
                    previous_hash: String::new(),
                    merkle_root: String::new(),
                    timestamp: 0,
                    nonce: 0,
                    difficulty: 0,
                },
                transactions: vec![coinbase_transaction(A1.clone())],
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
        let node = Node::new(0, NodeType::Wallet, None);
        let (addrs, _rx) = node.start().await.unwrap();
        let addr = addrs[0];
        let mut stream = TcpStream::connect(addr).await.unwrap();
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
        let node = Node::with_interval(0, Duration::from_millis(50), NodeType::Wallet, None);
        let (_addrs, _rx) = node.start().await.unwrap();
        let unreachable: SocketAddr = "127.0.0.1:9".parse().unwrap();
        node.peers.lock().await.insert(unreachable);
        sleep(Duration::from_millis(200)).await;
        assert!(!node.peers().await.contains(&unreachable));
    }

    #[tokio::test]
    async fn sync_from_peer_updates_chain() {
        let node_a = Node::with_interval(0, Duration::from_millis(50), NodeType::Verifier, None);
        let (addrs_a, _) = node_a.start().await.unwrap();
        let addr_a = addrs_a[0];
        {
            let mut chain = node_a.chain.lock().await;
            let mut tx = Transaction {
                sender: A1.into(),
                recipient: A2.into(),
                amount: 2,
                signature: Vec::new(),
                encrypted_message: Vec::new(),
            };
            sign_for("m/0'/0/0", &mut tx);
            chain.add_transaction(tx);
            let block = chain.candidate_block();
            chain.add_block(block);
        }

        let node_b = Node::with_interval(0, Duration::from_millis(50), NodeType::Verifier, None);
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
        let node = Node::new(0, NodeType::Wallet, None);
        let (addrs, _rx) = node.start().await.unwrap();
        let addr = addrs[0];
        let mut stream = TcpStream::connect(addr).await.unwrap();
        let mut tx = Transaction {
            sender: A1.into(),
            recipient: A2.into(),
            amount: 3,
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
        let node = Node::new(0, NodeType::Verifier, None);
        let (addrs, _rx) = node.start().await.unwrap();
        let addr = addrs[0];
        let mut tx = Transaction {
            sender: A1.into(),
            recipient: A2.into(),
            amount: 1,
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
        let mut stream = TcpStream::connect(addr).await.unwrap();
        write_msg(&mut stream, &block_msg).await.unwrap();
        sleep(Duration::from_millis(50)).await;
        assert_eq!(node.chain_len().await, 1);
    }

    #[tokio::test]
    async fn broadcast_block_propagates() {
        let node_a = Node::with_interval(0, Duration::from_millis(50), NodeType::Verifier, None);
        let (addrs_a, _) = node_a.start().await.unwrap();
        let addr_a = addrs_a[0];

        let node_b = Node::with_interval(0, Duration::from_millis(50), NodeType::Verifier, None);
        let (addrs_b, _) = node_b.start().await.unwrap();
        let addr_b = addrs_b[0];

        node_a.peers.lock().await.insert(addr_b);

        let mut tx = Transaction {
            sender: A1.into(),
            recipient: A2.into(),
            amount: 2,
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
    async fn miner_mines_pending_tx() {
        let node = Node::with_interval(0, Duration::from_millis(50), NodeType::Miner, Some(0));
        let (_addrs, _rx) = node.start().await.unwrap();
        {
            let mut chain = node.chain.lock().await;
            chain.add_block(Block {
                header: BlockHeader {
                    previous_hash: String::new(),
                    merkle_root: String::new(),
                    timestamp: 0,
                    nonce: 0,
                    difficulty: 0,
                },
                transactions: vec![coinbase_transaction(A1)],
            });
            let mut tx = Transaction {
                sender: A1.into(),
                recipient: A2.into(),
                amount: 1,
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
        let miner = Node::with_interval(0, Duration::from_millis(50), NodeType::Miner, Some(1));
        let (_m_addrs, _rx) = miner.start().await.unwrap();
        {
            let mut chain = miner.chain.lock().await;
            chain.add_block(Block {
                header: BlockHeader {
                    previous_hash: String::new(),
                    merkle_root: String::new(),
                    timestamp: 0,
                    nonce: 0,
                    difficulty: 0,
                },
                transactions: vec![coinbase_transaction(A1)],
            });
            let mut tx = Transaction {
                sender: A1.into(),
                recipient: A2.into(),
                amount: 1,
                signature: Vec::new(),
                encrypted_message: Vec::new(),
            };
            sign_for("m/0'/0/0", &mut tx);
            chain.add_transaction(tx);
        }
        sleep(Duration::from_millis(200)).await;
        // mining should wait for peers
        assert_eq!(miner.chain_len().await, 1);

        let peer = Node::with_interval(0, Duration::from_millis(50), NodeType::Verifier, None);
        let (addrs, _) = peer.start().await.unwrap();
        miner.connect(addrs[0]).await.unwrap();
        sleep(Duration::from_millis(200)).await;
        assert_eq!(miner.chain_len().await, 2);
    }
}
