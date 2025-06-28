use coin::Blockchain;
use coin_proto::proto::{Chain, GetChain, GetPeers, NodeMessage, Peers, Ping, Pong, Transaction};
use prost::Message;
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
    msg.encode(&mut buf).unwrap();
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
    Ok(NodeMessage::decode(&buf[..]).unwrap())
}

async fn read_with_timeout(socket: &mut TcpStream) -> bool {
    timeout(Duration::from_secs(3), read_msg(socket))
        .await
        .is_ok()
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NodeType {
    Wallet,
    Miner,
    Verifier,
}

/// Simple P2P node maintaining a peer address list and pinging peers
pub struct Node {
    port: u16,
    peers: Arc<Mutex<HashSet<SocketAddr>>>,
    ping_interval: Duration,
    node_type: NodeType,
    chain: Arc<Mutex<Blockchain>>,
}

impl Node {
    pub fn new(port: u16, node_type: NodeType) -> Self {
        Self {
            port,
            peers: Arc::new(Mutex::new(HashSet::new())),
            ping_interval: Duration::from_secs(5),
            node_type,
            chain: Arc::new(Mutex::new(Blockchain::new())),
        }
    }

    #[allow(dead_code)]
    pub fn with_interval(port: u16, interval: Duration, node_type: NodeType) -> Self {
        Self {
            port,
            peers: Arc::new(Mutex::new(HashSet::new())),
            ping_interval: interval,
            node_type,
            chain: Arc::new(Mutex::new(Blockchain::new())),
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
                    if let Ok((mut socket, addr)) = listener.accept().await {
                        peers.lock().await.insert(addr);
                        let tx = tx.clone();
                        let peers = peers.clone();
                        let chain = chain.clone();
                        tokio::spawn(async move {
                            loop {
                                match read_msg(&mut socket).await {
                                    Ok(msg) => match msg.msg.unwrap() {
                                        coin_proto::proto::node_message::Msg::Transaction(t) => {
                                            {
                                                let mut chain = chain.lock().await;
                                                chain.add_transaction(t.clone());
                                            }
                                            let _ = tx.send(t).await;
                                        }
                                        coin_proto::proto::node_message::Msg::Ping(_) => {
                                            let resp = NodeMessage {
                                                msg: Some(
                                                    coin_proto::proto::node_message::Msg::Pong(
                                                        Pong {},
                                                    ),
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
                                                    coin_proto::proto::node_message::Msg::Peers(
                                                        Peers { addrs: list },
                                                    ),
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
                                            let msg = NodeMessage {
                                                msg: Some(
                                                    coin_proto::proto::node_message::Msg::Chain(
                                                        Chain { blocks },
                                                    ),
                                                ),
                                            };
                                            let _ = write_msg(&mut socket, &msg).await;
                                        }
                                        coin_proto::proto::node_message::Msg::Chain(c) => {
                                            chain.lock().await.replace(c.blocks);
                                        }
                                        coin_proto::proto::node_message::Msg::Block(_b) => {
                                            // block handling not implemented yet
                                        }
                                    },
                                    Err(_) => break,
                                }
                            }
                            peers.lock().await.remove(&addr);
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
                                if read_with_timeout(&mut stream).await {
                                    return;
                                }
                            }
                        }
                        peers.lock().await.remove(&addr);
                    });
                }
            }
        });

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
                self.chain.lock().await.replace(c.blocks);
            }
        }
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
    use std::net::SocketAddr;
    use tokio::time::{Duration, sleep};

    #[tokio::test]
    async fn node_connects_and_pings() {
        let node = Node::with_interval(0, Duration::from_millis(50), NodeType::Wallet);
        assert_eq!(node.node_type(), NodeType::Wallet);
        let (addrs, mut rx) = node.start().await.unwrap();
        let addr = addrs[0];
        node.connect(addr).await.unwrap();
        sleep(Duration::from_millis(200)).await;
        assert!(!node.peers().await.is_empty());
        let tx = Transaction {
            sender: "a".into(),
            recipient: "b".into(),
            amount: 1,
        };
        send_transaction(&addr.to_string(), &tx).await.unwrap();
        let rec = tokio::time::timeout(Duration::from_secs(1), rx.recv())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(rec, tx);
    }

    #[tokio::test]
    async fn peers_message_updates_list() {
        let node = Node::new(0, NodeType::Wallet);
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
        let node = Node::with_interval(0, Duration::from_millis(50), NodeType::Wallet);
        let (_addrs, _rx) = node.start().await.unwrap();
        let unreachable: SocketAddr = "127.0.0.1:9".parse().unwrap();
        node.peers.lock().await.insert(unreachable);
        sleep(Duration::from_millis(200)).await;
        assert!(!node.peers().await.contains(&unreachable));
    }

    #[tokio::test]
    async fn sync_from_peer_updates_chain() {
        let node_a = Node::with_interval(0, Duration::from_millis(50), NodeType::Verifier);
        let (addrs_a, _) = node_a.start().await.unwrap();
        let addr_a = addrs_a[0];
        node_a.chain.lock().await.add_transaction(Transaction {
            sender: "x".into(),
            recipient: "y".into(),
            amount: 2,
        });

        let node_b = Node::with_interval(0, Duration::from_millis(50), NodeType::Verifier);
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
        let node = Node::new(0, NodeType::Wallet);
        let (addrs, _rx) = node.start().await.unwrap();
        let addr = addrs[0];
        let mut stream = TcpStream::connect(addr).await.unwrap();
        let chain_msg = NodeMessage {
            msg: Some(coin_proto::proto::node_message::Msg::Chain(Chain {
                blocks: vec![Transaction {
                    sender: "s".into(),
                    recipient: "r".into(),
                    amount: 3,
                }],
            })),
        };
        write_msg(&mut stream, &chain_msg).await.unwrap();
        sleep(Duration::from_millis(50)).await;
        assert_eq!(node.chain_len().await, 1);
    }
}
