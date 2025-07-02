use coin::{Block, BlockHeader, coinbase_transaction, compute_merkle_root};
use coin_p2p::{
    Node, NodeType,
    rpc::{RpcMessage, read_rpc, write_rpc},
    sign_handshake,
};
use coin_wallet::Wallet;
use hex_literal::hex;
use rand::rngs::OsRng;
use secp256k1::{PublicKey, Secp256k1, SecretKey};
use stake::Vote;
use std::net::SocketAddr;
use tokio::net::TcpStream;
use tokio::time::{Duration, sleep, timeout};

const A1: &str = "1BvgsfsZQVtkLS69NvGF8rw6NZW2ShJQHr";
const A2: &str = "1B1TKfsCkW5LQ6R1kSXUx7hLt49m1kwz75";
const SEED: [u8; 16] = hex!("000102030405060708090a0b0c0d0e0f");

fn sign_vote(path: &str, vote: &mut Vote) {
    let wallet = Wallet::from_seed(&SEED).unwrap();
    let sk = wallet.derive_priv(path).unwrap().secret_key().clone();
    vote.sign(&sk);
}

async fn handshake_peer(addr: SocketAddr) -> tokio::io::Result<TcpStream> {
    for _ in 0..10 {
        let mut rng = OsRng;
        let sk = SecretKey::new(&mut rng);
        let pk = PublicKey::from_secret_key(&Secp256k1::new(), &sk);
        if let Ok(mut stream) = TcpStream::connect(addr).await {
            let hs = RpcMessage::Handshake(coin_proto::Handshake {
                network_id: "coin".into(),
                version: 1,
                public_key: pk.serialize().to_vec(),
                signature: sign_handshake(&sk, "coin", 1),
            });
            if write_rpc(&mut stream, &hs).await.is_ok() {
                if let Ok(Ok(resp)) =
                    timeout(Duration::from_millis(500), read_rpc(&mut stream)).await
                {
                    if matches!(resp, RpcMessage::Handshake(_)) {
                        return Ok(stream);
                    }
                }
            }
        }
        sleep(Duration::from_millis(30)).await;
    }
    Err(tokio::io::Error::new(
        tokio::io::ErrorKind::Other,
        "handshake failed",
    ))
}

#[tokio::test]
async fn network_votes_finalize_block() {
    timeout(Duration::from_secs(20), async {
        let node_a = Node::with_interval(
            vec!["127.0.0.1:0".parse().unwrap()],
            Duration::from_millis(50),
            NodeType::Verifier,
            None,
            None,
            None,
            None,
            None,
            None,
            Some(10),
            Some(8),
            None,
        );
        let (addrs_a, _) = node_a.start().await.unwrap();
        sleep(Duration::from_millis(50)).await;
        let addr_a = addrs_a[0];

        let node_b = Node::with_interval(
            vec!["127.0.0.1:0".parse().unwrap()],
            Duration::from_millis(50),
            NodeType::Verifier,
            None,
            None,
            None,
            None,
            None,
            None,
            Some(10),
            Some(8),
            None,
        );
        let (_addrs_b, _) = node_b.start().await.unwrap();
        sleep(Duration::from_millis(50)).await;
        node_b.connect(addr_a).await.unwrap();

        let node_c = Node::with_interval(
            vec!["127.0.0.1:0".parse().unwrap()],
            Duration::from_millis(50),
            NodeType::Verifier,
            None,
            None,
            None,
            None,
            None,
            None,
            Some(10),
            Some(8),
            None,
        );
        let (_addrs_c, _) = node_c.start().await.unwrap();
        sleep(Duration::from_millis(50)).await;
        node_c.connect(addr_a).await.unwrap();

        {
            let chain_handle = node_a.chain_handle();
            let mut chain = chain_handle.lock().await;
            let reward = chain.block_subsidy();
            let tx1 = coinbase_transaction(A1, reward).unwrap();
            let merkle1 = compute_merkle_root(&[tx1.clone()]);
            chain.add_block(Block {
                header: BlockHeader {
                    previous_hash: String::new(),
                    merkle_root: merkle1,
                    timestamp: 0,
                    nonce: 0,
                    difficulty: 0,
                },
                transactions: vec![tx1],
            });
            let prev = chain.last_block_hash().unwrap();
            let tx2 = coinbase_transaction(A2, reward).unwrap();
            let merkle2 = compute_merkle_root(&[tx2.clone()]);
            chain.add_block(Block {
                header: BlockHeader {
                    previous_hash: prev.clone(),
                    merkle_root: merkle2,
                    timestamp: 1,
                    nonce: 0,
                    difficulty: 0,
                },
                transactions: vec![tx2],
            });
        }
        let hash = {
            let chain_handle = node_a.chain_handle();
            let chain = chain_handle.lock().await;
            chain.all().last().unwrap().hash()
        };

        {
            let consensus_handle = node_a.consensus_handle();
            let chain_handle = node_a.chain_handle();
            let mut cs = consensus_handle.lock().await;
            let mut chain = chain_handle.lock().await;
            cs.registry_mut().stake(&mut chain, A1, 30);
            cs.registry_mut().stake(&mut chain, A2, 30);
            cs.start_round(hash.clone());
        }

        let mut v1 = Vote::new(A1.into(), hash.clone());
        sign_vote("m/0'/0/0", &mut v1);
        node_a.handle_vote(&v1).await;

        sleep(Duration::from_millis(50)).await;
        {
            let cs = node_a.consensus_handle();
            let cs = cs.lock().await;
            assert!(!cs.is_finalized(&hash));
        }

        let mut v2 = Vote::new(A2.into(), hash.clone());
        sign_vote("m/0'/0/1", &mut v2);
        node_a.handle_vote(&v2).await;
        sleep(Duration::from_millis(100)).await;
        {
            let cs = node_a.consensus_handle();
            let cs = cs.lock().await;
            assert!(cs.is_finalized(&hash));
        }

        node_a.shutdown();
        node_b.shutdown();
        node_c.shutdown();
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn peer_limit_and_rate_limit() {
    let node = Node::new(
        vec!["127.0.0.1:0".parse().unwrap()],
        NodeType::Verifier,
        None,
        None,
        None,
        None,
        None,
        None,
        Some(5),
        Some(2),
        None,
    );
    let (addrs, _) = node.start().await.unwrap();
    sleep(Duration::from_millis(50)).await;
    let addr = addrs[0];

    let mut peer1 = handshake_peer(addr).await.unwrap();
    let peer1_addr = peer1.local_addr().unwrap();
    loop {
        if node.peers().await.contains(&peer1_addr) {
            break;
        }
        sleep(Duration::from_millis(10)).await;
    }

    let mut peer2 = handshake_peer(addr).await.unwrap();
    let _peer2_addr = peer2.local_addr().unwrap();
    loop {
        if node.peers().await.len() == 2 {
            break;
        }
        sleep(Duration::from_millis(10)).await;
    }

    let attempt = timeout(Duration::from_millis(100), handshake_peer(addr)).await;
    assert!(matches!(attempt, Err(_) | Ok(Err(_))));
    assert_eq!(node.peers().await.len(), 2);

    for _ in 0..6 {
        write_rpc(&mut peer1, &RpcMessage::Ping).await.unwrap();
    }
    sleep(Duration::from_millis(100)).await;
    assert!(!node.peers().await.contains(&peer1_addr));

    let mut peer3 = handshake_peer(addr).await.unwrap();
    let peer3_addr = peer3.local_addr().unwrap();
    loop {
        if node.peers().await.contains(&peer3_addr) {
            break;
        }
        sleep(Duration::from_millis(10)).await;
    }
    assert_eq!(node.peers().await.len(), 2);

    node.shutdown();
    drop(peer2);
    drop(peer3);
}
