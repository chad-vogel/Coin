use coin::address_from_secret;
use coin_p2p::{
    Node, NodeType,
    rpc::{RpcMessage, read_rpc, write_rpc},
    sign_handshake,
};
use rand::rngs::OsRng;
use secp256k1::{Secp256k1, SecretKey};
use stake::Vote;
use tokio::net::TcpListener;
use tokio::time::{Duration, sleep};

const A1: &str = "1BvgsfsZQVtkLS69NvGF8rw6NZW2ShJQHr";

#[tokio::test]
async fn broadcast_vote_sends_vote() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let node = Node::new(
        vec![],
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
    node.connect(addr).await.unwrap();

    let server = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        match read_rpc(&mut stream).await.unwrap() {
            RpcMessage::Handshake(_) => {}
            other => panic!("expected handshake, got {:?}", other),
        }
        let mut rng = rand::rngs::OsRng;
        let sk = SecretKey::new(&mut rng);
        let pk = secp256k1::PublicKey::from_secret_key(&Secp256k1::new(), &sk);
        let reply = RpcMessage::Handshake(coin_proto::Handshake {
            network_id: "coin".into(),
            version: 1,
            public_key: pk.serialize().to_vec(),
            signature: sign_handshake(&sk, "coin", 1),
        });
        write_rpc(&mut stream, &reply).await.unwrap();
        match read_rpc(&mut stream).await.unwrap() {
            RpcMessage::Vote(v) => v,
            other => panic!("expected vote, got {:?}", other),
        }
    });

    let sk = SecretKey::from_slice(&[1u8; 32]).unwrap();
    let addr_str = address_from_secret(&sk);
    let mut vote = Vote::new(addr_str.clone(), "h".into());
    vote.sign(&sk);
    node.broadcast_vote(&vote).await.unwrap();

    let v = server.await.unwrap();
    assert_eq!(v.validator, addr_str);
}

#[tokio::test]
async fn handle_vote_finalizes_block() {
    let dir = tempfile::tempdir().unwrap();
    unsafe {
        std::env::set_var("BLOCK_DIR", dir.path());
    }
    let node = Node::new(
        vec![],
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
    {
        let handle = node.chain_handle();
        let mut chain = handle.lock().await;
        let reward = chain.block_subsidy();
        chain.add_block(coin::Block {
            header: coin::BlockHeader {
                previous_hash: String::new(),
                merkle_root: String::new(),
                timestamp: 0,
                nonce: 0,
                difficulty: 0,
            },
            transactions: vec![coin::coinbase_transaction(A1, reward).unwrap()],
        });
    }
    let hash = {
        let handle = node.chain_handle();
        handle.lock().await.all().last().unwrap().hash()
    };
    {
        let chain_handle = node.chain_handle();
        let mut chain = chain_handle.lock().await;
        let cons_handle = node.consensus_handle();
        let mut cs = cons_handle.lock().await;
        cs.registry_mut().stake(&mut chain, A1, 10);
        cs.start_round(hash.clone());
    }
    let sk = SecretKey::from_slice(&[1u8; 32]).unwrap();
    let mut vote = Vote::new(A1.into(), hash.clone());
    vote.sign(&sk);
    node.handle_vote(&vote).await;
    sleep(Duration::from_millis(50)).await;
    assert!(node.consensus_handle().lock().await.is_finalized(&hash));
    assert!(dir.path().join("blk00000.dat").exists());
    unsafe {
        std::env::remove_var("BLOCK_DIR");
    }
}
