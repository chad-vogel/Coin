use coin::{Block, BlockHeader, Blockchain, coinbase_transaction};
use coin_p2p::{
    Node, NodeType,
    rpc::{RpcMessage, read_rpc, write_rpc},
    sign_handshake,
};
use coin_proto::Handshake;
use coin_wallet::Wallet;
use hex_literal::hex;
use rand::rngs::OsRng;
use secp256k1::{PublicKey, Secp256k1, SecretKey};
use stake::Vote;
use tempfile::tempdir;
use tokio::net::TcpStream;
use tokio::time::{Duration, sleep};

const A1: &str = "1BvgsfsZQVtkLS69NvGF8rw6NZW2ShJQHr";
const A2: &str = "1B1TKfsCkW5LQ6R1kSXUx7hLt49m1kwz75";
const SEED: [u8; 16] = hex!("000102030405060708090a0b0c0d0e0f");

fn sign_vote(path: &str, vote: &mut Vote) {
    let wallet = Wallet::from_seed(&SEED).unwrap();
    let sk = wallet.derive_priv(path).unwrap().secret_key().clone();
    vote.sign(&sk);
}

#[tokio::test]
async fn finalize_block_on_votes() {
    let dir = tempdir().unwrap();
    unsafe {
        std::env::set_var("BLOCK_DIR", dir.path());
    }
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
        None,
        None,
        None,
    );
    let (addrs, _) = node.start().await.unwrap();
    let mut addr = addrs[0];
    if addr.ip().is_unspecified() {
        addr = std::net::SocketAddr::new("127.0.0.1".parse().unwrap(), addr.port());
    }
    {
        let chain_handle = node.chain_handle();
        let mut chain = chain_handle.lock().await;
        let reward = chain.block_subsidy();
        chain.add_block(Block {
            header: BlockHeader {
                previous_hash: String::new(),
                merkle_root: String::new(),
                timestamp: 0,
                nonce: 0,
                difficulty: 0,
            },
            transactions: vec![
                coinbase_transaction(A1, reward),
                coinbase_transaction(A2, reward),
            ],
        });
        let prev = chain.last_block_hash().unwrap();
        chain.add_block(Block {
            header: BlockHeader {
                previous_hash: prev.clone(),
                merkle_root: String::new(),
                timestamp: 1,
                nonce: 0,
                difficulty: 0,
            },
            transactions: vec![],
        });
    }
    let hash = {
        let chain_handle = node.chain_handle();
        let chain = chain_handle.lock().await;
        chain.all().last().unwrap().hash()
    };
    {
        let consensus_handle = node.consensus_handle();
        let chain_handle = node.chain_handle();
        let mut cs = consensus_handle.lock().await;
        let mut chain = chain_handle.lock().await;
        cs.registry_mut().stake(&mut chain, A1, 30);
        cs.registry_mut().stake(&mut chain, A2, 30);
        cs.start_round(hash.clone());
    }
    async fn send_vote(addr: std::net::SocketAddr, vote: Vote) {
        let mut stream = TcpStream::connect(addr).await.unwrap();
        let mut rng = OsRng;
        let sk = SecretKey::new(&mut rng);
        let pk = PublicKey::from_secret_key(&Secp256k1::new(), &sk);
        let hs = RpcMessage::Handshake(Handshake {
            network_id: "coin".into(),
            version: 1,
            public_key: pk.serialize().to_vec(),
            signature: sign_handshake(&sk, "coin", 1),
        });
        write_rpc(&mut stream, &hs).await.unwrap();
        let _ = read_rpc(&mut stream).await.unwrap();
        let msg = RpcMessage::Vote(coin_proto::Vote {
            validator: vote.validator,
            block_hash: vote.block_hash,
            signature: vote.signature,
        });
        write_rpc(&mut stream, &msg).await.unwrap();
    }

    let mut v1 = Vote::new(A1.into(), hash.clone());
    sign_vote("m/0'/0/0", &mut v1);
    send_vote(addr, v1).await;
    sleep(Duration::from_millis(50)).await;
    assert!(dir.path().read_dir().unwrap().next().is_none());

    let mut v2 = Vote::new(A2.into(), hash.clone());
    sign_vote("m/0'/0/1", &mut v2);
    send_vote(addr, v2).await;
    sleep(Duration::from_millis(200)).await;
    let cs_handle = node.consensus_handle();
    let cs = cs_handle.lock().await;
    assert_eq!(cs.voted_stake(), 60);
    drop(cs);
    let saved = Blockchain::load(dir.path()).unwrap_or_else(|e| panic!("{:?}", e));
    assert_eq!(saved.len(), 2);
    node.shutdown();
}
