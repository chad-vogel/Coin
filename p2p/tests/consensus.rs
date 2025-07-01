use coin::{Block, BlockHeader, Blockchain, coinbase_transaction, compute_merkle_root};
use coin_p2p::{Node, NodeType};
use coin_wallet::Wallet;
use hex_literal::hex;
use stake::Vote;
use tempfile::tempdir;
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
    {
        let chain_handle = node.chain_handle();
        let mut chain = chain_handle.lock().await;
        let reward = chain.block_subsidy();
        let tx1 = coinbase_transaction(A1, reward);
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
        let tx2 = coinbase_transaction(A2, reward);
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
    let mut v1 = Vote::new(A1.into(), hash.clone());
    sign_vote("m/0'/0/0", &mut v1);
    println!("sending first vote");
    {
        let handle = node.consensus_handle();
        let mut cs = handle.lock().await;
        assert!(!cs.register_vote(&v1));
    }
    sleep(Duration::from_millis(50)).await;
    assert!(dir.path().read_dir().unwrap().next().is_none());

    let mut v2 = Vote::new(A2.into(), hash.clone());
    sign_vote("m/0'/0/1", &mut v2);
    println!("sending second vote");
    let reached = {
        let handle = node.consensus_handle();
        let mut cs = handle.lock().await;
        cs.register_vote(&v2)
    };
    if reached {
        node.chain_handle().lock().await.save(dir.path()).unwrap();
    }
    sleep(Duration::from_millis(200)).await;
    let cs_handle = node.consensus_handle();
    let cs = cs_handle.lock().await;
    assert_eq!(cs.voted_stake(), 60);
    drop(cs);
    let saved = Blockchain::load(dir.path()).unwrap_or_else(|e| panic!("{:?}", e));
    assert_eq!(saved.len(), 2);
    node.shutdown();
}
