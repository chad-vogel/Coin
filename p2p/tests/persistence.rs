use coin::Blockchain;
use coin_p2p::{Node, NodeType};
use miner::mine_block;
use tempfile::tempdir;

const MINER: &str = "1BvgsfsZQVtkLS69NvGF8rw6NZW2ShJQHr";

#[tokio::test]
async fn reloads_block_after_restart() {
    let dir = tempdir().unwrap();
    std::env::set_var("BLOCK_DIR", dir.path());

    let node1 = Node::new(
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
    let _ = node1.start().await.unwrap();

    let block_hash = {
        let handle = node1.chain_handle();
        let mut chain = handle.lock().await;
        let block = mine_block(&mut chain, MINER);
        chain.save(dir.path()).unwrap();
        block.hash()
    };
    node1.shutdown();

    let node2 = Node::new(
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
    if let Ok(chain) = Blockchain::load(dir.path()) {
        *node2.chain_handle().lock().await = chain;
    }
    let _ = node2.start().await.unwrap();
    let (peer_count, height, mempool) = node2.status().await;
    assert_eq!(peer_count, 0);
    assert_eq!(height, 1);
    assert_eq!(mempool, 0);
    let loaded_hash = {
        let handle = node2.chain_handle();
        let chain = handle.lock().await;
        assert_eq!(chain.len(), 1);
        chain.last_block_hash().unwrap()
    };
    assert_eq!(block_hash, loaded_hash);
    node2.save_peers().await.unwrap();
    node2.shutdown();
    // remove env var so later tests have a fresh state
    std::env::remove_var("BLOCK_DIR");
}
