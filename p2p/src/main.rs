use anyhow::Result;
use clap::Parser;
use coin::Blockchain;
use coin_p2p::{Node, NodeType, config::Config};
use std::io::{self, Write};
use tokio::time::{Duration, sleep};

#[derive(Parser)]
struct Args {
    #[arg(long, default_value = "config.yaml")]
    config: String,
}

#[cfg(not(tarpaulin))]
#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();
    let cfg = Config::from_file(&args.config)?;
    let node = Node::new(
        cfg.listener_addrs(),
        cfg.node_type,
        Some(cfg.min_peers),
        cfg.wallet_address.clone(),
        Some(cfg.peers_file.clone()),
        Some(cfg.network_id.clone()),
        Some(cfg.protocol_version),
        Some(cfg.max_msgs_per_sec),
        Some(cfg.max_peers),
        Some(cfg.mining_threads),
    );
    if let Ok(chain) = Blockchain::load(&cfg.chain_file) {
        *node.chain_handle().lock().await = chain;
    }
    let (addrs, _rx) = node.start().await?;
    println!("Node running as {:?} on {:?}", node.node_type(), addrs);

    let status_node = node.clone();
    tokio::spawn(async move {
        loop {
            let (p, h, m) = status_node.status().await;
            print!("\rPeers: {} | Height: {} | Mempool: {}    ", p, h, m);
            io::stdout().flush().ok();
            sleep(Duration::from_secs(1)).await;
            if !status_node.is_running() {
                break;
            }
        }
    });

    for peer in cfg.seed_peer_addrs() {
        let _ = node.connect(peer).await;
    }
    tokio::signal::ctrl_c().await?;
    node.shutdown();
    let handle = node.chain_handle();
    let chain = handle.lock().await;
    chain.save(&cfg.chain_file)?;
    node.save_peers().await?;
    Ok(())
}

#[cfg(tarpaulin)]
fn main() {}
