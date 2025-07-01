use anyhow::Result;
use clap::Parser;
use coin::Blockchain;
use coin_p2p::{Node, config::Config};
use std::io::{self, Write};
use tokio::time::{Duration, sleep};

#[derive(Parser)]
struct Args {
    #[arg(long, default_value = "config.yaml")]
    config: String,
    #[arg(long)]
    tor_proxy: Option<String>,
}

#[cfg(not(tarpaulin))]
#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();
    let cfg = Config::from_file(&args.config)?;
    std::fs::create_dir_all(&cfg.block_dir)?;
    let tor_proxy = args
        .tor_proxy
        .or(cfg.tor_proxy.clone())
        .and_then(|s| s.parse().ok());
    let node = Node::new(
        cfg.listener_addrs(),
        cfg.node_type,
        None,
        cfg.wallet_address.clone(),
        None,
        tor_proxy,
        Some(cfg.network_id.clone()),
        Some(cfg.protocol_version),
        Some(cfg.max_msgs_per_sec),
        Some(cfg.max_peers),
        cfg.mining_threads,
    );
    if let Ok(chain) = Blockchain::load(&cfg.block_dir) {
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
    let mut chain = handle.lock().await;
    chain.prune(cfg.prune_depth as usize);
    std::fs::create_dir_all(&cfg.block_dir)?;
    chain.save(&cfg.block_dir)?;
    node.save_peers().await?;
    Ok(())
}

#[cfg(tarpaulin)]
fn main() {}
