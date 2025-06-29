use anyhow::Result;
use clap::Parser;
use coin::Blockchain;
use coin_p2p::{Node, NodeType, config::Config};

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
    );
    if let Ok(chain) = Blockchain::load(&cfg.chain_file) {
        *node.chain_handle().lock().await = chain;
    }
    let (_addrs, _rx) = node.start().await?;
    tokio::signal::ctrl_c().await?;
    let handle = node.chain_handle();
    let chain = handle.lock().await;
    chain.save(&cfg.chain_file)?;
    Ok(())
}

#[cfg(tarpaulin)]
fn main() {}
