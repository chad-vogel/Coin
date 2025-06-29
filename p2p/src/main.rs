use anyhow::Result;
use clap::Parser;
use coin::Blockchain;
use coin_p2p::{Node, NodeType};

#[derive(Parser)]
struct Args {
    #[arg(long)]
    port: u16,
    #[arg(long, value_enum)]
    node_type: NodeType,
    #[arg(long, default_value_t = 1)]
    min_peers: usize,
    #[arg(long, default_value = "chain.bin")]
    chain_file: String,
}

#[cfg(not(tarpaulin))]
#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();
    let node = Node::new(args.port, args.node_type, Some(args.min_peers));
    if let Ok(chain) = Blockchain::load(&args.chain_file) {
        *node.chain_handle().lock().await = chain;
    }
    let (_addrs, _rx) = node.start().await?;
    tokio::signal::ctrl_c().await?;
    let handle = node.chain_handle();
    let chain = handle.lock().await;
    chain.save(&args.chain_file)?;
    Ok(())
}

#[cfg(tarpaulin)]
fn main() {}
