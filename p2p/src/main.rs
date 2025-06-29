use anyhow::Result;
use clap::Parser;
use coin::Blockchain;
use coin_p2p::{Node, NodeType};

#[derive(Parser)]
struct Args {
    port: u16,
    role: String,
    #[arg(long, default_value = "chain.bin")]
    chain_file: String,
}

#[cfg(not(tarpaulin))]
#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();
    let kind = match args.role.as_str() {
        "wallet" => NodeType::Wallet,
        "miner" => NodeType::Miner,
        "verifier" => NodeType::Verifier,
        _ => NodeType::Wallet,
    };
    let node = Node::new(args.port, kind);
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
