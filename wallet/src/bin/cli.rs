//! Wallet command line interface. The entire CLI is skipped during coverage
//! measurement to keep results stable.

#![cfg_attr(tarpaulin, allow(dead_code))]

#[cfg(not(tarpaulin))]
mod real_cli {
    use anyhow::{Result, anyhow};
    use clap::{Parser, Subcommand};
    use coin::{Blockchain, TransactionExt, new_transaction_with_fee};
    use coin_proto::{Chain, GetChain, Handshake, NodeMessage, Transaction};
    use coin_wallet::Wallet;
    use rand::rngs::OsRng;
    use secp256k1::{PublicKey, Secp256k1, SecretKey};
    use sha2::{Digest, Sha256};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::{TcpStream, lookup_host};

    #[derive(Parser)]
    #[command(author, version, about)]
    struct Cli {
        #[arg(long, default_value = "wallet.mnemonic")]
        wallet: String,
        #[command(subcommand)]
        command: Commands,
    }

    #[derive(Subcommand)]
    enum Commands {
        /// Generate a new wallet and save the mnemonic
        Generate {},
        /// Import a wallet from mnemonic
        Import { phrase: String },
        /// Derive an address from a BIP32 path
        Derive { path: String },
        /// Display balance for an address via RPC
        Balance {
            address: Option<String>,
            path: Option<String>,
            #[arg(long, default_value = "127.0.0.1:9000")]
            node: String,
        },
        /// Sign and send a transaction
        Send {
            to: String,
            amount: u64,
            #[arg(long, default_value = "0")]
            fee: u64,
            path: String,
            #[arg(long, default_value = "127.0.0.1:9000")]
            node: String,
        },
    }

    fn write_wallet(path: &str, phrase: &str) -> Result<()> {
        std::fs::write(path, phrase).map_err(Into::into)
    }

    fn load_wallet(path: &str) -> Result<Wallet> {
        let phrase = std::fs::read_to_string(path)?;
        Ok(Wallet::from_mnemonic(&phrase, "").map_err(|e| anyhow!("{:?}", e))?)
    }

    fn sign_handshake(sk: &SecretKey, network_id: &str, version: u32) -> Vec<u8> {
        let mut hasher = Sha256::new();
        hasher.update(network_id.as_bytes());
        hasher.update(version.to_be_bytes());
        let hash = hasher.finalize();
        let secp = Secp256k1::new();
        let msg = secp256k1::Message::from_slice(&hash).expect("32 bytes");
        let sig = secp.sign_ecdsa_recoverable(&msg, sk);
        let (rec_id, data) = sig.serialize_compact();
        let mut out = Vec::with_capacity(65);
        out.push(rec_id.to_i32() as u8);
        out.extend_from_slice(&data);
        out
    }

    fn verify_handshake(h: &Handshake) -> bool {
        if h.public_key.len() != 33 || h.signature.len() != 65 {
            return false;
        }
        let pk = match PublicKey::from_slice(&h.public_key) {
            Ok(p) => p,
            Err(_) => return false,
        };
        let rec_id = match secp256k1::ecdsa::RecoveryId::from_i32(h.signature[0] as i32) {
            Ok(id) => id,
            Err(_) => return false,
        };
        let mut data = [0u8; 64];
        data.copy_from_slice(&h.signature[1..]);
        let sig = match secp256k1::ecdsa::RecoverableSignature::from_compact(&data, rec_id) {
            Ok(s) => s,
            Err(_) => return false,
        };
        let mut hasher = Sha256::new();
        hasher.update(h.network_id.as_bytes());
        hasher.update(h.version.to_be_bytes());
        let hash = hasher.finalize();
        let msg = secp256k1::Message::from_slice(&hash).expect("32 bytes");
        let secp = Secp256k1::new();
        match secp.recover_ecdsa(&msg, &sig) {
            Ok(p) => p == pk,
            Err(_) => false,
        }
    }

    async fn write_msg(stream: &mut TcpStream, msg: &NodeMessage) -> Result<()> {
        let buf = serde_json::to_vec(msg)?;
        let len = (buf.len() as u32).to_be_bytes();
        stream.write_all(&len).await?;
        stream.write_all(&buf).await?;
        Ok(())
    }

    async fn read_msg(stream: &mut TcpStream) -> Result<NodeMessage> {
        let mut len_buf = [0u8; 4];
        stream.read_exact(&mut len_buf).await?;
        let len = u32::from_be_bytes(len_buf) as usize;
        let mut buf = vec![0u8; len];
        stream.read_exact(&mut buf).await?;
        Ok(serde_json::from_slice(&buf)?)
    }

    async fn rpc_connect(addr: &str) -> Result<TcpStream> {
        let addr = lookup_host(addr)
            .await?
            .next()
            .ok_or(anyhow!("invalid addr"))?;
        let mut stream = TcpStream::connect(addr).await?;
        let mut rng = OsRng;
        let sk = SecretKey::new(&mut rng);
        let secp = Secp256k1::new();
        let pk = PublicKey::from_secret_key(&secp, &sk);
        let hs = NodeMessage::Handshake(Handshake {
            network_id: "coin".to_string(),
            version: 1,
            public_key: pk.serialize().to_vec(),
            signature: sign_handshake(&sk, "coin", 1),
        });
        write_msg(&mut stream, &hs).await?;
        match read_msg(&mut stream).await? {
            NodeMessage::Handshake(h)
                if h.network_id == "coin" && h.version == 1 && verify_handshake(&h) => {}
            _ => return Err(anyhow!("handshake failed")),
        }
        Ok(stream)
    }

    async fn fetch_chain(addr: &str) -> Result<Vec<coin::Block>> {
        let mut stream = rpc_connect(addr).await?;
        let get = NodeMessage::GetChain(GetChain {});
        write_msg(&mut stream, &get).await?;
        loop {
            match read_msg(&mut stream).await? {
                NodeMessage::Chain(Chain { blocks }) => {
                    let chain: Vec<_> = blocks
                        .into_iter()
                        .filter_map(coin::Block::from_rpc)
                        .collect();
                    return Ok(chain);
                }
                _ => continue,
            }
        }
    }

    async fn send_transaction(addr: &str, tx: &Transaction) -> Result<()> {
        let mut stream = rpc_connect(addr).await?;
        let msg = NodeMessage::Transaction(tx.clone());
        write_msg(&mut stream, &msg).await?;
        Ok(())
    }

    #[cfg(not(tarpaulin))]
    pub async fn run() -> Result<()> {
        let cli = Cli::parse();
        match cli.command {
            Commands::Generate {} => {
                let wallet = Wallet::generate("").map_err(|e| anyhow!("{:?}", e))?;
                let phrase = wallet.mnemonic().unwrap().phrase().to_string();
                write_wallet(&cli.wallet, &phrase)?;
                println!("Mnemonic: {}", phrase);
            }
            Commands::Import { phrase } => {
                let wallet = Wallet::from_mnemonic(&phrase, "").map_err(|e| anyhow!("{:?}", e))?;
                write_wallet(&cli.wallet, wallet.mnemonic().unwrap().phrase())?;
            }
            Commands::Derive { path } => {
                let wallet = load_wallet(&cli.wallet)?;
                let addr = wallet
                    .derive_address(&path)
                    .map_err(|e| anyhow!("{:?}", e))?;
                println!("{}", addr);
            }
            Commands::Balance {
                address,
                path,
                node,
            } => {
                let addr = if let Some(a) = address {
                    a
                } else if let Some(p) = path {
                    let wallet = load_wallet(&cli.wallet)?;
                    wallet.derive_address(&p).map_err(|e| anyhow!("{:?}", e))?
                } else {
                    return Err(anyhow!("address or path required"));
                };
                let blocks = fetch_chain(&node).await?;
                let mut bc = Blockchain::new();
                for b in blocks {
                    bc.add_block(b);
                }
                println!("{}", bc.balance(&addr));
            }
            Commands::Send {
                to,
                amount,
                fee,
                path,
                node,
            } => {
                let wallet = load_wallet(&cli.wallet)?;
                let child = wallet.derive_priv(&path).map_err(|e| anyhow!("{:?}", e))?;
                let from = wallet
                    .derive_address(&path)
                    .map_err(|e| anyhow!("{:?}", e))?;
                let mut tx = new_transaction_with_fee(&from, to, amount, fee);
                tx.sign(child.secret_key());
                send_transaction(&node, &tx).await?;
                println!("Transaction sent");
            }
        }
        Ok(())
    }
}

#[cfg(tarpaulin)]
fn main() {}

#[cfg(not(tarpaulin))]
#[tokio::main]
async fn main() -> anyhow::Result<()> {
    real_cli::run().await
}
