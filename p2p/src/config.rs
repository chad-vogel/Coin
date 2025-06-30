use serde::Deserialize;
use std::fs::File;
use std::net::{SocketAddr, ToSocketAddrs};

use crate::NodeType;

#[derive(Debug, Deserialize)]
pub struct Listener {
    pub ip: String,
    pub port: u16,
}

#[derive(Debug, Deserialize)]
pub struct Config {
    pub listeners: Vec<Listener>,
    pub wallet_address: Option<String>,
    pub node_type: NodeType,
    #[serde(default = "default_min_peers")]
    pub min_peers: usize,
    #[serde(default = "default_chain_file")]
    pub chain_file: String,
    #[serde(default)]
    pub seed_peers: Vec<String>,
    #[serde(default)]
    pub tor_proxy: Option<String>,
    #[serde(default = "default_network_id")]
    pub network_id: String,
    #[serde(default = "default_protocol_version")]
    pub protocol_version: u32,
    #[serde(default = "default_max_msgs_per_sec")]
    pub max_msgs_per_sec: u32,
    #[serde(default = "default_max_peers")]
    pub max_peers: usize,
    #[serde(default = "default_mining_threads")]
    pub mining_threads: usize,
}

fn default_chain_file() -> String {
    "chain.bin".to_string()
}

fn default_min_peers() -> usize {
    1
}

fn default_network_id() -> String {
    "coin".to_string()
}

fn default_protocol_version() -> u32 {
    1
}

fn default_max_msgs_per_sec() -> u32 {
    10
}

fn default_max_peers() -> usize {
    32
}

fn default_mining_threads() -> usize {
    std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(1)
}

impl Config {
    pub fn from_file(path: &str) -> anyhow::Result<Self> {
        let file = File::open(path)?;
        Ok(serde_yaml::from_reader(file)?)
    }

    pub fn listener_addrs(&self) -> Vec<SocketAddr> {
        self.listeners
            .iter()
            .filter_map(|l| {
                if l.ip.contains(':') {
                    format!("[{}]:{}", l.ip, l.port).parse().ok()
                } else {
                    format!("{}:{}", l.ip, l.port).parse().ok()
                }
            })
            .collect()
    }

    pub fn seed_peer_addrs(&self) -> Vec<SocketAddr> {
        self.seed_peers
            .iter()
            .filter_map(|s| s.to_socket_addrs().ok().and_then(|mut a| a.next()))
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_peers_fields() {
        let yaml = r#"
listeners:
  - ip: "0.0.0.0"
    port: 8000
node_type: Wallet
seed_peers:
  - "127.0.0.1:9000"
"#;
        let cfg: Config = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(cfg.seed_peers, vec!["127.0.0.1:9000".to_string()]);
        assert_eq!(cfg.network_id, "coin");
        assert_eq!(cfg.protocol_version, 1);
        assert_eq!(cfg.max_msgs_per_sec, 10);
        assert_eq!(cfg.max_peers, 32);
        assert!(cfg.mining_threads >= 1);
        assert!(cfg.tor_proxy.is_none());
    }

    #[test]
    fn ipv6_listener_parses() {
        let yaml = r#"
listeners:
  - ip: "::1"
    port: 9000
node_type: Wallet
"#;
        let cfg: Config = serde_yaml::from_str(yaml).unwrap();
        let addrs = cfg.listener_addrs();
        assert_eq!(addrs.len(), 1);
        assert_eq!(addrs[0].port(), 9000);
        assert!(addrs[0].is_ipv6());
    }
}
