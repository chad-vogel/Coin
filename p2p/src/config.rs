use serde::Deserialize;
use std::fs::File;
use std::net::SocketAddr;

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
    #[serde(default)]
    pub min_peers: usize,
    #[serde(default = "default_chain_file")]
    pub chain_file: String,
}

fn default_chain_file() -> String {
    "chain.bin".to_string()
}

impl Config {
    pub fn from_file(path: &str) -> anyhow::Result<Self> {
        let file = File::open(path)?;
        Ok(serde_yaml::from_reader(file)?)
    }

    pub fn listener_addrs(&self) -> Vec<SocketAddr> {
        self.listeners
            .iter()
            .filter_map(|l| format!("{}:{}", l.ip, l.port).parse().ok())
            .collect()
    }
}
