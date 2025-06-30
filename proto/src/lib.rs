use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Transaction {
    pub sender: String,
    pub recipient: String,
    pub amount: u64,
    pub fee: u64,
    pub signature: Vec<u8>,
    pub encrypted_message: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Ping;

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Pong;

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct GetPeers;

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Peers {
    pub addrs: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct GetChain;

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct GetBlock {
    pub hash: String,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Chain {
    pub blocks: Vec<Block>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct BlockHeader {
    pub previous_hash: String,
    pub merkle_root: String,
    pub timestamp: u64,
    pub nonce: u64,
    pub difficulty: u32,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Block {
    pub header: BlockHeader,
    pub transactions: Vec<Transaction>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Handshake {
    pub network_id: String,
    pub version: u32,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type", content = "msg")]
pub enum NodeMessage {
    Transaction(Transaction),
    Ping(Ping),
    Pong(Pong),
    GetPeers(GetPeers),
    Peers(Peers),
    GetChain(GetChain),
    GetBlock(GetBlock),
    Chain(Chain),
    Block(Block),
    Handshake(Handshake),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn transaction_roundtrip() {
        let tx = Transaction {
            sender: "alice".into(),
            recipient: "bob".into(),
            amount: 10,
            fee: 0,
            signature: vec![],
            encrypted_message: vec![],
        };
        let data = serde_json::to_vec(&tx).unwrap();
        let decoded: Transaction = serde_json::from_slice(&data).unwrap();
        assert_eq!(tx, decoded);
    }

    #[test]
    fn block_roundtrip() {
        let block = Block {
            header: BlockHeader {
                previous_hash: "prev".into(),
                merkle_root: "root".into(),
                timestamp: 1,
                nonce: 2,
                difficulty: 3,
            },
            transactions: vec![Transaction {
                sender: "alice".into(),
                recipient: "bob".into(),
                amount: 10,
                fee: 0,
                signature: vec![],
                encrypted_message: vec![],
            }],
        };
        let data = serde_json::to_vec(&block).unwrap();
        let decoded: Block = serde_json::from_slice(&data).unwrap();
        assert_eq!(block, decoded);
    }
}
