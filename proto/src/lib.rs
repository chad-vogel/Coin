use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Transaction {
    pub sender: String,
    pub recipient: String,
    pub amount: u64,
    pub fee: u64,
    pub signature: Vec<u8>,
    pub encrypted_message: Vec<u8>,
    #[serde(default)]
    pub inputs: Vec<TransactionInput>,
    #[serde(default)]
    pub outputs: Vec<TransactionOutput>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct TransactionInput {
    pub address: String,
    pub amount: u64,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct TransactionOutput {
    pub address: String,
    pub amount: u64,
}
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Deploy {
    pub wasm: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Invoke {
    pub contract: String,
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
    /// Milliseconds since the Unix epoch
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
    pub public_key: Vec<u8>,
    pub signature: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Vote {
    pub validator: String,
    pub block_hash: String,
    pub signature: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Schedule {
    pub slot: u64,
    pub validator: String,
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
            inputs: vec![],
            outputs: vec![],
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
                inputs: vec![],
                outputs: vec![],
            }],
        };
        let data = serde_json::to_vec(&block).unwrap();
        let decoded: Block = serde_json::from_slice(&data).unwrap();
        assert_eq!(block, decoded);
    }

    #[test]
    fn vote_roundtrip() {
        let vote = Vote {
            validator: "val".into(),
            block_hash: "hash".into(),
            signature: vec![1, 2, 3],
        };
        let data = serde_json::to_vec(&vote).unwrap();
        let decoded: Vote = serde_json::from_slice(&data).unwrap();
        assert_eq!(vote, decoded);
    }

    #[test]
    fn schedule_roundtrip() {
        let sched = Schedule {
            slot: 1,
            validator: "v".into(),
        };
        let data = serde_json::to_vec(&sched).unwrap();
        let decoded: Schedule = serde_json::from_slice(&data).unwrap();
        assert_eq!(sched, decoded);
    }
}
