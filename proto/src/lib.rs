pub mod proto {
    include!(concat!(env!("OUT_DIR"), "/coin.rs"));
}

#[cfg(test)]
mod tests {
    use super::proto::{Block, BlockHeader, Transaction};
    use prost::Message;

    #[test]
    fn transaction_serializes() {
        let tx = Transaction {
            sender: "alice".into(),
            recipient: "bob".into(),
            amount: 10,
            signature: Vec::new(),
            encrypted_message: Vec::new(),
        };
        let mut buf = Vec::new();
        tx.encode(&mut buf).unwrap();
        let decoded = Transaction::decode(&buf[..]).unwrap();
        assert_eq!(tx, decoded);
    }

    #[test]
    fn block_roundtrip() {
        let header = BlockHeader {
            previous_hash: "prev".into(),
            merkle_root: "root".into(),
            timestamp: 1,
            nonce: 2,
            difficulty: 3,
        };
        let block = Block {
            header: Some(header),
            transactions: vec![Transaction {
                sender: "alice".into(),
                recipient: "bob".into(),
                amount: 10,
                signature: Vec::new(),
                encrypted_message: Vec::new(),
            }],
        };
        let mut buf = Vec::new();
        block.encode(&mut buf).unwrap();
        let decoded = Block::decode(&buf[..]).unwrap();
        assert_eq!(block, decoded);
    }
}
