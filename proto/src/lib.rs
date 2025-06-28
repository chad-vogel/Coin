pub mod proto {
    include!(concat!(env!("OUT_DIR"), "/coin.rs"));
}

#[cfg(test)]
mod tests {
    use super::proto::Transaction;
    use prost::Message;

    #[test]
    fn transaction_serializes() {
        let tx = Transaction {
            sender: "alice".into(),
            recipient: "bob".into(),
            amount: 10,
        };
        let mut buf = Vec::new();
        tx.encode(&mut buf).unwrap();
        let decoded = Transaction::decode(&buf[..]).unwrap();
        assert_eq!(tx, decoded);
    }
}
