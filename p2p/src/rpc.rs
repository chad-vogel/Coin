use coin_proto::{
    Balance, Block, Chain, Finalized, GetBalance, GetBlock, GetBlocks, GetChain, GetPeers,
    GetTransaction, Handshake, Peers, Ping, Pong, Schedule, Stake, Transaction, TransactionDetail,
    Unstake, Vote,
};
use jsonrpc_lite::JsonRpc;
use serde_json::{Value, json};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

#[derive(Clone, Debug)]
pub enum RpcMessage {
    Transaction(Transaction),
    Ping,
    Pong,
    GetPeers,
    Peers(Peers),
    GetChain,
    GetBlock(GetBlock),
    GetBlocks(GetBlocks),
    GetBalance(GetBalance),
    GetTransaction(GetTransaction),
    Chain(Chain),
    Block(Block),
    Balance(Balance),
    TransactionDetail(TransactionDetail),
    Stake(Stake),
    Unstake(Unstake),
    Vote(Vote),
    Finalized(Finalized),
    Schedule(Schedule),
    Handshake(Handshake),
}

pub fn encode_message(msg: &RpcMessage) -> JsonRpc {
    match msg {
        RpcMessage::Transaction(t) => JsonRpc::notification_with_params("transaction", json!(t)),
        RpcMessage::Ping => JsonRpc::notification("ping"),
        RpcMessage::Pong => JsonRpc::notification("pong"),
        RpcMessage::GetPeers => JsonRpc::notification("getPeers"),
        RpcMessage::Peers(p) => JsonRpc::notification_with_params("peers", json!(p)),
        RpcMessage::GetChain => JsonRpc::notification("getChain"),
        RpcMessage::GetBlock(g) => JsonRpc::notification_with_params("getBlock", json!(g)),
        RpcMessage::GetBlocks(g) => JsonRpc::notification_with_params("getBlocks", json!(g)),
        RpcMessage::GetBalance(g) => JsonRpc::notification_with_params("getBalance", json!(g)),
        RpcMessage::GetTransaction(g) => {
            JsonRpc::notification_with_params("getTransaction", json!(g))
        }
        RpcMessage::Chain(c) => JsonRpc::notification_with_params("chain", json!(c)),
        RpcMessage::Block(b) => JsonRpc::notification_with_params("block", json!(b)),
        RpcMessage::Balance(b) => JsonRpc::notification_with_params("balance", json!(b)),
        RpcMessage::TransactionDetail(t) => {
            JsonRpc::notification_with_params("transactionDetail", json!(t))
        }
        RpcMessage::Stake(s) => JsonRpc::notification_with_params("stake", json!(s)),
        RpcMessage::Unstake(u) => JsonRpc::notification_with_params("unstake", json!(u)),
        RpcMessage::Vote(v) => JsonRpc::notification_with_params("vote", json!(v)),
        RpcMessage::Finalized(f) => JsonRpc::notification_with_params("finalized", json!(f)),
        RpcMessage::Schedule(s) => JsonRpc::notification_with_params("schedule", json!(s)),
        RpcMessage::Handshake(h) => JsonRpc::notification_with_params("handshake", json!(h)),
    }
}

pub fn decode_message(rpc: JsonRpc) -> Option<RpcMessage> {
    match rpc.get_method()? {
        "transaction" => rpc
            .get_params()
            .and_then(|p| serde_json::from_value::<Transaction>(params_to_value(p)).ok())
            .map(RpcMessage::Transaction),
        "ping" => Some(RpcMessage::Ping),
        "pong" => Some(RpcMessage::Pong),
        "getPeers" => Some(RpcMessage::GetPeers),
        "peers" => rpc
            .get_params()
            .and_then(|p| serde_json::from_value::<Peers>(params_to_value(p)).ok())
            .map(RpcMessage::Peers),
        "getChain" => Some(RpcMessage::GetChain),
        "getBlock" => rpc
            .get_params()
            .and_then(|p| serde_json::from_value::<GetBlock>(params_to_value(p)).ok())
            .map(RpcMessage::GetBlock),
        "getBlocks" => rpc
            .get_params()
            .and_then(|p| serde_json::from_value::<GetBlocks>(params_to_value(p)).ok())
            .map(RpcMessage::GetBlocks),
        "getBalance" => rpc
            .get_params()
            .and_then(|p| serde_json::from_value::<GetBalance>(params_to_value(p)).ok())
            .map(RpcMessage::GetBalance),
        "getTransaction" => rpc
            .get_params()
            .and_then(|p| serde_json::from_value::<GetTransaction>(params_to_value(p)).ok())
            .map(RpcMessage::GetTransaction),
        "chain" => rpc
            .get_params()
            .and_then(|p| serde_json::from_value::<Chain>(params_to_value(p)).ok())
            .map(RpcMessage::Chain),
        "block" => rpc
            .get_params()
            .and_then(|p| serde_json::from_value::<Block>(params_to_value(p)).ok())
            .map(RpcMessage::Block),
        "balance" => rpc
            .get_params()
            .and_then(|p| serde_json::from_value::<Balance>(params_to_value(p)).ok())
            .map(RpcMessage::Balance),
        "transactionDetail" => rpc
            .get_params()
            .and_then(|p| serde_json::from_value::<TransactionDetail>(params_to_value(p)).ok())
            .map(RpcMessage::TransactionDetail),
        "stake" => rpc
            .get_params()
            .and_then(|p| serde_json::from_value::<Stake>(params_to_value(p)).ok())
            .map(RpcMessage::Stake),
        "unstake" => rpc
            .get_params()
            .and_then(|p| serde_json::from_value::<Unstake>(params_to_value(p)).ok())
            .map(RpcMessage::Unstake),
        "vote" => rpc
            .get_params()
            .and_then(|p| serde_json::from_value::<Vote>(params_to_value(p)).ok())
            .map(RpcMessage::Vote),
        "finalized" => rpc
            .get_params()
            .and_then(|p| serde_json::from_value::<Finalized>(params_to_value(p)).ok())
            .map(RpcMessage::Finalized),
        "schedule" => rpc
            .get_params()
            .and_then(|p| serde_json::from_value::<Schedule>(params_to_value(p)).ok())
            .map(RpcMessage::Schedule),
        "handshake" => rpc
            .get_params()
            .and_then(|p| serde_json::from_value::<Handshake>(params_to_value(p)).ok())
            .map(RpcMessage::Handshake),
        _ => None,
    }
}

fn params_to_value(p: jsonrpc_lite::Params) -> Value {
    match p {
        jsonrpc_lite::Params::Array(mut a) => {
            if a.len() == 1 {
                a.remove(0)
            } else {
                Value::Array(a)
            }
        }
        jsonrpc_lite::Params::Map(m) => Value::Object(m),
        jsonrpc_lite::Params::None(()) => Value::Null,
    }
}

pub async fn write_rpc(socket: &mut TcpStream, msg: &RpcMessage) -> tokio::io::Result<()> {
    let rpc = encode_message(msg);
    let data = serde_json::to_vec(&rpc)
        .map_err(|e| tokio::io::Error::new(tokio::io::ErrorKind::InvalidData, e))?;
    let len = (data.len() as u32).to_be_bytes();
    socket.write_all(&len).await?;
    socket.write_all(&data).await?;
    Ok(())
}

pub async fn read_rpc(socket: &mut TcpStream) -> tokio::io::Result<RpcMessage> {
    let mut len_buf = [0u8; 4];
    socket.read_exact(&mut len_buf).await?;
    let len = u32::from_be_bytes(len_buf) as usize;
    if len > 1024 * 1024 {
        return Err(tokio::io::Error::new(
            tokio::io::ErrorKind::InvalidData,
            "message too large",
        ));
    }
    let mut buf = vec![0u8; len];
    socket.read_exact(&mut buf).await?;
    let rpc: JsonRpc = serde_json::from_slice(&buf)
        .map_err(|e| tokio::io::Error::new(tokio::io::ErrorKind::InvalidData, e))?;
    decode_message(rpc)
        .ok_or_else(|| tokio::io::Error::new(tokio::io::ErrorKind::InvalidData, "invalid rpc"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::net::TcpListener;

    #[tokio::test]
    async fn write_and_read_roundtrip() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let client = tokio::spawn(async move {
            let mut stream = TcpStream::connect(addr).await.unwrap();
            write_rpc(&mut stream, &RpcMessage::Ping).await.unwrap();
        });

        let (mut stream, _) = listener.accept().await.unwrap();
        let msg = read_rpc(&mut stream).await.unwrap();
        assert!(matches!(msg, RpcMessage::Ping));
        client.await.unwrap();
    }

    #[tokio::test]
    async fn read_rpc_rejects_large_message() {
        use tokio::io::AsyncWriteExt;
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let client = tokio::spawn(async move {
            let mut stream = TcpStream::connect(addr).await.unwrap();
            let len = (1024 * 1024 + 1u32).to_be_bytes();
            stream.write_all(&len).await.unwrap();
            stream.write_all(&vec![0u8; 1024 * 1024 + 1]).await.unwrap();
        });

        let (mut stream, _) = listener.accept().await.unwrap();
        let res = read_rpc(&mut stream).await;
        assert!(res.is_err());
        client.await.unwrap();
    }

    #[tokio::test]
    async fn read_rpc_invalid_json() {
        use tokio::io::AsyncWriteExt;
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let client = tokio::spawn(async move {
            let mut stream = TcpStream::connect(addr).await.unwrap();
            stream.write_all(&5u32.to_be_bytes()).await.unwrap();
            stream.write_all(b"hello").await.unwrap();
        });

        let (mut stream, _) = listener.accept().await.unwrap();
        assert!(read_rpc(&mut stream).await.is_err());
        client.await.unwrap();
    }

    #[test]
    fn decode_unknown_method() {
        let rpc = JsonRpc::notification("unknown");
        assert!(decode_message(rpc).is_none());
    }

    #[test]
    fn params_to_value_variants() {
        use jsonrpc_lite::Params;
        let val = params_to_value(Params::Array(vec![json!(1), json!(2)]));
        assert!(matches!(val, Value::Array(a) if a.len() == 2));
        let val = params_to_value(Params::None(()));
        assert!(val.is_null());
    }

    #[test]
    fn encode_decode_roundtrip() {
        let msg = RpcMessage::GetBalance(GetBalance {
            address: "a".into(),
        });
        let rpc = encode_message(&msg);
        let decoded = decode_message(rpc).unwrap();
        match decoded {
            RpcMessage::GetBalance(g) => assert_eq!(g.address, "a"),
            _ => panic!("wrong variant"),
        }

        let stake = RpcMessage::Stake(Stake {
            address: "a".into(),
            amount: 1,
        });
        let rpc = encode_message(&stake);
        let decoded = decode_message(rpc).unwrap();
        match decoded {
            RpcMessage::Stake(s) => {
                assert_eq!(s.address, "a");
                assert_eq!(s.amount, 1);
            }
            _ => panic!("wrong variant"),
        }

        let unstake = RpcMessage::Unstake(Unstake {
            address: "b".into(),
        });
        let rpc = encode_message(&unstake);
        let decoded = decode_message(rpc).unwrap();
        match decoded {
            RpcMessage::Unstake(u) => assert_eq!(u.address, "b"),
            _ => panic!("wrong variant"),
        }
    }
}
