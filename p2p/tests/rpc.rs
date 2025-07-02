use coin_p2p::rpc::{RpcMessage, decode_message, encode_message, read_rpc, write_rpc};
use coin_proto::{
    Balance, Finalize, GetBalance, GetBlocks, GetTransaction, Schedule, Transaction,
    TransactionDetail, Vote,
};
use jsonrpc_lite::JsonRpc;
use serde_json;
use tokio::io::AsyncWriteExt;
use tokio::net::{TcpListener, TcpStream};

#[test]
fn vote_and_schedule_roundtrip() {
    let v = Vote {
        validator: "v".into(),
        block_hash: "h".into(),
        signature: vec![1, 2, 3],
    };
    let msg = RpcMessage::Vote(v.clone());
    let json = encode_message(&msg);
    let dec = decode_message(json).unwrap();
    match dec {
        RpcMessage::Vote(v2) => assert_eq!(v2, v),
        _ => panic!("wrong message"),
    }

    let sched = Schedule {
        slot: 1,
        validator: "v".into(),
    };
    let msg2 = RpcMessage::Schedule(sched.clone());
    let json2 = encode_message(&msg2);
    let dec2 = decode_message(json2).unwrap();
    match dec2 {
        RpcMessage::Schedule(s2) => assert_eq!(s2, sched),
        _ => panic!("wrong message"),
    }

    let final_msg = RpcMessage::Finalize(Finalize { hash: "abc".into() });
    let enc = encode_message(&final_msg);
    let decf = decode_message(enc).unwrap();
    match decf {
        RpcMessage::Finalize(f) => assert_eq!(f.hash, "abc"),
        _ => panic!("wrong message"),
    }

    let bal_req = RpcMessage::GetBalance(GetBalance {
        address: "addr".into(),
    });
    let json = encode_message(&bal_req);
    let dec = decode_message(json).unwrap();
    match dec {
        RpcMessage::GetBalance(b) => assert_eq!(b.address, "addr"),
        _ => panic!("wrong message"),
    }

    let tx_detail = TransactionDetail {
        transaction: Transaction {
            sender: "a".into(),
            recipient: "b".into(),
            amount: 1,
            fee: 0,
            signature: vec![],
            encrypted_message: vec![],
            inputs: vec![],
            outputs: vec![],
        },
    };
    let detail = RpcMessage::TransactionDetail(tx_detail.clone());
    let json = encode_message(&detail);
    let dec = decode_message(json).unwrap();
    match dec {
        RpcMessage::TransactionDetail(t) => assert_eq!(t, tx_detail),
        _ => panic!("wrong message"),
    }
}

#[tokio::test]
async fn write_and_read_roundtrip() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let msg = RpcMessage::Ping;
    let server = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let received = read_rpc(&mut stream).await.unwrap();
        assert!(matches!(received, RpcMessage::Ping));
    });
    let mut client = TcpStream::connect(addr).await.unwrap();
    write_rpc(&mut client, &msg).await.unwrap();
    server.await.unwrap();
}

#[tokio::test]
async fn read_rpc_rejects_large_message() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let client = tokio::spawn(async move {
        let mut s = TcpStream::connect(addr).await.unwrap();
        let len = ((1024 * 1024) + 1u32).to_be_bytes();
        s.write_all(&len).await.unwrap();
        s.write_all(&[0u8; 1]).await.unwrap();
    });
    let (mut stream, _) = listener.accept().await.unwrap();
    let err = read_rpc(&mut stream).await.unwrap_err();
    assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);
    client.await.unwrap();
}

#[test]
fn decode_message_handles_multi_param_array() {
    let json = r#"{"jsonrpc":"2.0","method":"peers","params":["a","b"]}"#;
    let rpc: jsonrpc_lite::JsonRpc = serde_json::from_str(json).unwrap();
    assert!(decode_message(rpc).is_none());
}
