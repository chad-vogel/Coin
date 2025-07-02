use coin::{Block, BlockHeader, coinbase_transaction};
use coin_p2p::{Node, NodeType};
use coin_proto::Transaction;
use hyper::{Body, Method, Request, StatusCode};
use reqwest::Client;
use serde_json::Value;
use tokio::task;

#[tokio::test]
async fn test_http_endpoints() {
    let node = Node::new(
        vec!["0.0.0.0:0".parse().unwrap()],
        NodeType::Wallet,
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        None,
    );
    let reward;
    {
        let handle = node.chain_handle();
        let mut chain = handle.lock().await;
        reward = chain.block_subsidy();
        let _ = chain.add_block(Block {
            header: BlockHeader {
                previous_hash: String::new(),
                merkle_root: String::new(),
                timestamp: 0,
                nonce: 0,
                difficulty: 0,
            },
            transactions: vec![coinbase_transaction(
                "1BvgsfsZQVtkLS69NvGF8rw6NZW2ShJQHr",
                reward,
            )],
        });
    }
    let (addrs, _) = node.start().await.unwrap();
    let node_addr = addrs[0];

    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let server = task::spawn(async move {
        hyper::Server::from_tcp(listener)
            .unwrap()
            .serve(hyper::service::make_service_fn(move |_| {
                let node_addr = node_addr;
                async move {
                    Ok::<_, std::convert::Infallible>(hyper::service::service_fn(move |req| {
                        coin_http::handle_req(req, node_addr)
                    }))
                }
            }))
            .await
            .unwrap();
    });

    let client = Client::new();
    let resp = client
        .get(&format!(
            "http://{}/getBalance/1BvgsfsZQVtkLS69NvGF8rw6NZW2ShJQHr",
            addr
        ))
        .send()
        .await
        .unwrap();
    assert!(resp.status().is_success());
    let v: Value = resp.json().await.unwrap();
    assert_eq!(v["method"], "balance");
    assert_eq!(v["params"]["amount"].as_i64().unwrap(), reward as i64);

    let tx = Transaction {
        sender: "a".into(),
        recipient: "b".into(),
        amount: 1,
        fee: 0,
        signature: vec![],
        encrypted_message: vec![],
        inputs: vec![],
        outputs: vec![],
        contract_state: std::collections::HashMap::new(),
    };
    let resp = client
        .post(&format!("http://{}/sendTransaction", addr))
        .json(&tx)
        .send()
        .await
        .unwrap();
    assert!(resp.status().is_success());
    assert!(resp.text().await.unwrap().is_empty());

    let resp = client
        .get(&format!("http://{}/getBlocks/0/0", addr))
        .send()
        .await
        .unwrap();
    assert!(resp.status().is_success());
    let v: Value = resp.json().await.unwrap();
    assert_eq!(v["method"], "chain");
    assert_eq!(v["params"]["blocks"].as_array().unwrap().len(), 1);

    let resp = client
        .get(&format!("http://{}/mempool", addr))
        .send()
        .await
        .unwrap();
    assert!(resp.status().is_success());
    let v: Value = resp.json().await.unwrap();
    assert_eq!(v["method"], "chain");

    let resp = client
        .get(&format!("http://{}/status", addr))
        .send()
        .await
        .unwrap();
    assert!(resp.status().is_success());
    let v: Value = resp.json().await.unwrap();
    assert!(v["peers"].as_u64().unwrap() >= 1);
    assert_eq!(v["height"], 1);

    server.abort();
}

#[tokio::test]
async fn test_send_transaction_invalid_json() {
    let req = Request::builder()
        .method(Method::POST)
        .uri("/sendTransaction")
        .body(Body::from("oops"))
        .unwrap();
    let resp = coin_http::handle_req(req, "127.0.0.1:1".parse().unwrap())
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn test_get_blocks_bad_path() {
    let req = Request::builder()
        .method(Method::GET)
        .uri("/getBlocks/1")
        .body(Body::empty())
        .unwrap();
    let resp = coin_http::handle_req(req, "127.0.0.1:1".parse().unwrap())
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn test_not_found_path() {
    let req = Request::builder()
        .method(Method::GET)
        .uri("/unknown")
        .body(Body::empty())
        .unwrap();
    let resp = coin_http::handle_req(req, "127.0.0.1:1".parse().unwrap())
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn test_rpc_error() {
    let req = Request::builder()
        .method(Method::GET)
        .uri("/getBalance/alice")
        .body(Body::empty())
        .unwrap();
    let resp = coin_http::handle_req(req, "127.0.0.1:1".parse().unwrap())
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::INTERNAL_SERVER_ERROR);
}

#[tokio::test]
async fn test_forward_rpc_timeout() {
    use coin_p2p::rpc::{RpcMessage, read_rpc, write_rpc};
    use coin_proto::Handshake;
    use tokio::net::TcpListener;
    use tokio::time::{Duration, sleep};

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let _ = read_rpc(&mut stream).await.unwrap();
        let reply = RpcMessage::Handshake(Handshake {
            network_id: "coin".into(),
            version: 1,
            public_key: vec![],
            signature: vec![],
        });
        write_rpc(&mut stream, &reply).await.unwrap();
        sleep(Duration::from_secs(2)).await;
    });

    let req = Request::builder()
        .method(Method::GET)
        .uri("/getBalance/alice")
        .body(Body::empty())
        .unwrap();
    let resp = coin_http::handle_req(req, addr).await.unwrap();
    assert!(resp.status().is_success());
    assert_eq!(
        hyper::body::to_bytes(resp.into_body()).await.unwrap().len(),
        0
    );

    server.abort();
}
