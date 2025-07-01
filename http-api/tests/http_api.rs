use coin_proto::Transaction;
use reqwest::Client;
use serde_json::Value;
use tokio::task;

#[tokio::test]
async fn test_http_endpoints() {
    let addr = "127.0.0.1:0";
    // start server on random port
    let listener = std::net::TcpListener::bind(addr).unwrap();
    let addr = listener.local_addr().unwrap();
    let server = task::spawn(async move {
        hyper::Server::from_tcp(listener)
            .unwrap()
            .serve(hyper::service::make_service_fn(|_| async {
                Ok::<_, std::convert::Infallible>(hyper::service::service_fn(coin_http::handle_req))
            }))
            .await
            .unwrap();
    });

    let client = Client::new();
    let resp = client
        .get(&format!("http://{}/getBalance/alice", addr))
        .send()
        .await
        .unwrap();
    assert!(resp.status().is_success());
    let v: Value = resp.json().await.unwrap();
    assert_eq!(v["method"], "getBalance");

    let tx = Transaction {
        sender: "a".into(),
        recipient: "b".into(),
        amount: 1,
        fee: 0,
        signature: vec![],
        encrypted_message: vec![],
        inputs: vec![],
        outputs: vec![],
    };
    let resp = client
        .post(&format!("http://{}/sendTransaction", addr))
        .json(&tx)
        .send()
        .await
        .unwrap();
    assert!(resp.status().is_success());
    let v: Value = resp.json().await.unwrap();
    assert_eq!(v["method"], "transaction");

    let resp = client
        .get(&format!("http://{}/getBlocks/1/2", addr))
        .send()
        .await
        .unwrap();
    assert!(resp.status().is_success());
    let v: Value = resp.json().await.unwrap();
    assert_eq!(v["method"], "getBlocks");

    server.abort();
}
