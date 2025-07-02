use coin_p2p::rpc::{self, RpcMessage, read_rpc, write_rpc};
use coin_p2p::sign_handshake;
use coin_proto::{GetBalance, GetBlocks, Handshake, Transaction};
use hyper::service::{make_service_fn, service_fn};
use hyper::{Body, Method, Request, Response, Server, StatusCode};
use rand::rngs::OsRng;
use secp256k1::{Secp256k1, SecretKey};
use std::convert::Infallible;
use std::net::SocketAddr;
use tokio::net::TcpStream;
use tokio::time::{Duration, timeout};

async fn forward_rpc(node: SocketAddr, msg: &RpcMessage) -> std::io::Result<Option<RpcMessage>> {
    let mut stream = TcpStream::connect(node).await?;
    let mut rng = OsRng;
    let sk = SecretKey::new(&mut rng);
    let pk = secp256k1::PublicKey::from_secret_key(&Secp256k1::new(), &sk);
    let hs = RpcMessage::Handshake(Handshake {
        network_id: "coin".into(),
        version: 1,
        public_key: pk.serialize().to_vec(),
        signature: sign_handshake(&sk, "coin", 1),
    });
    write_rpc(&mut stream, &hs).await?;
    let _ = read_rpc(&mut stream).await?;
    write_rpc(&mut stream, msg).await?;
    match timeout(Duration::from_secs(1), read_rpc(&mut stream)).await {
        Ok(Ok(r)) => Ok(Some(r)),
        Ok(Err(e)) => Err(e),
        Err(_) => Ok(None),
    }
}

pub async fn handle_req(
    req: Request<Body>,
    node: SocketAddr,
) -> Result<Response<Body>, Infallible> {
    let mut not_found = |msg| {
        Response::builder()
            .status(StatusCode::NOT_FOUND)
            .body(Body::from(msg))
            .unwrap()
    };
    match (req.method(), req.uri().path()) {
        (&Method::GET, path) if path.starts_with("/getBalance/") => {
            let addr = path.trim_start_matches("/getBalance/");
            let msg = RpcMessage::GetBalance(GetBalance {
                address: addr.to_string(),
            });
            match forward_rpc(node, &msg).await {
                Ok(Some(resp)) => {
                    let rpc = rpc::encode_message(&resp);
                    let body = serde_json::to_vec(&rpc).unwrap();
                    Ok(Response::new(Body::from(body)))
                }
                Ok(None) => Ok(Response::new(Body::empty())),
                Err(_) => Ok(Response::builder()
                    .status(StatusCode::INTERNAL_SERVER_ERROR)
                    .body(Body::from("rpc error"))
                    .unwrap()),
            }
        }
        (&Method::GET, path) if path.starts_with("/getBlocks/") => {
            // format /getBlocks/start/end
            let parts: Vec<&str> = path.split('/').collect();
            if parts.len() != 4 {
                return Ok(not_found("bad path"));
            }
            let start: u64 = parts[2].parse().unwrap_or(0);
            let end: u64 = parts[3].parse().unwrap_or(0);
            let msg = RpcMessage::GetBlocks(GetBlocks { start, end });
            match forward_rpc(node, &msg).await {
                Ok(Some(resp)) => {
                    let rpc = rpc::encode_message(&resp);
                    let body = serde_json::to_vec(&rpc).unwrap();
                    Ok(Response::new(Body::from(body)))
                }
                Ok(None) => Ok(Response::new(Body::empty())),
                Err(_) => Ok(Response::builder()
                    .status(StatusCode::INTERNAL_SERVER_ERROR)
                    .body(Body::from("rpc error"))
                    .unwrap()),
            }
        }
        (&Method::POST, "/sendTransaction") => {
            let data = hyper::body::to_bytes(req.into_body()).await.unwrap();
            let tx: Transaction = match serde_json::from_slice(&data) {
                Ok(t) => t,
                Err(_) => {
                    return Ok(Response::builder()
                        .status(StatusCode::BAD_REQUEST)
                        .body(Body::from("invalid transaction"))
                        .unwrap());
                }
            };
            let msg = RpcMessage::Transaction(tx);
            match forward_rpc(node, &msg).await {
                Ok(Some(resp)) => {
                    let rpc = rpc::encode_message(&resp);
                    let body = serde_json::to_vec(&rpc).unwrap();
                    Ok(Response::new(Body::from(body)))
                }
                Ok(None) => Ok(Response::new(Body::empty())),
                Err(_) => Ok(Response::builder()
                    .status(StatusCode::INTERNAL_SERVER_ERROR)
                    .body(Body::from("rpc error"))
                    .unwrap()),
            }
        }
        (&Method::GET, "/mempool") => {
            let msg = RpcMessage::GetChain;
            match forward_rpc(node, &msg).await {
                Ok(Some(resp)) => {
                    let rpc = rpc::encode_message(&resp);
                    let body = serde_json::to_vec(&rpc).unwrap();
                    Ok(Response::new(Body::from(body)))
                }
                Ok(None) => Ok(Response::new(Body::empty())),
                Err(_) => Ok(Response::builder()
                    .status(StatusCode::INTERNAL_SERVER_ERROR)
                    .body(Body::from("rpc error"))
                    .unwrap()),
            }
        }
        (&Method::GET, "/status") => {
            let peers = match forward_rpc(node, &RpcMessage::GetPeers).await {
                Ok(Some(RpcMessage::Peers(p))) => p.addrs.len(),
                _ => 0,
            };
            let height = match forward_rpc(node, &RpcMessage::GetChain).await {
                Ok(Some(RpcMessage::Chain(c))) => c.blocks.len(),
                _ => 0,
            };
            let body = serde_json::to_vec(&serde_json::json!({
                "peers": peers,
                "height": height
            }))
            .unwrap();
            Ok(Response::new(Body::from(body)))
        }
        _ => Ok(not_found("not found")),
    }
}

pub async fn serve(addr: &str, node: &str) -> hyper::Result<()> {
    let node_addr: SocketAddr = node.parse().expect("invalid node addr");
    let make_svc = make_service_fn(move |_conn| {
        let node = node_addr;
        async move { Ok::<_, Infallible>(service_fn(move |req| handle_req(req, node))) }
    });
    let server = Server::bind(&addr.parse().unwrap()).serve(make_svc);
    server.await
}
