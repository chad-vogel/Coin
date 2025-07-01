use coin_p2p::rpc::{self, RpcMessage};
use coin_proto::{GetBalance, GetBlocks, Transaction};
use hyper::service::{make_service_fn, service_fn};
use hyper::{Body, Method, Request, Response, Server, StatusCode};
use std::convert::Infallible;

pub async fn handle_req(req: Request<Body>) -> Result<Response<Body>, Infallible> {
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
            let rpc = rpc::encode_message(&msg);
            let body = serde_json::to_vec(&rpc).unwrap();
            Ok(Response::new(Body::from(body)))
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
            let rpc = rpc::encode_message(&msg);
            let body = serde_json::to_vec(&rpc).unwrap();
            Ok(Response::new(Body::from(body)))
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
            let rpc = rpc::encode_message(&msg);
            let body = serde_json::to_vec(&rpc).unwrap();
            Ok(Response::new(Body::from(body)))
        }
        _ => Ok(not_found("not found")),
    }
}

pub async fn serve(addr: &str) -> hyper::Result<()> {
    let make_svc = make_service_fn(|_conn| async { Ok::<_, Infallible>(service_fn(handle_req)) });
    let server = Server::bind(&addr.parse().unwrap()).serve(make_svc);
    server.await
}
