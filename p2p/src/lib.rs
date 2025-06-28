use coin_proto::proto::Transaction;
use prost::Message;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::mpsc;

pub async fn start_server(
    addr: &str,
) -> tokio::io::Result<(std::net::SocketAddr, mpsc::Receiver<Transaction>)> {
    let listener = TcpListener::bind(addr).await?;
    let local = listener.local_addr()?;
    let (tx, rx) = mpsc::channel(8);
    tokio::spawn(async move {
        loop {
            if let Ok((mut socket, _)) = listener.accept().await {
                let tx = tx.clone();
                tokio::spawn(async move {
                    let mut len_buf = [0u8; 4];
                    if socket.read_exact(&mut len_buf).await.is_ok() {
                        let len = u32::from_be_bytes(len_buf) as usize;
                        let mut buf = vec![0u8; len];
                        if socket.read_exact(&mut buf).await.is_ok() {
                            if let Ok(txn) = Transaction::decode(&buf[..]) {
                                let _ = tx.send(txn).await;
                            }
                        }
                    }
                });
            }
        }
    });
    Ok((local, rx))
}

pub async fn send_transaction(addr: &str, tx: &Transaction) -> tokio::io::Result<()> {
    let mut stream = TcpStream::connect(addr).await?;
    let mut buf = Vec::new();
    tx.encode(&mut buf).unwrap();
    let len = (buf.len() as u32).to_be_bytes();
    stream.write_all(&len).await?;
    stream.write_all(&buf).await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use coin_proto::proto::Transaction;
    use tokio::time::{Duration, sleep, timeout};

    #[tokio::test]
    async fn send_and_receive() {
        let (addr, mut rx) = start_server("127.0.0.1:0").await.unwrap();
        sleep(Duration::from_millis(50)).await;
        let tx_msg = Transaction {
            sender: "a".into(),
            recipient: "b".into(),
            amount: 1,
        };
        send_transaction(&addr.to_string(), &tx_msg).await.unwrap();
        let received = timeout(Duration::from_secs(1), rx.recv())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(tx_msg, received);
    }
}
