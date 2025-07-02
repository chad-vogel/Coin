#![cfg(feature = "cli-tests")]

use assert_cmd::Command;
use tempfile;

#[cfg(not(tarpaulin))]
#[test]
fn generate_and_derive() {
    let dir = tempfile::tempdir().unwrap();
    let wallet = dir.path().join("test.mnemonic");
    Command::cargo_bin("cli")
        .unwrap()
        .args(["--wallet", wallet.to_str().unwrap(), "generate"])
        .assert()
        .success();
    assert!(wallet.exists());
    let out = Command::cargo_bin("cli")
        .unwrap()
        .args(["--wallet", wallet.to_str().unwrap(), "derive", "m/0'/0/0"])
        .output()
        .unwrap();
    assert!(out.status.success());
    let addr = String::from_utf8(out.stdout).unwrap();
    assert!(matches!(addr.trim().len(), 33 | 34));
}

#[cfg(not(tarpaulin))]
#[test]
fn import_and_derive() {
    let dir = tempfile::tempdir().unwrap();
    let wallet = dir.path().join("import.mnemonic");
    let phrase = coin_wallet::Wallet::generate("")
        .unwrap()
        .mnemonic()
        .unwrap()
        .phrase()
        .to_string();
    Command::cargo_bin("cli")
        .unwrap()
        .args(["--wallet", wallet.to_str().unwrap(), "import", &phrase])
        .assert()
        .success();
    let out = Command::cargo_bin("cli")
        .unwrap()
        .args(["--wallet", wallet.to_str().unwrap(), "derive", "m/0'/0/1"])
        .output()
        .unwrap();
    assert!(out.status.success());
    let addr = String::from_utf8(out.stdout).unwrap();
    assert!(matches!(addr.trim().len(), 33 | 34));
}

#[cfg(not(tarpaulin))]
#[test]
fn generate_and_derive_encrypted() {
    let dir = tempfile::tempdir().unwrap();
    let wallet = dir.path().join("enc.mnemonic");
    Command::cargo_bin("cli")
        .unwrap()
        .args([
            "--wallet",
            wallet.to_str().unwrap(),
            "--password",
            "secret",
            "generate",
        ])
        .assert()
        .success();
    assert!(wallet.exists());
    let contents = std::fs::read_to_string(&wallet).unwrap();
    assert!(!contents.contains(' '));
    let out = Command::cargo_bin("cli")
        .unwrap()
        .args([
            "--wallet",
            wallet.to_str().unwrap(),
            "--password",
            "secret",
            "derive",
            "m/0'/0/0",
        ])
        .output()
        .unwrap();
    assert!(out.status.success());
    let addr = String::from_utf8(out.stdout).unwrap();
    assert!(matches!(addr.trim().len(), 33 | 34));
}

#[cfg(not(tarpaulin))]
#[test]
fn stake_and_unstake_via_rpc() {
    use coin_p2p::rpc::{RpcMessage, read_rpc, write_rpc};
    use coin_proto::Handshake;
    use tokio::net::TcpListener;

    let dir = tempfile::tempdir().unwrap();
    let wallet = dir.path().join("stake.mnemonic");
    Command::cargo_bin("cli")
        .unwrap()
        .args(["--wallet", wallet.to_str().unwrap(), "generate"])
        .assert()
        .success();

    let rt = tokio::runtime::Runtime::new().unwrap();
    let listener = rt.block_on(TcpListener::bind("127.0.0.1:0")).unwrap();
    let addr = listener.local_addr().unwrap();

    let server = std::thread::spawn(move || {
        rt.block_on(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let _ = read_rpc(&mut stream).await.unwrap();
            let reply = RpcMessage::Handshake(Handshake {
                network_id: "coin".into(),
                version: 1,
                public_key: vec![],
                signature: vec![],
            });
            write_rpc(&mut stream, &reply).await.unwrap();
            match read_rpc(&mut stream).await.unwrap() {
                RpcMessage::Stake(s) => {
                    assert_eq!(s.amount, 5);
                    assert!(!s.address.is_empty());
                }
                other => panic!("unexpected {:?}", other),
            }

            let (mut stream, _) = listener.accept().await.unwrap();
            let _ = read_rpc(&mut stream).await.unwrap();
            let reply = RpcMessage::Handshake(Handshake {
                network_id: "coin".into(),
                version: 1,
                public_key: vec![],
                signature: vec![],
            });
            write_rpc(&mut stream, &reply).await.unwrap();
            match read_rpc(&mut stream).await.unwrap() {
                RpcMessage::Unstake(u) => {
                    assert!(!u.address.is_empty());
                }
                other => panic!("unexpected {:?}", other),
            }
        });
    });

    Command::cargo_bin("cli")
        .unwrap()
        .args([
            "--wallet",
            wallet.to_str().unwrap(),
            "stake",
            "--amount",
            "5",
            "--path",
            "m/0'/0/0",
            "--node",
            &addr.to_string(),
        ])
        .assert()
        .success();

    Command::cargo_bin("cli")
        .unwrap()
        .args([
            "--wallet",
            wallet.to_str().unwrap(),
            "unstake",
            "--path",
            "m/0'/0/0",
            "--node",
            &addr.to_string(),
        ])
        .assert()
        .success();

    server.join().unwrap();
}
