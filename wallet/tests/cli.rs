#![cfg(feature = "cli-tests")]

use assert_cmd::Command;
use coin_p2p::{
    rpc::{RpcMessage, RpcTransport},
    sign_handshake,
};
use coin_proto::{Handshake, Stake, Unstake};
use secp256k1::{PublicKey, Secp256k1, SecretKey};
use tempfile;
use tokio::net::TcpListener;

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
#[tokio::test]
async fn stake_and_unstake_commands() {
    let dir = tempfile::tempdir().unwrap();
    let wallet_path = dir.path().join("stake.mnemonic");
    let wallet = coin_wallet::Wallet::generate("").unwrap();
    std::fs::write(&wallet_path, wallet.mnemonic().unwrap().phrase()).unwrap();
    let addr = wallet.derive_address("m/0'/0/0").unwrap();

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let srv_addr = listener.local_addr().unwrap();

    let server = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        if let RpcMessage::Handshake(_) = stream.read_rpc().await.unwrap() {
            let sk = SecretKey::from_slice(&[1u8; 32]).unwrap();
            let pk = PublicKey::from_secret_key(&Secp256k1::new(), &sk);
            let resp = RpcMessage::Handshake(Handshake {
                network_id: "coin".into(),
                version: 1,
                public_key: pk.serialize().to_vec(),
                signature: sign_handshake(&sk, "coin", 1),
            });
            stream.write_rpc(&resp).await.unwrap();
        }
        if let RpcMessage::Stake(s) = stream.read_rpc().await.unwrap() {
            assert_eq!(s.address, addr);
            assert_eq!(s.amount, 5);
        } else {
            panic!("expected stake msg");
        }

        let (mut stream, _) = listener.accept().await.unwrap();
        if let RpcMessage::Handshake(_) = stream.read_rpc().await.unwrap() {
            let sk = SecretKey::from_slice(&[1u8; 32]).unwrap();
            let pk = PublicKey::from_secret_key(&Secp256k1::new(), &sk);
            let resp = RpcMessage::Handshake(Handshake {
                network_id: "coin".into(),
                version: 1,
                public_key: pk.serialize().to_vec(),
                signature: sign_handshake(&sk, "coin", 1),
            });
            stream.write_rpc(&resp).await.unwrap();
        }
        if let RpcMessage::Unstake(u) = stream.read_rpc().await.unwrap() {
            assert_eq!(u.address, addr);
        } else {
            panic!("expected unstake msg");
        }
    });

    Command::cargo_bin("cli")
        .unwrap()
        .args([
            "--wallet",
            wallet_path.to_str().unwrap(),
            "stake",
            "5",
            "m/0'/0/0",
            "--node",
            &srv_addr.to_string(),
        ])
        .assert()
        .success();

    Command::cargo_bin("cli")
        .unwrap()
        .args([
            "--wallet",
            wallet_path.to_str().unwrap(),
            "unstake",
            "m/0'/0/0",
            "--node",
            &srv_addr.to_string(),
        ])
        .assert()
        .success();

    server.await.unwrap();
}
