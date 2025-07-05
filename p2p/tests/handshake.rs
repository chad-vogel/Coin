use coin_p2p::{Node, NodeConfig, NodeType, sign_handshake, verify_handshake};
use coin_proto::Handshake;
use rand::rngs::OsRng;
use secp256k1::{PublicKey, Secp256k1, SecretKey};

#[test]
fn sign_and_verify_roundtrip() {
    let mut rng = OsRng;
    let sk = SecretKey::new(&mut rng);
    let pk = PublicKey::from_secret_key(&Secp256k1::new(), &sk);
    let sig = sign_handshake(&sk, "coin", 1);
    let hs = Handshake {
        network_id: "coin".into(),
        version: 1,
        public_key: pk.serialize().to_vec(),
        signature: sig,
    };
    assert!(verify_handshake(&hs));
}

#[test]
fn verify_detects_tampered_sig() {
    let mut rng = OsRng;
    let sk = SecretKey::new(&mut rng);
    let pk = PublicKey::from_secret_key(&Secp256k1::new(), &sk);
    let mut sig = sign_handshake(&sk, "coin", 1);
    sig[0] ^= 0x01;
    let hs = Handshake {
        network_id: "coin".into(),
        version: 1,
        public_key: pk.serialize().to_vec(),
        signature: sig,
    };
    assert!(!verify_handshake(&hs));
}

#[test]
fn verify_rejects_bad_length() {
    let mut rng = OsRng;
    let sk = SecretKey::new(&mut rng);
    let pk = PublicKey::from_secret_key(&Secp256k1::new(), &sk);
    let mut sig = sign_handshake(&sk, "coin", 1);
    sig.pop();
    let hs = Handshake {
        network_id: "coin".into(),
        version: 1,
        public_key: pk.serialize().to_vec(),
        signature: sig,
    };
    assert!(!verify_handshake(&hs));
}

#[test]
fn verify_rejects_bad_pubkey() {
    let mut rng = OsRng;
    let sk = SecretKey::new(&mut rng);
    let sig = sign_handshake(&sk, "coin", 1);
    let hs = Handshake {
        network_id: "coin".into(),
        version: 1,
        public_key: vec![0u8; 30],
        signature: sig,
    };
    assert!(!verify_handshake(&hs));
}

#[tokio::test]
async fn node_rejects_mismatched_handshake() {
    let node_a = Node::new(
        vec!["0.0.0.0:0".parse().unwrap()],
        NodeType::Wallet,
        NodeConfig {
            network_id: Some("net1".into()),
            protocol_version: Some(1),
            ..Default::default()
        },
    );
    let (addrs, _) = node_a.start().await.unwrap();
    let addr = addrs[0];
    let node_b = Node::new(
        vec!["0.0.0.0:0".parse().unwrap()],
        NodeType::Wallet,
        NodeConfig {
            network_id: Some("net2".into()),
            protocol_version: Some(1),
            ..Default::default()
        },
    );
    assert!(node_b.connect(addr).await.is_err());
    assert!(node_b.peers().await.is_empty());
    let node_c = Node::new(
        vec!["0.0.0.0:0".parse().unwrap()],
        NodeType::Wallet,
        NodeConfig {
            network_id: Some("net1".into()),
            protocol_version: Some(2),
            ..Default::default()
        },
    );
    assert!(node_c.connect(addr).await.is_err());
    assert!(node_c.peers().await.is_empty());
}
