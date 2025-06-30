use assert_cmd::Command;
use tempfile;

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
    assert_eq!(addr.trim().len(), 34);
}
