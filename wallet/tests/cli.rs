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
