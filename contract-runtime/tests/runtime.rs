use coin_proto::Transaction;
use contract_runtime::Runtime;
use serial_test::serial;
use tempfile;

#[test]
fn deploy_and_invoke() {
    // wasm module that returns 42 from main
    let wat = "(module (func (export \"main\") (result i32) i32.const 42))";
    let wasm = wat::parse_str(wat).expect("compile");
    let mut rt = Runtime::new();
    rt.deploy("alice", &wasm).expect("deploy");
    let mut gas = 1_000;
    let (result, _) = rt.execute("alice", &mut gas).expect("execute");
    assert_eq!(result, 42);
    assert!(gas < 1_000);
}
#[test]
fn execute_missing() {
    let mut rt = Runtime::new();
    let mut gas = 1;
    assert!(rt.execute("none", &mut gas).is_err());
}
#[test]
fn tx_helpers() {
    let wasm = wat::parse_str("(module)").unwrap();
    let deploy: Transaction = contract_runtime::ContractTxExt::deploy_tx("a", wasm.clone());
    let invoke: Transaction = contract_runtime::ContractTxExt::invoke_tx("b", "a");
    assert!(!deploy.encrypted_message.is_empty());
    assert!(!invoke.encrypted_message.is_empty());
}

#[test]
#[serial]
fn state_persistence() {
    let wat = r#"
    (module
        (import "env" "get" (func $get (param i32) (result i32)))
        (import "env" "set" (func $set (param i32 i32)))
        (func (export "main") (result i32)
            (local $v i32)
            (local.set $v (call $get (i32.const 0)))
            (call $set (i32.const 0) (i32.add (local.get $v) (i32.const 1)))
            (call $get (i32.const 0))
        )
    )
    "#;
    let wasm = wat::parse_str(wat).unwrap();
    let dir = tempfile::tempdir().unwrap();
    unsafe {
        std::env::set_var("CONTRACT_STATE_FILE", dir.path().join("state.json"));
    }
    let mut rt = Runtime::new();
    rt.deploy("alice", &wasm).unwrap();
    let mut gas = 10_000;
    assert_eq!(rt.execute("alice", &mut gas).unwrap().0, 1);
    assert!(gas < 10_000);
    let mut gas2 = 10_000;
    assert_eq!(rt.execute("alice", &mut gas2).unwrap().0, 2);
    unsafe {
        std::env::remove_var("CONTRACT_STATE_FILE");
    }
}

#[test]
#[serial]
fn state_reload_from_disk() {
    let wat = r#"
    (module
        (import "env" "get" (func $get (param i32) (result i32)))
        (import "env" "set" (func $set (param i32 i32)))
        (func (export "main") (result i32)
            (local $v i32)
            (local.set $v (call $get (i32.const 0)))
            (call $set (i32.const 0) (i32.add (local.get $v) (i32.const 1)))
            (call $get (i32.const 0))
        )
    )
    "#;
    let wasm = wat::parse_str(wat).unwrap();
    let dir = tempfile::tempdir().unwrap();
    unsafe {
        std::env::set_var("CONTRACT_STATE_FILE", dir.path().join("state.json"));
    }
    {
        let mut rt = Runtime::new();
        rt.deploy("alice", &wasm).unwrap();
        let mut gas = 10_000;
        assert_eq!(rt.execute("alice", &mut gas).unwrap().0, 1);
    }
    {
        let mut rt = Runtime::new();
        rt.deploy("alice", &wasm).unwrap();
        let mut gas = 10_000;
        assert_eq!(rt.execute("alice", &mut gas).unwrap().0, 2);
    }
    unsafe {
        std::env::remove_var("CONTRACT_STATE_FILE");
    }
}
#[test]
fn out_of_gas() {
    let wat = "(module (func (export \"main\") (result i32) i32.const 1))";
    let wasm = wat::parse_str(wat).unwrap();
    let mut rt = Runtime::new();
    rt.deploy("carol", &wasm).unwrap();
    let mut gas = 0;
    assert!(rt.execute("carol", &mut gas).is_err());
}

#[test]
fn gas_consumption() {
    // empty function that returns 0
    let wat = "(module (func (export \"main\") (result i32) i32.const 0))";
    let wasm = wat::parse_str(wat).unwrap();
    let mut rt = Runtime::new();
    rt.deploy("dave", &wasm).unwrap();
    let mut gas = 10;
    assert!(rt.execute("dave", &mut gas).is_ok());
    assert!(gas < 10);
}
