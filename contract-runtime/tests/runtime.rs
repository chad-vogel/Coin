use coin_proto::Transaction;
use contract_runtime::Runtime;

#[test]
fn deploy_and_invoke() {
    // wasm module that returns 42 from main
    let wat = "(module (func (export \"main\") (result i32) i32.const 42))";
    let wasm = wat::parse_str(wat).expect("compile");
    let mut rt = Runtime::new();
    rt.deploy("alice", &wasm).expect("deploy");
    let result = rt.execute("alice").expect("execute");
    assert_eq!(result, 42);
}
#[test]
fn execute_missing() {
    let mut rt = Runtime::new();
    assert!(rt.execute("none").is_err());
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
    let mut rt = Runtime::new();
    rt.deploy("alice", &wasm).unwrap();
    assert_eq!(rt.execute("alice").unwrap(), 1);
    assert_eq!(rt.execute("alice").unwrap(), 2);
}
