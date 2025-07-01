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
    let rt = Runtime::new();
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
