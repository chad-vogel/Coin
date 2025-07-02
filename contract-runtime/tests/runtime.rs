use coin_proto::Transaction;
use contract_runtime::Runtime;
use serial_test::serial;
use tempfile;

#[test]
fn deploy_and_invoke() {
    // wasm module that returns 42 from main
    let wat = "(module (func (export \"main\") (result i64) i64.const 42))";
    let wasm = wat::parse_str(wat).expect("compile");
    let mut rt = Runtime::new();
    rt.deploy("alice", &wasm).expect("deploy");
    let mut gas = 1_000;
    let result = rt.execute("alice", &mut gas).expect("execute");
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
        (import "env" "get" (func $get (param i32) (result i64)))
        (import "env" "set" (func $set (param i32 i64)))
        (func (export "main") (result i64)
            (local $v i64)
            (local.set $v (call $get (i32.const 0)))
            (call $set (i32.const 0) (i64.add (local.get $v) (i64.const 1)))
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
    assert_eq!(rt.execute("alice", &mut gas).unwrap(), 1);
    assert!(gas < 10_000);
    let mut gas2 = 10_000;
    assert_eq!(rt.execute("alice", &mut gas2).unwrap(), 2);
    unsafe {
        std::env::remove_var("CONTRACT_STATE_FILE");
    }
}

#[test]
#[serial]
fn state_reload_from_disk() {
    let wat = r#"
    (module
        (import "env" "get" (func $get (param i32) (result i64)))
        (import "env" "set" (func $set (param i32 i64)))
        (func (export "main") (result i64)
            (local $v i64)
            (local.set $v (call $get (i32.const 0)))
            (call $set (i32.const 0) (i64.add (local.get $v) (i64.const 1)))
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
        assert_eq!(rt.execute("alice", &mut gas).unwrap(), 1);
    }
    {
        let mut rt = Runtime::new();
        rt.deploy("alice", &wasm).unwrap();
        let mut gas = 10_000;
        assert_eq!(rt.execute("alice", &mut gas).unwrap(), 2);
    }
    unsafe {
        std::env::remove_var("CONTRACT_STATE_FILE");
    }
}
#[test]
fn out_of_gas() {
    let wat = "(module (func (export \"main\") (result i64) i64.const 1))";
    let wasm = wat::parse_str(wat).unwrap();
    let mut rt = Runtime::new();
    rt.deploy("carol", &wasm).unwrap();
    let mut gas = 0;
    assert!(rt.execute("carol", &mut gas).is_err());
}

#[test]
fn gas_consumption() {
    // empty function that returns 0
    let wat = "(module (func (export \"main\") (result i64) i64.const 0))";
    let wasm = wat::parse_str(wat).unwrap();
    let mut rt = Runtime::new();
    rt.deploy("dave", &wasm).unwrap();
    let mut gas = 10;
    assert!(rt.execute("dave", &mut gas).is_ok());
    assert!(gas < 10);
}

#[test]
fn simulate_does_not_persist() {
    let wat = "(module (import \"env\" \"set\" (func $set (param i32 i64))) (func (export \"main\") (result i64) (call $set (i32.const 0) (i64.const 7)) i64.const 0))";
    let wasm = wat::parse_str(wat).unwrap();
    let mut rt = Runtime::new();
    rt.deploy("sim", &wasm).unwrap();
    let mut gas = 1000;
    let (_, state) = rt.simulate("sim", &mut gas).unwrap();
    assert!(matches!(
        state.get(&0),
        Some(contract_runtime::Value::I64(7))
    ));
    assert!(rt.simulate("sim", &mut gas).is_ok());
    assert!(rt.execute("sim", &mut gas).unwrap() == 0);
    assert!(matches!(
        rt.simulate("sim", &mut gas).unwrap().1.get(&0),
        Some(contract_runtime::Value::I64(7))
    ));
}

#[test]
fn u256_host_functions() {
    let wat = r#"
    (module
        (import "env" "set_u256" (func $set (param i32 i32 i64)))
        (import "env" "get_u256" (func $get (param i32 i32) (result i64)))
        (func (export "main") (result i64)
            (call $set (i32.const 0) (i32.const 0) (i64.const 5))
            (call $get (i32.const 0) (i32.const 0))
        )
    )
    "#;
    let wasm = wat::parse_str(wat).unwrap();
    let mut rt = Runtime::new();
    rt.deploy("u256", &wasm).unwrap();
    let mut gas = 1000;
    assert_eq!(rt.execute("u256", &mut gas).unwrap(), 5);
    if let Some(contract_runtime::Value::U256(parts)) =
        rt.simulate("u256", &mut gas).unwrap().1.get(&0).cloned()
    {
        assert_eq!(parts[0], 5);
    } else {
        panic!("missing u256 value");
    }
}

#[test]
fn simulate_out_of_gas_error() {
    let wat = "(module (func (export \"main\") (result i64) i64.const 1))";
    let wasm = wat::parse_str(wat).unwrap();
    let mut rt = Runtime::new();
    rt.deploy("oops", &wasm).unwrap();
    let mut gas = 0;
    assert!(rt.simulate("oops", &mut gas).is_err());
}
