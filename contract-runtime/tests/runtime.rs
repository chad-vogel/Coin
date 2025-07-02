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
#[serial]
fn bool_storage() {
    let wat = r#"
    (module
        (import "env" "get_bool" (func $get (param i32) (result i32)))
        (import "env" "set_bool" (func $set (param i32 i32)))
        (func (export "main") (result i64)
            (local $v i32)
            (local.set $v (call $get (i32.const 0)))
            (call $set (i32.const 0) (i32.eqz (local.get $v)))
            (i64.extend_i32_u (call $get (i32.const 0)))
        )
    )
    "#;
    let wasm = wat::parse_str(wat).unwrap();
    let dir = tempfile::tempdir().unwrap();
    unsafe {
        std::env::set_var("CONTRACT_STATE_FILE", dir.path().join("state.json"));
    }
    let mut rt = Runtime::new();
    rt.deploy("bob", &wasm).unwrap();
    let mut gas = 10_000;
    assert_eq!(rt.execute("bob", &mut gas).unwrap(), 1);
    let mut gas2 = 10_000;
    assert_eq!(rt.execute("bob", &mut gas2).unwrap(), 0);
    unsafe {
        std::env::remove_var("CONTRACT_STATE_FILE");
    }
}

#[test]
#[serial]
fn u128_storage() {
    let wat = r#"
    (module
        (import "env" "get_u128" (func $get (param i32) (result i64 i64)))
        (import "env" "set_u128" (func $set (param i32 i64 i64)))
        (func (export "main") (result i64)
            (local $lo i64)
            (local $hi i64)
            (call $get (i32.const 0))
            (local.set $hi)
            (local.set $lo)
            (if (i64.eq (local.get $lo) (i64.const 0))
                (then (call $set (i32.const 0) (i64.const 1) (i64.const 0)))
                (else (call $set (i32.const 0) (i64.const 2) (i64.const 0)))
            )
            (call $get (i32.const 0))
            (local.set $hi)
            (local.set $lo)
            (local.get $lo)
        )
    )
    "#;
    let wasm = wat::parse_str(wat).unwrap();
    let dir = tempfile::tempdir().unwrap();
    unsafe {
        std::env::set_var("CONTRACT_STATE_FILE", dir.path().join("state.json"));
    }
    let mut rt = Runtime::new();
    rt.deploy("eve", &wasm).unwrap();
    let mut gas = 10_000;
    assert_eq!(rt.execute("eve", &mut gas).unwrap(), 1);
    let mut gas2 = 10_000;
    assert_eq!(rt.execute("eve", &mut gas2).unwrap(), 2);
    unsafe {
        std::env::remove_var("CONTRACT_STATE_FILE");
    }
}

#[test]
#[serial]
fn u256_storage() {
    let wat = r#"
    (module
        (import "env" "get_u256" (func $get (param i32) (result i64 i64 i64 i64)))
        (import "env" "set_u256" (func $set (param i32 i64 i64 i64 i64)))
        (func (export "main") (result i64)
            (local $a i64)
            (local $b i64)
            (local $c i64)
            (local $d i64)
            (call $get (i32.const 0))
            (local.set $d)
            (local.set $c)
            (local.set $b)
            (local.set $a)
            (if (i64.eq (local.get $a) (i64.const 0))
                (then (call $set (i32.const 0) (i64.const 1) (i64.const 0) (i64.const 0) (i64.const 0)))
                (else (call $set (i32.const 0) (i64.const 2) (i64.const 0) (i64.const 0) (i64.const 0)))
            )
            (call $get (i32.const 0))
            (local.set $d)
            (local.set $c)
            (local.set $b)
            (local.set $a)
            (local.get $a)
        )
    )
    "#;
    let wasm = wat::parse_str(wat).unwrap();
    let dir = tempfile::tempdir().unwrap();
    unsafe {
        std::env::set_var("CONTRACT_STATE_FILE", dir.path().join("state.json"));
    }
    let mut rt = Runtime::new();
    rt.deploy("frank", &wasm).unwrap();
    let mut gas = 10_000;
    assert_eq!(rt.execute("frank", &mut gas).unwrap(), 1);
    let mut gas2 = 10_000;
    assert_eq!(rt.execute("frank", &mut gas2).unwrap(), 2);
    unsafe {
        std::env::remove_var("CONTRACT_STATE_FILE");
    }
}

#[test]
#[serial]
fn address_storage() {
    let wat = r#"
    (module
        (import "env" "get_address" (func $get (param i32) (result i64 i64 i64 i64)))
        (import "env" "set_address" (func $set (param i32 i64 i64 i64 i64)))
        (func (export "main") (result i64)
            (local $a i64)
            (local $b i64)
            (local $c i64)
            (local $d i64)
            (call $get (i32.const 0))
            (local.set $d)
            (local.set $c)
            (local.set $b)
            (local.set $a)
            (if (i64.eq (local.get $a) (i64.const 0))
                (then (call $set (i32.const 0) (i64.const 11) (i64.const 22) (i64.const 33) (i64.const 44)))
                (else (call $set (i32.const 0) (i64.const 55) (i64.const 66) (i64.const 77) (i64.const 88)))
            )
            (call $get (i32.const 0))
            (local.set $d)
            (local.set $c)
            (local.set $b)
            (local.set $a)
            (local.get $a)
        )
    )
    "#;
    let wasm = wat::parse_str(wat).unwrap();
    let dir = tempfile::tempdir().unwrap();
    unsafe {
        std::env::set_var("CONTRACT_STATE_FILE", dir.path().join("state.json"));
    }
    let mut rt = Runtime::new();
    rt.deploy("gina", &wasm).unwrap();
    let mut gas = 10_000;
    assert_eq!(rt.execute("gina", &mut gas).unwrap(), 11);
    let mut gas2 = 10_000;
    assert_eq!(rt.execute("gina", &mut gas2).unwrap(), 55);
    unsafe {
        std::env::remove_var("CONTRACT_STATE_FILE");
    }
}
