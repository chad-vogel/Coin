use coin_proto::Transaction;
use serde::{Deserialize, Serialize};
use serde_json;
use std::collections::{HashMap, hash_map::Entry};
use std::fs;

const STATE_FILE: &str = "runtime_state.json";

fn state_path() -> String {
    std::env::var("CONTRACT_STATE_FILE").unwrap_or_else(|_| STATE_FILE.to_string())
}
use wasmi::{Caller, Config, Engine, Linker, Module, Store};

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub enum Value {
    I64(i64),
    U256([u64; 4]),
}

impl Default for Value {
    fn default() -> Self {
        Value::I64(0)
    }
}

pub struct Runtime {
    engine: Engine,
    modules: HashMap<String, Module>,
    state: HashMap<String, HashMap<i32, Value>>,
}

impl Default for Runtime {
    fn default() -> Self {
        Self::new()
    }
}

impl Runtime {
    fn load_state() -> HashMap<String, HashMap<i32, Value>> {
        let path = state_path();
        if let Ok(data) = fs::read_to_string(path) {
            serde_json::from_str(&data).unwrap_or_default()
        } else {
            HashMap::new()
        }
    }

    fn save_state(&self) {
        if let Ok(data) = serde_json::to_string(&self.state) {
            let path = state_path();
            let _ = fs::write(path, data);
        }
    }

    pub fn new() -> Self {
        let mut config = Config::default();
        config.consume_fuel(true);
        Self {
            engine: Engine::new(&config),
            modules: HashMap::new(),
            state: Self::load_state(),
        }
    }

    pub fn deploy(&mut self, addr: &str, wasm: &[u8]) -> anyhow::Result<()> {
        let module = Module::new(&self.engine, wasm)?;
        self.modules.insert(addr.to_string(), module);
        Ok(())
    }

    pub fn execute(&mut self, addr: &str, gas: &mut u64) -> anyhow::Result<i64> {
        let module = self
            .modules
            .get(addr)
            .ok_or_else(|| anyhow::anyhow!("module not found"))?;

        let state = self.state.get(addr).cloned().unwrap_or_default();
        let mut store = Store::new(&self.engine, state);
        if *gas > 0 {
            store.add_fuel(*gas).map_err(|e| anyhow::anyhow!(e))?;
        }
        let mut linker = Linker::new(&self.engine);
        linker.func_wrap(
            "env",
            "get",
            |caller: Caller<'_, HashMap<i32, Value>>, key: i32| match caller.data().get(&key) {
                Some(Value::I64(v)) => *v,
                _ => 0,
            },
        )?;
        linker.func_wrap(
            "env",
            "set",
            |mut caller: Caller<'_, HashMap<i32, Value>>, key: i32, val: i64| {
                caller.data_mut().insert(key, Value::I64(val));
            },
        )?;
        linker.func_wrap(
            "env",
            "get_u256",
            |caller: Caller<'_, HashMap<i32, Value>>, key: i32, idx: i32| match caller
                .data()
                .get(&key)
            {
                Some(Value::U256(arr)) => arr.get(idx as usize).copied().unwrap_or(0) as i64,
                _ => 0,
            },
        )?;
        linker.func_wrap(
            "env",
            "set_u256",
            |mut caller: Caller<'_, HashMap<i32, Value>>, key: i32, idx: i32, val: i64| {
                let idx = idx as usize;
                let val_u64 = val as u64;
                match caller.data_mut().entry(key) {
                    Entry::Occupied(mut e) => match e.get_mut() {
                        Value::U256(arr) => {
                            if idx < 4 {
                                arr[idx] = val_u64;
                            }
                        }
                        v => {
                            let mut arr = [0u64; 4];
                            if idx < 4 {
                                arr[idx] = val_u64;
                            }
                            *v = Value::U256(arr);
                        }
                    },
                    Entry::Vacant(v) => {
                        let mut arr = [0u64; 4];
                        if idx < 4 {
                            arr[idx] = val_u64;
                        }
                        v.insert(Value::U256(arr));
                    }
                }
            },
        )?;
        let instance = linker.instantiate(&mut store, module)?.start(&mut store)?;
        let func = instance.get_typed_func::<(), i64>(&store, "main")?;
        let result = match func.call(&mut store, ()) {
            Ok(res) => res,
            Err(e) => {
                if format!("{e}").contains("all fuel consumed") {
                    return Err(anyhow::anyhow!("gas limit exceeded"));
                }
                return Err(anyhow::anyhow!(e));
            }
        };
        if let Some(consumed) = store.fuel_consumed() {
            if consumed > *gas {
                *gas = 0;
                return Err(anyhow::anyhow!("gas limit exceeded"));
            }
            *gas -= consumed;
        }
        self.state.insert(addr.to_string(), store.data().clone());
        self.save_state();
        Ok(result)
    }

    pub fn simulate(
        &self,
        addr: &str,
        gas: &mut u64,
    ) -> anyhow::Result<(i64, HashMap<i32, Value>)> {
        let module = self
            .modules
            .get(addr)
            .ok_or_else(|| anyhow::anyhow!("module not found"))?;

        let state = self.state.get(addr).cloned().unwrap_or_default();
        let mut store = Store::new(&self.engine, state);
        if *gas > 0 {
            store.add_fuel(*gas).map_err(|e| anyhow::anyhow!(e))?;
        }
        let mut linker = Linker::new(&self.engine);
        linker.func_wrap(
            "env",
            "get",
            |caller: Caller<'_, HashMap<i32, Value>>, key: i32| match caller.data().get(&key) {
                Some(Value::I64(v)) => *v,
                _ => 0,
            },
        )?;
        linker.func_wrap(
            "env",
            "set",
            |mut caller: Caller<'_, HashMap<i32, Value>>, key: i32, val: i64| {
                caller.data_mut().insert(key, Value::I64(val));
            },
        )?;
        linker.func_wrap(
            "env",
            "get_u256",
            |caller: Caller<'_, HashMap<i32, Value>>, key: i32, idx: i32| match caller
                .data()
                .get(&key)
            {
                Some(Value::U256(arr)) => arr.get(idx as usize).copied().unwrap_or(0) as i64,
                _ => 0,
            },
        )?;
        linker.func_wrap(
            "env",
            "set_u256",
            |mut caller: Caller<'_, HashMap<i32, Value>>, key: i32, idx: i32, val: i64| {
                let idx = idx as usize;
                let val_u64 = val as u64;
                match caller.data_mut().entry(key) {
                    Entry::Occupied(mut e) => match e.get_mut() {
                        Value::U256(arr) => {
                            if idx < 4 {
                                arr[idx] = val_u64;
                            }
                        }
                        v => {
                            let mut arr = [0u64; 4];
                            if idx < 4 {
                                arr[idx] = val_u64;
                            }
                            *v = Value::U256(arr);
                        }
                    },
                    Entry::Vacant(v) => {
                        let mut arr = [0u64; 4];
                        if idx < 4 {
                            arr[idx] = val_u64;
                        }
                        v.insert(Value::U256(arr));
                    }
                }
            },
        )?;
        let instance = linker.instantiate(&mut store, module)?.start(&mut store)?;
        let func = instance.get_typed_func::<(), i64>(&store, "main")?;
        let result = match func.call(&mut store, ()) {
            Ok(res) => res,
            Err(e) => {
                if format!("{e}").contains("all fuel consumed") {
                    return Err(anyhow::anyhow!("gas limit exceeded"));
                }
                return Err(anyhow::anyhow!(e));
            }
        };
        if let Some(consumed) = store.fuel_consumed() {
            if consumed > *gas {
                *gas = 0;
                return Err(anyhow::anyhow!("gas limit exceeded"));
            }
            *gas -= consumed;
        }
        Ok((result, store.data().clone()))
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct DeployPayload {
    pub wasm: Vec<u8>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct InvokePayload {
    pub contract: String,
}

pub trait ContractTxExt {
    fn deploy_tx(addr: impl Into<String>, wasm: Vec<u8>) -> Self;
    fn invoke_tx(sender: impl Into<String>, contract: impl Into<String>) -> Self;
}

impl ContractTxExt for Transaction {
    fn deploy_tx(addr: impl Into<String>, wasm: Vec<u8>) -> Self {
        Transaction {
            sender: addr.into(),
            recipient: String::new(),
            amount: 0,
            fee: 0,
            signature: Vec::new(),
            encrypted_message: serde_json::to_vec(&DeployPayload { wasm }).unwrap(),
            inputs: Vec::new(),
            outputs: Vec::new(),
        }
    }

    fn invoke_tx(sender: impl Into<String>, contract: impl Into<String>) -> Self {
        Transaction {
            sender: sender.into(),
            recipient: String::new(),
            amount: 0,
            fee: 0,
            signature: Vec::new(),
            encrypted_message: serde_json::to_vec(&InvokePayload {
                contract: contract.into(),
            })
            .unwrap(),
            inputs: Vec::new(),
            outputs: Vec::new(),
        }
    }
}
