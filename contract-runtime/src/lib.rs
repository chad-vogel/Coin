use coin_proto::Transaction;
use serde::{Deserialize, Serialize};
use serde_json;
use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};

const STATE_FILE: &str = "runtime_state.json";

fn default_state_path() -> PathBuf {
    std::env::var("CONTRACT_STATE_FILE")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from(STATE_FILE))
}
use wasmi::{Caller, Config, Engine, Linker, Module, Store};

pub struct Runtime {
    engine: Engine,
    modules: HashMap<String, Module>,
    state: HashMap<String, HashMap<i32, i64>>,
    state_path: PathBuf,
}

impl Default for Runtime {
    fn default() -> Self {
        Self::new(None)
    }
}

impl Runtime {
    fn load_state(path: &Path) -> HashMap<String, HashMap<i32, i64>> {
        if let Ok(data) = fs::read_to_string(path) {
            serde_json::from_str(&data).unwrap_or_default()
        } else {
            HashMap::new()
        }
    }

    fn save_state(&self) {
        if let Ok(data) = serde_json::to_string(&self.state) {
            let _ = fs::write(&self.state_path, data);
        }
    }

    pub fn new(state_path: Option<PathBuf>) -> Self {
        let mut config = Config::default();
        config.consume_fuel(true);
        let path = state_path.unwrap_or_else(default_state_path);
        let state = Self::load_state(&path);
        Self {
            engine: Engine::new(&config),
            modules: HashMap::new(),
            state,
            state_path: path,
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
            |caller: Caller<'_, HashMap<i32, i64>>, key: i32| {
                *caller.data().get(&key).unwrap_or(&0)
            },
        )?;
        linker.func_wrap(
            "env",
            "set",
            |mut caller: Caller<'_, HashMap<i32, i64>>, key: i32, val: i64| {
                caller.data_mut().insert(key, val);
            },
        )?;
        linker.func_wrap(
            "env",
            "get_bool",
            |caller: Caller<'_, HashMap<i32, i64>>, key: i32| {
                if *caller.data().get(&key).unwrap_or(&0) != 0 {
                    1i32
                } else {
                    0i32
                }
            },
        )?;
        linker.func_wrap(
            "env",
            "set_bool",
            |mut caller: Caller<'_, HashMap<i32, i64>>, key: i32, val: i32| {
                caller.data_mut().insert(key, if val == 0 { 0 } else { 1 });
            },
        )?;
        linker.func_wrap(
            "env",
            "get_u128",
            |caller: Caller<'_, HashMap<i32, i64>>, base: i32| {
                (
                    *caller.data().get(&base).unwrap_or(&0),
                    *caller.data().get(&(base + 1)).unwrap_or(&0),
                )
            },
        )?;
        linker.func_wrap(
            "env",
            "set_u128",
            |mut caller: Caller<'_, HashMap<i32, i64>>, base: i32, lo: i64, hi: i64| {
                caller.data_mut().insert(base, lo);
                caller.data_mut().insert(base + 1, hi);
            },
        )?;
        linker.func_wrap(
            "env",
            "get_u256",
            |caller: Caller<'_, HashMap<i32, i64>>, base: i32| {
                (
                    *caller.data().get(&base).unwrap_or(&0),
                    *caller.data().get(&(base + 1)).unwrap_or(&0),
                    *caller.data().get(&(base + 2)).unwrap_or(&0),
                    *caller.data().get(&(base + 3)).unwrap_or(&0),
                )
            },
        )?;
        linker.func_wrap(
            "env",
            "set_u256",
            |mut caller: Caller<'_, HashMap<i32, i64>>,
             base: i32,
             a: i64,
             b: i64,
             c: i64,
             d: i64| {
                caller.data_mut().insert(base, a);
                caller.data_mut().insert(base + 1, b);
                caller.data_mut().insert(base + 2, c);
                caller.data_mut().insert(base + 3, d);
            },
        )?;
        linker.func_wrap(
            "env",
            "get_address",
            |caller: Caller<'_, HashMap<i32, i64>>, base: i32| {
                (
                    *caller.data().get(&base).unwrap_or(&0),
                    *caller.data().get(&(base + 1)).unwrap_or(&0),
                    *caller.data().get(&(base + 2)).unwrap_or(&0),
                    *caller.data().get(&(base + 3)).unwrap_or(&0),
                )
            },
        )?;
        linker.func_wrap(
            "env",
            "set_address",
            |mut caller: Caller<'_, HashMap<i32, i64>>,
             base: i32,
             a: i64,
             b: i64,
             c: i64,
             d: i64| {
                caller.data_mut().insert(base, a);
                caller.data_mut().insert(base + 1, b);
                caller.data_mut().insert(base + 2, c);
                caller.data_mut().insert(base + 3, d);
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
