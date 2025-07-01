use coin_proto::Transaction;
use serde::{Deserialize, Serialize};
use serde_json;
use std::collections::HashMap;
use wasmi::core::TrapCode;
use wasmi::{Caller, Config, Engine, Linker, Module, Store};

pub struct Runtime {
    engine: Engine,
    modules: HashMap<String, Module>,
    state: HashMap<String, HashMap<i32, i32>>,
}

impl Default for Runtime {
    fn default() -> Self {
        Self::new()
    }
}

impl Runtime {
    pub fn new() -> Self {
        let mut config = Config::default();
        config.consume_fuel(true);
        Self {
            engine: Engine::new(&config),
            modules: HashMap::new(),
            state: HashMap::new(),
        }
    }

    pub fn deploy(&mut self, addr: &str, wasm: &[u8]) -> anyhow::Result<()> {
        let module = Module::new(&self.engine, wasm)?;
        self.modules.insert(addr.to_string(), module);
        Ok(())
    }

    pub fn execute(&mut self, addr: &str, gas: &mut u64) -> anyhow::Result<i32> {
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
            |caller: Caller<'_, HashMap<i32, i32>>, key: i32| {
                *caller.data().get(&key).unwrap_or(&0)
            },
        )?;
        linker.func_wrap(
            "env",
            "set",
            |mut caller: Caller<'_, HashMap<i32, i32>>, key: i32, val: i32| {
                caller.data_mut().insert(key, val);
            },
        )?;
        let instance = linker.instantiate(&mut store, module)?.start(&mut store)?;
        let func = instance.get_typed_func::<(), i32>(&store, "main")?;
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
