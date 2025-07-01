use coin_proto::Transaction;
use serde::{Deserialize, Serialize};
use serde_json;
use wasmi::{Engine, Linker, Module, Store};

pub struct Runtime {
    engine: Engine,
    modules: std::collections::HashMap<String, Module>,
}

impl Default for Runtime {
    fn default() -> Self {
        Self::new()
    }
}

impl Runtime {
    pub fn new() -> Self {
        Self {
            engine: Engine::default(),
            modules: std::collections::HashMap::new(),
        }
    }

    pub fn deploy(&mut self, addr: &str, wasm: &[u8]) -> anyhow::Result<()> {
        let module = Module::new(&self.engine, wasm)?;
        self.modules.insert(addr.to_string(), module);
        Ok(())
    }

    pub fn execute(&self, addr: &str) -> anyhow::Result<i32> {
        let module = self
            .modules
            .get(addr)
            .ok_or_else(|| anyhow::anyhow!("module not found"))?;
        let mut store = Store::new(&self.engine, ());
        let mut linker = Linker::new(&self.engine);
        let instance = linker.instantiate(&mut store, module)?.start(&mut store)?;
        let func = instance.get_typed_func::<(), i32>(&store, "main")?;
        Ok(func.call(&mut store, ())?)
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
