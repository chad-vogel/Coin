# Coin

This project aims to become a full-fledged coin system built with multiple crates. Network interactions are handled via a JSON-RPC interface exposed by the `coin-p2p` crate. The main `coin` crate provides core blockchain functionality. Unit tests cover all functionality and code coverage is measured using `cargo tarpaulin`.

Each coin is divisible into 100&nbsp;000&nbsp;000 units allowing for very small transfers.

## Block Structure

Blocks contain a header and a list of transactions. The header stores:

- `previous_hash` – SHA256 hash of the preceding block
- `merkle_root` – root of a Merkle tree over all transactions
- `timestamp` – seconds since the Unix epoch
- `nonce` – value modified by miners to satisfy difficulty
- `difficulty` – number of leading zero bits required in the block hash

The main crate exposes helper methods for constructing transactions and
calculating block hashes.

Old blocks can prune stored transactions once they are buried under enough
confirmations. Because only the Merkle root is included in the block hash,
discarding transaction data does not invalidate the chain.

## Mining Protocol

Mining starts with a candidate block created from all pending transactions.
Miners add a coinbase transaction paying the current block subsidy to
themselves. The subsidy starts at 50 coins and halves every `HALVING_INTERVAL`
(200,000) blocks until a maximum of 20 million coins have been issued.
After inserting the coinbase transaction, miners repeatedly hash the block
header while incrementing the `nonce` until the SHA256 digest has the required
number of leading zero bits, defined by the `difficulty` field. Once a valid
block is produced it is broadcast to peers and appended to the local chain.

### Difficulty Adjustment

`DIFFICULTY_WINDOW` recent blocks are examined each time a new block is added.
If the average spacing between them is less than `TARGET_BLOCK_TIME` the
difficulty is increased; if it is greater, the difficulty decreases. This keeps
block production close to the target interval.

## Running a Miner

The `coin-p2p` crate provides a simple command line interface. A miner can be
started with:

```bash
cargo run -p coin-p2p -- --port <PORT> --node-type miner
```
Replace `<PORT>` with the TCP port to listen on. Additional nodes can be run as
`wallet` or `verifier` types using the same command structure:

```bash
cargo run -p coin-p2p -- --port 9000 --node-type wallet
```

## Configuration File

Nodes load settings from a YAML file passed with `--config` (defaults to
`config.yaml`). The repository includes an annotated example at
`config.example.yaml`:

```yaml
# Example configuration for coin-p2p
listeners:
  - ip: "0.0.0.0"
    port: 9000
wallet_address: "1BvgsfsZQVtkLS69NvGF8rw6NZW2ShJQHr"
node_type: Miner
block_dir: "blocks"
seed_peers:
  - "127.0.0.1:9001"
```

Field descriptions:

- `listeners` – network interfaces and ports to bind.
- `wallet_address` – optional address used when mining rewards are paid.
- `node_type` – one of `Miner`, `Wallet`, or `Verifier`.
- `block_dir` – directory where block files are stored.
- `seed_peers` – peers contacted on startup for bootstrapping.

## Tor Usage

Nodes can route outbound connections through a SOCKS5 proxy such as the one
provided by a local Tor daemon. Start Tor locally and set `tor_proxy` either in
`config.yaml` or via `--tor-proxy` when running `coin-p2p`:

```bash
tor &
cargo run -p coin-p2p -- --tor-proxy 127.0.0.1:9050
```

Transactions and block requests will then be tunneled through Tor.

## Wallet Basics

The `coin-wallet` crate offers a BIP32 HD wallet implementation.
Generate a new wallet with a random mnemonic and derive addresses as shown
below:

```rust
use coin_wallet::Wallet;

let wallet = Wallet::generate("").unwrap();
println!("Mnemonic: {}", wallet.mnemonic().unwrap());

let first = wallet.derive_address("m/0'/0/0").unwrap();
println!("First address: {}", first);
```

Existing phrases can be imported with `Wallet::from_mnemonic` and private or
public keys are derived using standard BIP32 paths. Transactions may be signed
by converting a derived key into a `k256::ecdsa::SigningKey`:

```rust
use coin_wallet::Wallet;
use coin::new_transaction_with_fee;
use k256::ecdsa::{signature::Signer, SigningKey};
use sha2::{Digest, Sha256};

let wallet = Wallet::generate("").unwrap();
let tx = new_transaction_with_fee("alice", "bob", 5, 0);
let hash = Sha256::digest(tx.hash().as_bytes());
let child = wallet.derive_priv("m/0'/0/0").unwrap();
let signer: SigningKey = (&child).into();
let sig = signer.sign(&hash);
```

## Development

```bash
# Format and test
cargo fmt
cargo test

# Run coverage (fails below 90%)
cargo tarpaulin --workspace --timeout 60 --fail-under 90
```

## License

This project is licensed under the [MIT License](LICENSE).

