# Coin

This project aims to become a full-fledged coin system built with multiple crates. Protocol buffer definitions live in `coin-proto` and networking utilities live in `coin-p2p`. The main `coin` crate provides core blockchain functionality. Unit tests cover all functionality and code coverage is measured using `cargo tarpaulin`.

## Block Structure

Blocks contain a header and a list of transactions. The header stores:

- `previous_hash` – SHA256 hash of the preceding block
- `merkle_root` – hash of all transactions in the block
- `timestamp` – seconds since the Unix epoch
- `nonce` – value modified by miners to satisfy difficulty
- `difficulty` – number of leading zero bytes required in the block hash

The main crate exposes helper methods for constructing transactions and
calculating block hashes.

## Mining Protocol

Mining repeatedly hashes a candidate block while incrementing the `nonce`
until the SHA256 digest contains the required number of leading zero bytes.
Miners insert a coinbase transaction paying `BLOCK_SUBSIDY` to themselves
before starting the search. Once a valid block is found it is broadcast to
peers and appended to the local chain.

### Difficulty Adjustment

`DIFFICULTY_WINDOW` recent blocks are examined each time a new block is added.
If the average time between them is less than `TARGET_BLOCK_TIME` the
difficulty is increased; if it is greater, the difficulty decreases. This keeps
block production close to the target interval.

## Running a Miner

The `coin-p2p` crate provides a simple command line interface. A miner can be
started with:

```bash
cargo run -p coin-p2p -- <port> miner
```

Replace `<port>` with the TCP port to listen on. Additional nodes can be run as
`wallet` or `verifier` types using the same command structure.

## Development

```bash
# Format and test
cargo fmt
cargo test

# Optional: run coverage
cargo tarpaulin --timeout 60
```
