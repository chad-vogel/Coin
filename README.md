# Coin

This project aims to become a full-fledged coin system built with multiple crates. Protocol buffer definitions live in `coin-proto` and networking utilities live in `coin-p2p`. The main `coin` crate provides core blockchain functionality. Unit tests cover all functionality and code coverage is measured using `cargo tarpaulin`.

## Development

```bash
# Format and test
cargo fmt -- --check
cargo test

# Optional: run coverage
cargo tarpaulin --timeout 60
```
