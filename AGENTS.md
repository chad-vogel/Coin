# Contributor Guidelines

 - Always run `cargo fmt` and `cargo test` before committing.
- For coverage checks, run `cargo tarpaulin --timeout 60`.
- Include unit tests for all new functionality to maintain 100% coverage.
- Use defensive programming and clear code structure.
- Organize functionality into separate crates whenever it makes sense.
- Communication contracts should be defined using Protocol Buffers.
- Provide a simple peer-to-peer protocol for node communication.
