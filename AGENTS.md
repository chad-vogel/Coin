# Contributor Guidelines

 - Always run `cargo fmt` and `cargo test` before committing.
- For coverage checks, run `cargo tarpaulin --workspace --timeout 60 --fail-under 90`.
- Include unit tests for all new functionality. Overall test coverage must stay above 90%, with a target of 95%.
- Use defensive programming and clear code structure.
- Organize functionality into separate crates whenever it makes sense.
- Communication contracts should be defined using Protocol Buffers.
- Provide a simple peer-to-peer protocol for node communication.
