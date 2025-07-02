# Contributor Guidelines

- Always run `cargo fmt` and `cargo test` before committing.
- For coverage checks, run `cargo tarpaulin --workspace --timeout 60 --fail-under 90`.
- Include unit tests for all new functionality. Overall test coverage must stay above 90%, and PRs should strive to push coverage toward the 95% target.
- Use defensive programming and clear code structure.
- Organize functionality into separate crates whenever it makes sense.
- Communication contracts should be defined using JSON-RPC.
- Provide a simple peer-to-peer protocol for node communication.
