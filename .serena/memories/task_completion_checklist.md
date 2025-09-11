# Task Completion Checklist

When completing development tasks in this project:

## Code Quality
1. Run `cargo check` to ensure compilation
2. Run `cargo test` to ensure all tests pass  
3. Run `cargo fmt` if code formatting is needed
4. Run `cargo clippy` if linting is configured

## Testing
- Add unit tests for new functionality in the appropriate `#[cfg(test)]` module
- Test file operations use temporary files (pattern: `/tmp/test_*`)
- Clean up test files in test teardown

## Documentation  
- Add doc comments for public APIs
- Update any relevant memory files if architectural changes are made

## Build Verification
- Ensure `cargo build` succeeds
- Test that relevant binaries run with `cargo run --bin <name>`

Note: This project currently has minimal CI/CD or automated tooling configured.