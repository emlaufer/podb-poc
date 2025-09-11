# Development Commands

## Building and Checking
- `cargo build` - Build all workspace members
- `cargo check` - Quick compile check without producing binaries
- `cargo build --release` - Production build

## Testing
- `cargo test` - Run all tests in the workspace
- `cargo test -p lib` - Run tests only in the lib crate
- Tests are located in `lib/src/lib.rs` in the `tests` module

## Running Applications
- `cargo run --bin client` - Run the client application  
- `cargo run --bin server` - Run the server application

## Development Tools
- `cargo fmt` - Format code (if rustfmt is configured)
- `cargo clippy` - Linting (if clippy is available)
- `cargo doc` - Generate documentation

## Project Structure
- Root `Cargo.toml` defines the workspace
- Each component (client, lib, server) has its own `Cargo.toml`
- No README or configuration files present in the project