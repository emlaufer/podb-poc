# PODB-POC

## Architecture

### Workspace Structure

- **`lib/`** - Core library with predicates and POD proving 
- **`client/`** - Command-line client
- **`server/`** - HTTP server
- **`solver/`** - POD solver 
- **`pod_derive/`** - Custom derive macro for converting Rust structs to Pod dictionaries

### Core Components

#### Library (`lib/`)
The core library provides `FileState` - a file-based state management system that:
- Stores indexed JSON objects in JSONL format
- Supports append-only operations with automatic indexing
- Handles generic serializable data types
- Provides comprehensive error handling
- Implements membership proof generation and verification

#### Client (`client/`)
A CLI application built with `clap` that provides the following commands:

```bash
podb-client [OPTIONS] <COMMAND>
```

**Options:**
- `--server-url <URL>` - Server URL (default: http://localhost:3000)

**Commands:**

- `generate-keypair [--name <NAME>]` - Generate a new keypair and save to files
- `generate-invite --admin-key <PATH> --invite-member <PATH> [--output <PATH>]` - Generate an invite pod for a member
- `accept-invite --invite-pod <PATH> --invitee-key <PATH> [--output <PATH>]` - Accept an invite and generate acceptance pod
- `submit-accept --accept-pod <PATH> --member-public-key <PATH>` - Submit accepted invite to server
- `status` - Check server status

#### Server (`server/`)
An HTTP server built with `axum` that:
- Handles membership invitation and acceptance workflows
- Verifies cryptographic proofs
- Maintains membership state
- Provides REST API endpoints for client interactions

#### Solver (`solver/`)
A zero-knowledge proof constraint solver that:
- Implements various cryptographic predicates (equality, hashing, signatures, etc.)
- Generates proof DAGs (Directed Acyclic Graphs)
- Handles constraint satisfaction and verification
- Supports custom operations and handlers

## Getting Started

### Prerequisites
- Rust toolchain (2024 edition)
- Git

### Building
```bash
# Build all workspace members
cargo build

# Quick compile check
cargo check

# Format code
cargo fmt

# Run linting
cargo clippy
```

### Testing
```bash
# Run all tests
cargo test

# Run tests for specific crate
cargo test -p lib
cargo test -p solver
```

### Running Applications

#### Start the Server
```bash
cargo run --bin server
```
The server will start on `http://localhost:3000` by default.

#### Use the Client
```bash
# Generate keypairs for admin and member
cargo run --bin client -- generate-keypair --name admin
cargo run --bin client -- generate-keypair --name member

# Generate an invite (admin invites member)
cargo run --bin client -- generate-invite \
  --admin-key admin_private.pem \
  --invite-member member_public.pem \
  --output invite.pod

# Accept the invite (member accepts)
cargo run --bin client -- accept-invite \
  --invite-pod invite.pod \
  --invitee-key member_private.pem \
  --output accept.pod

# Submit acceptance to server
cargo run --bin client -- submit-accept \
  --accept-pod accept.pod \
  --member-public-key member_public.pem

# Check server status
cargo run --bin client -- status
```

## Client Command Line Interface

The client provides a comprehensive CLI for membership operations:

### Key Management
- **`generate-keypair`** - Creates public/private key pairs for cryptographic operations

### Invitation Workflow
1. **`generate-invite`** - Admin generates invitation pods for prospective members
2. **`accept-invite`** - Invited users accept invitations and generate acceptance proofs
3. **`submit-accept`** - Accepted invitations are submitted to the server for verification

### System Monitoring
- **`status`** - Check server connectivity and system status

### File Outputs
- Private keys: `{name}_private.pem`
- Public keys: `{name}_public.pem`
- Invitation pods: `invite.pod` (or custom path)
- Acceptance pods: `accept.pod` (or custom path)

## Development

### Code Conventions
- Uses Rust 2024 edition with standard naming conventions
- Comprehensive error handling with custom error enums and `From` trait implementations
- Serde for JSON serialization with derive macros
- Unit tests in `#[cfg(test)]` modules using temporary files (`/tmp/test_*` pattern)
- Public APIs clearly marked, helper methods kept private

### Task Completion Checklist
When contributing:
1. Run `cargo check` to ensure compilation
2. Run `cargo test` to verify all tests pass
3. Add unit tests for new functionality
4. Ensure `cargo build` succeeds
5. Test relevant binaries with `cargo run --bin <name>`

## Technology Stack

- **Rust 2024** - Core language and edition
- **Serde** - Serialization/deserialization
- **Axum** - HTTP server framework
- **Clap** - Command-line argument parsing
- **Tokio** - Async runtime
- **Pod2** - Zero-knowledge proof system
- **Tracing** - Structured logging and instrumentation

## License

This project is a proof of concept developed by 0xPARC.
