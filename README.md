# PODB-POC

## Architecture

### Workspace Structure

- **`lib/`** - Core library with predicates and POD proving 
- **`client/`** - Command-line client
- **`server/`** - HTTP server
- **`solver/`** - POD solver 
- **`pod_derive/`** - Custom derive macro for converting Rust structs to Pod dictionaries

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
