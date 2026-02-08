# Vault CLI

A command-line interface for managing Vault - a secure, quantum-resistant user authentication and management system.

## Installation

```bash
cargo install --path vault-cli
```

Or run directly:

```bash
cargo run --bin vault -- <command>
```

## Configuration

### Initial Setup

Configure the CLI interactively:

```bash
vault config init
```

This will prompt you for:
- Vault API URL
- Authentication method (user login or API key)
- Tenant ID (if using API key)

### Manual Configuration

Set configuration values directly:

```bash
# Set API URL
vault config set-url https://api.vault.example.com

# Set API key (for service accounts)
vault config set-api-key <your-api-key>

# Set default tenant
vault config set-tenant <tenant-id>
```

### View Configuration

```bash
vault config show
```

## Authentication

### Login with Email/Password

```bash
# Will prompt for password
vault auth login user@example.com

# Or provide password directly
vault auth login user@example.com --password "mypassword"
```

### Login with API Key

```bash
vault auth login --api-key <key>
```

### Check Current User

```bash
vault auth whoami
```

### Logout

```bash
vault auth logout
```

## User Management

### List Users

```bash
# Basic list
vault users list

# With pagination
vault users list --page 2 --per-page 50

# Filter by email
vault users list --email "user@example.com"

# Filter by status
vault users list --status active
```

### Get User Details

```bash
vault users get <user_id>
```

### Create User

```bash
# Basic creation
vault users create --email user@example.com --name "John Doe"

# With password
vault users create --email user@example.com --password "securepass" --name "John Doe"

# With verified email
vault users create --email user@example.com --name "John Doe" --email-verified
```

### Update User

```bash
# Update name
vault users update <user_id> --name "Jane Doe"

# Update email
vault users update <user_id> --email newemail@example.com

# Update status
vault users update <user_id> --status suspended
```

### Delete User

```bash
# With confirmation
vault users delete <user_id>

# Skip confirmation
vault users delete <user_id> --force
```

### Suspend/Activate User

```bash
# Suspend user
vault users suspend <user_id> --reason "Violation of terms"

# Activate user
vault users activate <user_id>
```

## Organization Management

### List Organizations

```bash
vault orgs list

# With pagination
vault orgs list --page 1 --per-page 20
```

### Get Organization

```bash
vault orgs get <org_id>
```

### Create Organization

```bash
# Basic creation
vault orgs create --name "Acme Corp"

# With custom slug
vault orgs create --name "Acme Corp" --slug acme

# With description
vault orgs create --name "Acme Corp" --description "A demo organization"
```

### Update Organization

```bash
vault orgs update <org_id> --name "Acme Inc" --website https://acme.com
```

### Delete Organization

```bash
vault orgs delete <org_id>

# Skip confirmation
vault orgs delete <org_id> --force
```

### Member Management

```bash
# List members
vault orgs members list <org_id>

# Add member
vault orgs members add <org_id> --user-id <user_id> --role admin

# Update member role
vault orgs members update <org_id> --user-id <user_id> --role member

# Remove member
vault orgs members remove <org_id> --user-id <user_id>
```

## Session Management

### List Sessions

```bash
# List own sessions
vault sessions list

# List user sessions (admin)
vault sessions list --user-id <user_id>
```

### Revoke Session

```bash
# Revoke own session
vault sessions revoke <session_id>

# Revoke user session (admin)
vault sessions revoke <session_id> --user-id <user_id>
```

### Revoke All Sessions

```bash
# Revoke all own sessions
vault sessions revoke-all

# Revoke all user sessions (admin)
vault sessions revoke-all --user-id <user_id>
```

## Migration Tools

### Import Users from CSV

```bash
vault migrate import-users users.csv --format csv

# Dry run
vault migrate import-users users.csv --format csv --dry-run
```

### Import Users from JSON

```bash
vault migrate import-users users.json --format json
```

### Export Users

```bash
# Export to JSON (stdout)
vault migrate export-users --format json

# Export to file
vault migrate export-users --format json --output users.json

# Export to CSV
vault migrate export-users --format csv --output users.csv

# Filter by status
vault migrate export-users --format json --status active
```

### Import from Auth0

```bash
vault migrate from-auth0 \
    --domain your-domain.auth0.com \
    --token <management-api-token>
```

### Import from Firebase

```bash
vault migrate from-firebase \
    --credentials firebase-credentials.json
```

## Plugin Management

### List Plugins

```bash
vault plugins list

# With details
vault plugins list --detailed
```

### Install Plugin

```bash
vault plugins install ./my-plugin --enable
```

### Enable/Disable Plugin

```bash
vault plugins enable my-plugin
vault plugins disable my-plugin
```

### Create Plugin Scaffold

```bash
# Built-in plugin
vault plugins create my-plugin

# Native plugin
vault plugins create my-plugin --plugin-type native

# WASM plugin
vault plugins create my-plugin --plugin-type wasm
```

## Other Commands

### Test Connection

```bash
vault ping
```

### Show Version

```bash
vault --version
```

### Show Help

```bash
vault --help
vault users --help
vault orgs --help
```

## Output Formats

All commands support multiple output formats:

```bash
# Table format (default)
vault users list --format table

# JSON format
vault users list --format json

# YAML format
vault users list --format yaml
```

## Environment Variables

The CLI respects the following environment variables:

- `VAULT_API_URL` - Default API URL
- `VAULT_API_KEY` - API key for authentication
- `VAULT_TENANT_ID` - Default tenant ID

## Global Options

```bash
# Verbose output
vault --verbose users list

# Quiet mode
vault --quiet users list

# Custom API URL (overrides config)
vault --api-url https://api.example.com users list

# Custom tenant (overrides config)
vault --tenant-id my-tenant users list
```

## Configuration File Location

- macOS: `~/Library/Application Support/vault/config.toml`
- Linux: `~/.config/vault/config.toml`
- Windows: `%APPDATA%\vault\config.toml`

## Security Notes

- Store your API keys securely and never commit them to version control
- Use the `--force` flag with caution for destructive operations
- Sessions are stored in the config directory with appropriate permissions
- Consider using environment variables for sensitive values in CI/CD pipelines
