# Fantastic Auth CLI

A command-line interface for managing Fantastic Auth - a secure, quantum-resistant user authentication and management system.

## Installation

```bash
cargo install --path fantasticauth-cli
```

Or run directly:

```bash
cargo run --bin fantasticauth -- <command>
```

## Configuration

### Initial Setup

Configure the CLI interactively:

```bash
fantasticauth config init
```

This will prompt you for:
- Fantastic Auth API URL
- Authentication method (user login or API key)
- Tenant ID (if using API key)

### Manual Configuration

Set configuration values directly:

```bash
# Set API URL
fantasticauth config set-url https://api.fantasticauth.example.com

# Set API key (for service accounts)
fantasticauth config set-api-key <your-api-key>

# Set default tenant
fantasticauth config set-tenant <tenant-id>
```

### View Configuration

```bash
fantasticauth config show
```

## Authentication

### Login with Email/Password

```bash
# Will prompt for password
fantasticauth auth login user@example.com

# Or provide password directly
fantasticauth auth login user@example.com --password "mypassword"
```

### Login with API Key

```bash
fantasticauth auth login --api-key <key>
```

### Check Current User

```bash
fantasticauth auth whoami
```

### Logout

```bash
fantasticauth auth logout
```

## User Management

### List Users

```bash
# Basic list
fantasticauth users list

# With pagination
fantasticauth users list --page 2 --per-page 50

# Filter by email
fantasticauth users list --email "user@example.com"

# Filter by status
fantasticauth users list --status active
```

### Get User Details

```bash
fantasticauth users get <user_id>
```

### Create User

```bash
# Basic creation
fantasticauth users create --email user@example.com --name "John Doe"

# With password
fantasticauth users create --email user@example.com --password "securepass" --name "John Doe"

# With verified email
fantasticauth users create --email user@example.com --name "John Doe" --email-verified
```

### Update User

```bash
# Update name
fantasticauth users update <user_id> --name "Jane Doe"

# Update email
fantasticauth users update <user_id> --email newemail@example.com

# Update status
fantasticauth users update <user_id> --status suspended
```

### Delete User

```bash
# With confirmation
fantasticauth users delete <user_id>

# Skip confirmation
fantasticauth users delete <user_id> --force
```

### Suspend/Activate User

```bash
# Suspend user
fantasticauth users suspend <user_id> --reason "Violation of terms"

# Activate user
fantasticauth users activate <user_id>
```

## Organization Management

### List Organizations

```bash
fantasticauth orgs list

# With pagination
fantasticauth orgs list --page 1 --per-page 20
```

### Get Organization

```bash
fantasticauth orgs get <org_id>
```

### Create Organization

```bash
# Basic creation
fantasticauth orgs create --name "Acme Corp"

# With custom slug
fantasticauth orgs create --name "Acme Corp" --slug acme

# With description
fantasticauth orgs create --name "Acme Corp" --description "A demo organization"
```

### Update Organization

```bash
fantasticauth orgs update <org_id> --name "Acme Inc" --website https://acme.com
```

### Delete Organization

```bash
fantasticauth orgs delete <org_id>

# Skip confirmation
fantasticauth orgs delete <org_id> --force
```

### Member Management

```bash
# List members
fantasticauth orgs members list <org_id>

# Add member
fantasticauth orgs members add <org_id> --user-id <user_id> --role admin

# Update member role
fantasticauth orgs members update <org_id> --user-id <user_id> --role member

# Remove member
fantasticauth orgs members remove <org_id> --user-id <user_id>
```

## Session Management

### List Sessions

```bash
# List own sessions
fantasticauth sessions list

# List user sessions (admin)
fantasticauth sessions list --user-id <user_id>
```

### Revoke Session

```bash
# Revoke own session
fantasticauth sessions revoke <session_id>

# Revoke user session (admin)
fantasticauth sessions revoke <session_id> --user-id <user_id>
```

### Revoke All Sessions

```bash
# Revoke all own sessions
fantasticauth sessions revoke-all

# Revoke all user sessions (admin)
fantasticauth sessions revoke-all --user-id <user_id>
```

## Migration Tools

### Import Users from CSV

```bash
fantasticauth migrate import-users users.csv --format csv

# Dry run
fantasticauth migrate import-users users.csv --format csv --dry-run
```

### Import Users from JSON

```bash
fantasticauth migrate import-users users.json --format json
```

### Export Users

```bash
# Export to JSON (stdout)
fantasticauth migrate export-users --format json

# Export to file
fantasticauth migrate export-users --format json --output users.json

# Export to CSV
fantasticauth migrate export-users --format csv --output users.csv

# Filter by status
fantasticauth migrate export-users --format json --status active
```

### Import from Auth0

```bash
fantasticauth migrate from-auth0 \
    --domain your-domain.auth0.com \
    --token <management-api-token>
```

### Import from Firebase

```bash
fantasticauth migrate from-firebase \
    --credentials firebase-credentials.json
```

## Plugin Management

### List Plugins

```bash
fantasticauth plugins list

# With details
fantasticauth plugins list --detailed
```

### Install Plugin

```bash
fantasticauth plugins install ./my-plugin --enable
```

### Enable/Disable Plugin

```bash
fantasticauth plugins enable my-plugin
fantasticauth plugins disable my-plugin
```

### Create Plugin Scaffold

```bash
# Built-in plugin
fantasticauth plugins create my-plugin

# Native plugin
fantasticauth plugins create my-plugin --plugin-type native

# WASM plugin
fantasticauth plugins create my-plugin --plugin-type wasm
```

## Other Commands

### Test Connection

```bash
fantasticauth ping
```

### Show Version

```bash
fantasticauth --version
```

### Show Help

```bash
fantasticauth --help
fantasticauth users --help
fantasticauth orgs --help
```

## Output Formats

All commands support multiple output formats:

```bash
# Table format (default)
fantasticauth users list --format table

# JSON format
fantasticauth users list --format json

# YAML format
fantasticauth users list --format yaml
```

## Environment Variables

The CLI respects the following environment variables:

- `FANTASTICAUTH_API_URL` - Default API URL
- `FANTASTICAUTH_API_KEY` - API key for authentication
- `FANTASTICAUTH_TENANT_ID` - Default tenant ID

## Global Options

```bash
# Verbose output
fantasticauth --verbose users list

# Quiet mode
fantasticauth --quiet users list

# Custom API URL (overrides config)
fantasticauth --api-url https://api.example.com users list

# Custom tenant (overrides config)
fantasticauth --tenant-id my-tenant users list
```

## Configuration File Location

- macOS: `~/Library/Application Support/fantasticauth/config.toml`
- Linux: `~/.config/fantasticauth/config.toml`
- Windows: `%APPDATA%\fantasticauth\config.toml`

## Security Notes

- Store your API keys securely and never commit them to version control
- Use the `--force` flag with caution for destructive operations
- Sessions are stored in the config directory with appropriate permissions
- Consider using environment variables for sensitive values in CI/CD pipelines
