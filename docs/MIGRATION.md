# Vault Migration Guide

This guide covers migrating users from external identity providers (Auth0, Clerk, Firebase) and generic CSV/JSON files into Vault.

## Table of Contents

- [Overview](#overview)
- [Common Features](#common-features)
- [Auth0 Migration](#auth0-migration)
- [Clerk Migration](#clerk-migration)
- [Firebase Migration](#firebase-migration)
- [CSV/JSON Import](#csvjson-import)
- [Conflict Resolution](#conflict-resolution)
- [Troubleshooting](#troubleshooting)

## Overview

Vault provides a unified migration CLI that supports importing users from multiple sources:

| Source | Users | Organizations | Passwords | Social Connections |
|--------|-------|---------------|-----------|-------------------|
| Auth0 | ✅ | ❌ | ⚠️ | ✅ (as metadata) |
| Clerk | ✅ | ✅ | ❌ | ❌ |
| Firebase | ✅ | ❌ | ⚠️ | ✅ (as identities) |
| CSV/JSON | ✅ | ❌ | ⚠️ | ❌ |

> ⚠️ Password migration requires special handling. See the [Password Migration](#password-migration) section.

## Common Features

All migration commands share these features:

### Dry Run Mode
Preview what would be migrated without making changes:

```bash
vault migrate auth0 --auth0-domain myapp.auth0.com ... --dry-run
```

### Conflict Resolution
Handle users that already exist in Vault:

```bash
# Skip existing users (default)
vault migrate auth0 ... --on-conflict skip

# Update existing users
vault migrate auth0 ... --on-conflict update

# Fail on conflict
vault migrate auth0 ... --on-conflict fail
```

### Batch Processing
Control the batch size for large migrations:

```bash
vault migrate auth0 ... --batch-size 50
```

### Resume Capability
Continue an interrupted migration:

```bash
vault migrate auth0 ... --resume-from 500
```

## Auth0 Migration

### Prerequisites

1. Create a Machine-to-Machine (M2M) application in Auth0
2. Authorize it for the Management API
3. Grant permissions: `read:users`, `read:user_idp_tokens`

### Basic Usage

```bash
vault migrate auth0 \
  --auth0-domain myapp.auth0.com \
  --auth0-client-id YOUR_CLIENT_ID \
  --auth0-client-secret YOUR_CLIENT_SECRET \
  --dry-run
```

### Full Options

```bash
vault migrate auth0 \
  --auth0-domain myapp.auth0.com \
  --auth0-client-id xxx \
  --auth0-client-secret xxx \
  --batch-size 100 \
  --on-conflict skip \
  --resume-from 0
```

### Password Migration from Auth0

Auth0 uses bcrypt for password hashing, while Vault uses Argon2id. You have three options:

**Option 1: Force Password Reset (Recommended)**
```bash
# Users set new passwords on first login
vault migrate auth0 ...
# Then trigger password reset emails
```

**Option 2: Bcrypt Import with Re-hash**
```bash
# Requires Auth0 password export (Enterprise plan)
# Vault can accept bcrypt hashes and re-hash on first login
```

**Option 3: Custom Hash Verification**
See the password help:
```bash
vault migrate auth0 ... --password-help
```

### Data Mapping

| Auth0 Field | Vault Field | Notes |
|-------------|-------------|-------|
| `user_id` | `metadata.auth0_user_id` | Stored as metadata |
| `email` | `email` | Primary identifier |
| `email_verified` | `email_verified` | Boolean |
| `name` | `name` | Full display name |
| `given_name` + `family_name` | `name` | Fallback if name not set |
| `nickname` | `name` | Fallback |
| `picture` | `avatar_url` | Profile image |
| `phone_number` | `phone` | If available |
| `app_metadata` | `metadata.auth0_app_metadata` | JSON blob |
| `user_metadata` | `metadata.auth0_user_metadata` | JSON blob |
| `identities` | `metadata.auth0_connection` + `identities` | Social providers |
| `created_at` | `created_at` | Preserved |
| `last_login` | `metadata.auth0_last_login` | Stored as metadata |

## Clerk Migration

### Prerequisites

1. Get your Clerk secret key from the Clerk Dashboard
2. Ensure your API key has read access to users and organizations

### Basic Usage

```bash
vault migrate clerk \
  --clerk-secret-key YOUR_CLERK_SECRET_KEY \
  --dry-run
```

### With Organizations

```bash
vault migrate clerk \
  --clerk-secret-key YOUR_CLERK_SECRET_KEY \
  --include-orgs \
  --on-conflict skip
```

### Full Options

```bash
vault migrate clerk \
  --clerk-secret-key YOUR_CLERK_SECRET_KEY \
  --include-orgs \
  --batch-size 100 \
  --on-conflict skip \
  --resume-from 0
```

### Data Mapping

| Clerk Field | Vault Field | Notes |
|-------------|-------------|-------|
| `id` | `metadata.clerk_user_id` | Stored as metadata |
| `email_addresses[0]` | `email` | Primary email |
| `primary_email_address_id` | - | Used to select correct email |
| `first_name` + `last_name` | `name` | Combined full name |
| `username` | `metadata.clerk_username` + `name` | Fallback for name |
| `profile_image_url` | `avatar_url` | Profile image |
| `phone_numbers[0]` | `phone` | Primary phone |
| `email_verified` | `email_verified` | Boolean |
| `public_metadata` | `metadata.clerk_public_metadata` | JSON blob |
| `created_at` | `created_at` | Unix timestamp → ISO 8601 |
| `last_sign_in_at` | `metadata.clerk_last_sign_in_at` | Stored as metadata |

### Organization Migration

When using `--include-orgs`:

| Clerk Org Field | Vault Org Field |
|-----------------|-----------------|
| `name` | `name` |
| `slug` | `slug` |
| `public_metadata` | `metadata` |

Organization memberships are also migrated with their roles.

## Firebase Migration

### Prerequisites

1. Download your Firebase service account key (JSON)
2. Go to Project Settings → Service Accounts → Generate New Private Key

### Basic Usage

```bash
vault migrate firebase \
  --firebase-credentials ./service-account.json \
  --dry-run
```

### With Custom Claims

```bash
vault migrate firebase \
  --firebase-credentials ./service-account.json \
  --include-claims
```

### Full Options

```bash
vault migrate firebase \
  --firebase-credentials ./service-account.json \
  --batch-size 1000 \
  --on-conflict skip \
  --include-claims
```

### Password Migration from Firebase

Firebase uses PBKDF2/SHA256 or scrypt. Similar to Auth0, you have options:

**Option 1: Force Password Reset (Recommended)**
```bash
vault migrate firebase ...
# Users set new passwords on first login
```

**Option 2: Export and Import Hashes**
```bash
# Use Firebase's export users API
vault migrate firebase ... --password-help
```

### Data Mapping

| Firebase Field | Vault Field | Notes |
|----------------|-------------|-------|
| `localId` | `metadata.firebase_uid` | Stored as metadata |
| `email` | `email` | Generated placeholder if missing |
| `emailVerified` | `email_verified` | Boolean |
| `displayName` | `name` | Full name |
| `photoUrl` | `avatar_url` | Profile image |
| `phoneNumber` | `phone` | If available |
| `customAttributes` | `metadata.firebase_custom_claims` | JSON blob |
| `providerUserInfo` | `identities` | Social providers |
| `createdAt` | `created_at` | Unix ms → ISO 8601 |
| `lastLoginAt` | `metadata.firebase_last_login` | Stored as metadata |
| `disabled` | `metadata.firebase_disabled` | Stored as metadata |

### Custom Claims to Roles

When using `--include-claims`, Vault will:
1. Parse the custom claims JSON for each user
2. Look for a `role` claim
3. Assign that role to the user in Vault

Example custom claims:
```json
{
  "role": "admin",
  "department": "engineering"
}
```

## CSV/JSON Import

### CSV Format

The CSV file should have headers. Supported columns:

```csv
email,name,email_verified,phone,created_at,custom_field1,custom_field2
john@example.com,John Doe,true,+1234567890,2024-01-01T00:00:00Z,value1,value2
jane@example.com,Jane Smith,false,+0987654321,2024-02-01T00:00:00Z,value3,value4
```

### JSON Format

Array of objects:
```json
[
  {
    "email": "john@example.com",
    "name": "John Doe",
    "email_verified": true,
    "phone": "+1234567890",
    "created_at": "2024-01-01T00:00:00Z"
  }
]
```

Or JSONL (one object per line):
```jsonl
{"email":"john@example.com","name":"John Doe"}
{"email":"jane@example.com","name":"Jane Smith"}
```

### Basic Usage

```bash
vault migrate csv --file users.csv --dry-run
```

### With Column Mapping

Map source columns to Vault fields:

```bash
vault migrate csv \
  --file users.csv \
  --mapping "fullName=name,userEmail=email,isVerified=email_verified"
```

### Full Options

```bash
vault migrate csv \
  --file users.csv \
  --format csv \
  --delimiter "," \
  --mapping "email=email,name=name" \
  --on-conflict skip \
  --skip-errors
```

### Generate Template

Create a template file for your import:

```bash
# CSV template
vault migrate csv --generate-template csv

# JSON template
vault migrate csv --generate-template json
```

## Conflict Resolution

When a user with the same email already exists in Vault:

| Strategy | Behavior |
|----------|----------|
| `skip` | Skip the user, continue with others (default) |
| `update` | Update the existing user with new data |
| `merge` | Merge data - keep existing, add new fields |
| `fail` | Stop the entire migration with an error |

## Troubleshooting

### Rate Limiting

If you hit rate limits:
- Reduce `--batch-size`
- The migration will automatically retry after rate limit reset
- Use `--resume-from` to continue after interruption

### Authentication Errors

**Auth0:**
- Verify your M2M application has the correct Management API permissions
- Check that the client ID and secret are correct
- Ensure the domain is correct (no `https://` prefix)

**Clerk:**
- Ensure you're using the secret key (starts with `sk_`)
- Verify the key has read access to users

**Firebase:**
- Verify the service account JSON is valid
- Check that the project ID in the credentials matches your project
- Ensure the service account has `Firebase Admin` role

### Validation Errors

If users fail validation:
- Use `--skip-errors` to continue with valid users
- Check the migration report for specific error messages
- Verify email formats in your source data

### Memory Issues

For very large migrations:
- Reduce `--batch-size` to process fewer users at once
- Run the migration on a machine with more RAM
- Consider splitting the export into multiple files

## Best Practices

1. **Always use `--dry-run` first** to validate the migration
2. **Start with a small batch** using `--resume-from` and small `--batch-size`
3. **Test with a staging environment** before migrating production
4. **Backup your Vault data** before large migrations
5. **Monitor API rate limits** during migration
6. **Document your column mappings** for CSV imports
7. **Verify a sample of users** after migration completes

## Migration Report

After each migration, you'll see a summary:

```
📊 Migration Report
═══════════════════════════════════════
✅ Successfully migrated: 950
⏭️  Skipped (already exist): 50
❌ Failed: 2
📦 Total processed: 1002
⏱️  Duration: 45s

⚠️  Warnings (1):
   • Invalid phone number format for user@example.com

❌ Failures (2):
   • bad@example.com: Invalid email format
   • other@example.com: API timeout
═══════════════════════════════════════
```

## Export from Vault

You can also export users from Vault:

```bash
# Export to JSON
vault migrate export --format json --output users.json

# Export to CSV
vault migrate export --format csv --output users.csv

# Export only active users
vault migrate export --format json --status active --output active-users.json
```
