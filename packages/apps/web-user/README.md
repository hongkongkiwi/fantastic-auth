# Vault User Portal

A user self-service portal built with TanStack Start for managing account settings, security, privacy, and devices.

## Features

- **Profile Management** - Update personal information, avatar, and contact details
- **Security Settings** - Manage password, two-factor authentication, and security keys (WebAuthn)
- **Device Management** - View and manage trusted devices with trust scores
- **Session Management** - View active sessions and revoke access from other devices
- **Privacy Center** - GDPR compliance features including data export and account deletion
- **Activity Log** - Review account activity and security events

## Tech Stack

- **Framework**: TanStack Start (React + SSR)
- **Router**: TanStack Router (file-based routing)
- **Styling**: Tailwind CSS v4
- **UI Components**: Radix UI primitives
- **Icons**: Lucide React
- **Notifications**: Sonner

## Development

```bash
# Install dependencies
pnpm install

# Run development server
pnpm dev
```

The app runs at `http://localhost:3002`.

## Project Structure

```
src/
├── routes/           # TanStack Start file-based routes
│   ├── __root.tsx    # Root layout with sidebar navigation
│   ├── index.tsx     # Profile page
│   ├── security.tsx  # Security settings (password, MFA, keys)
│   ├── devices.tsx   # Device management
│   ├── sessions.tsx  # Session management
│   ├── privacy.tsx   # Privacy/GDPR center
│   └── activity.tsx  # Activity log
├── components/
│   └── ui/          # Reusable UI components
├── lib/
│   └── utils.ts     # Utility functions
└── main.tsx         # Entry point
```

## Routes

| Route | Description |
|-------|-------------|
| `/` | Profile - Manage personal information |
| `/security` | Security - Password, MFA, WebAuthn keys |
| `/devices` | Devices - Manage trusted devices |
| `/sessions` | Sessions - View and revoke active sessions |
| `/privacy` | Privacy - GDPR data export, account deletion |
| `/activity` | Activity - Account activity log |

## API Integration

The portal connects to the Vault User API at `/api/v1/user`. Authentication uses Bearer tokens.

## Environment Variables

```env
VITE_API_URL=http://localhost:8080/api/v1/user
```
