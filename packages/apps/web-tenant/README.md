# Vault Admin Dashboard

A comprehensive web-based Admin Dashboard for managing Vault tenants, users, organizations, and settings.

## Features

### Dashboard
- Real-time key metrics (total users, active sessions, new signups)
- Activity charts with logins and signups over time
- Recent activity feed
- System health monitoring

### Users Management
- Paginated user table with advanced search and filtering
- User status filters (active, suspended, email verified, MFA enabled)
- Bulk actions (suspend, delete, export)
- Detailed user profile page with:
  - Profile information
  - Active sessions list
  - Activity history
  - Organization memberships
  - MFA status
  - Admin actions (suspend, delete, impersonate)

### Organizations
- Complete organization management
- Member management with role assignments
- SSO configuration (SAML/OIDC)
- Domain verification
- Organization settings

### Security
- Password policy configuration
- MFA settings and enforcement
- Session management
- Rate limiting controls
- Geographic restrictions

### Settings
- General settings (company name, support email)
- Email template configuration
- Branding customization (logo, colors)
- Custom domain settings
- Localization (i18n) settings

### Integrations
- OAuth 2.0 client management
- SAML connection configuration
- Webhook endpoint management

### Audit & Analytics
- Comprehensive audit log viewer with filtering
- Export to CSV/JSON
- User growth analytics
- Login methods breakdown
- Geographic and device analytics

## Tech Stack

- **Framework**: React 18 with TypeScript
- **Build Tool**: Vite
- **Styling**: Tailwind CSS
- **Routing**: React Router
- **Data Fetching**: TanStack Query (React Query)
- **State Management**: Zustand
- **Charts**: Recharts
- **Tables**: TanStack Table
- **Date Handling**: date-fns
- **Icons**: Lucide React

## Project Structure

```
vault-web-admin/
├── public/                  # Static assets
├── src/
│   ├── components/
│   │   ├── layout/         # Layout components (Sidebar, Header, Layout)
│   │   ├── dashboard/      # Dashboard components (StatsCard, ActivityChart, RecentActivity)
│   │   ├── users/          # User components (UserTable, UserDetails, UserFilters)
│   │   └── organizations/  # Organization components (OrgTable, OrgDetails)
│   ├── pages/              # Page components
│   ├── hooks/              # Custom React hooks
│   ├── services/           # API services
│   ├── types/              # TypeScript type definitions
│   ├── store/              # Zustand store
│   ├── lib/                # Utility functions
│   ├── App.tsx             # Main app component
│   ├── main.tsx            # Entry point
│   └── index.css           # Global styles
├── package.json
├── tsconfig.json
├── vite.config.ts
└── tailwind.config.js
```

## Getting Started

### Prerequisites

- Node.js 18+ 
- pnpm

### Installation

```bash
# Install dependencies
pnpm install

# Run development server
pnpm dev

# Build for production
pnpm build

# Preview production build
pnpm preview
```

### Environment Variables

Create a `.env` file in the root directory:

```env
VITE_API_URL=http://localhost:8080/api/v1/admin
```

## Authentication

The admin dashboard uses Vault's own authentication system. Admin users must have appropriate role permissions (`admin` or `super_admin`).

### API Integration

All API calls are made to `/api/v1/admin` with a Bearer token in the Authorization header:

```typescript
const api = axios.create({
  baseURL: '/api/v1/admin',
  headers: { Authorization: `Bearer ${token}` }
});
```

## Key Components

### Layout
- Responsive sidebar with collapsible navigation
- Dark mode support
- User profile dropdown
- Real-time notifications

### Data Tables
- Sortable columns
- Pagination
- Row selection with bulk actions
- Responsive design

### Charts
- Line charts for activity over time
- Pie charts for distribution data
- Bar charts for categorical data
- Responsive containers

## Development

### Code Style

- ESLint for linting
- TypeScript for type safety
- Prettier for formatting (optional)

### Adding New Pages

1. Create a new component in `src/pages/`
2. Add the route in `src/App.tsx`
3. Add navigation link in `src/components/layout/Sidebar.tsx`

### API Hooks

Use the custom hooks in `src/hooks/useApi.ts` for data fetching:

```typescript
const { data, isLoading } = useUsers(params);
const createUser = useCreateUser();
```

## Deployment

### Build

```bash
pnpm build
```

This creates a production build in the `dist/` directory.

### Docker

A Dockerfile can be added for containerized deployment:

```dockerfile
FROM node:18-alpine AS builder
WORKDIR /app
COPY package.json pnpm-lock.yaml ./
RUN pnpm install --frozen-lockfile
COPY . .
RUN pnpm build

FROM nginx:alpine
COPY --from=builder /app/dist /usr/share/nginx/html
COPY nginx.conf /etc/nginx/conf.d/default.conf
EXPOSE 80
```

## Browser Support

- Chrome/Edge (latest)
- Firefox (latest)
- Safari (latest)

## License

[Your License]

## Contributing

[Contributing Guidelines]
