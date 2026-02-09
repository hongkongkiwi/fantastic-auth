# Implementation Plan - Post-Reorganization Review

**Date:** 2026-02-09  
**Current Rating:** 8.5/10 (up from 6.5/10)  
**Target:** 10/10

---

## Current State Summary

### Project Structure (New Monorepo)
```
packages/
├── apps/
│   ├── web/           # User-facing UI (TanStack Start)
│   ├── web-admin/     # Tenant Admin UI (React + Vite)
│   ├── server/        # Rust backend
│   └── cli/           # Rust CLI
├── core/
│   └── rust/          # Core business logic
├── sdks/
│   ├── admin-sdks/    # Admin SDKs
│   ├── app-sdks/      # Client SDKs
│   └── internal-sdks/ # Internal SDKs
├── database/          # Migrations & schema
├── infrastructure/    # Terraform, Docker, K8s
├── plugins/           # Plugin system
└── specs/             # OpenAPI specs
```

### Recently Completed (From roadmap-remaining-features.md)
- ✅ Admin route stabilization (/dashboard, /organizations, /audit-logs)
- ✅ Password policy persistence
- ✅ OIDC usage stats DB-backed
- ✅ Consent export generation
- ✅ Bulk import lifecycle improvements
- ✅ SCIM operational gaps fixed
- ✅ SAML SLO user-initiated flow
- ✅ Zero Trust UI components (Device, Session, Privacy)

---

## Gap Analysis

### 1. Backend API Gaps (P0 - Blocking)

The new UI components were created but need corresponding API endpoints:

#### Device Management API
```rust
// Required endpoints:
GET    /api/v1/devices                    # List user devices
GET    /api/v1/devices/:id                 # Get device details
PUT    /api/v1/devices/:id/trust           # Update trust status
DELETE /api/v1/devices/:id                 # Revoke device
GET    /api/v1/devices/policy              # Get trust policy
PUT    /api/v1/devices/policy              # Update trust policy
POST   /api/v1/devices/:id/verify          # Trigger device verification
```

#### Session Management API
```rust
// Required endpoints:
GET    /api/v1/sessions                    # List active sessions
GET    /api/v1/sessions/:id                # Get session details
DELETE /api/v1/sessions/:id                # Revoke session
DELETE /api/v1/sessions/all-others         # Revoke all except current
GET    /api/v1/sessions/activity           # Session activity log
```

#### Privacy/GDPR API
```rust
// Required endpoints:
POST   /api/v1/privacy/export              # Request data export
GET    /api/v1/privacy/export/:id          # Get export status
GET    /api/v1/privacy/export/:id/download # Download export
DELETE /api/v1/privacy/account             # Request account deletion
GET    /api/v1/privacy/data-categories     # List data categories
GET    /api/v1/privacy/consents            # Get consent preferences
PUT    /api/v1/privacy/consents            # Update consent preferences
```

#### Security Dashboard API
```rust
// Required endpoints:
GET    /api/v1/security/score              # Get security score
GET    /api/v1/security/alerts             # List security alerts
PUT    /api/v1/security/alerts/:id/ack     # Acknowledge alert
GET    /api/v1/security/recommendations    # Get recommendations
GET    /api/v1/security/mfa-stats          # MFA adoption statistics
GET    /api/v1/security/risk-factors       # Risk factor breakdown
```

### 2. Web (User-Facing) UI Gaps (P0)

The user-facing UI (`packages/apps/web`) is missing critical self-service features:

#### Missing Routes
| Route | Component | Priority |
|-------|-----------|----------|
| `/profile` | UserProfile - View/edit own profile | P0 |
| `/security` | UserSecurity - MFA, password, sessions | P0 |
| `/devices` | UserDevices - Manage trusted devices | P0 |
| `/privacy` | UserPrivacy - GDPR/data controls | P0 |
| `/organizations/new` | CreateOrganization | P1 |
| `/invite/accept` | AcceptInvitation | P1 |

#### Missing Components in `packages/apps/web/src/components/`
- `UserProfile/` - Profile editing, avatar upload
- `SecuritySettings/` - MFA setup, password change
- `DeviceManager/` - Device trust management (user view)
- `SessionManager/` - Active sessions (user view) 
- `DataPrivacy/` - GDPR export/deletion (user view)

### 3. Web-Admin (Tenant Admin) UI Gaps (P1)

While Zero Trust components exist, these operational features are missing:

#### Missing Pages
| Page | Description | Priority |
|------|-------------|----------|
| `RateLimits.tsx` | Rate limiting configuration | P1 |
| `ApiKeys.tsx` | API key management (detailed) | P1 |
| `CustomDomains.tsx` | Custom domain setup wizard | P1 |
| `EmailTemplates.tsx` | Email template editor | P2 |
| `WebhookLogs.tsx` | Webhook delivery logs | P1 |
| `SamlDebugger.tsx` | SAML troubleshooting tool | P2 |
| `BulkOperations.tsx` | Bulk import/export UI | P2 |
| `MaintenanceMode.tsx` | Maintenance mode controls | P2 |

### 4. Hosted Auth Pages Gaps (P0)

The hosted pages (`packages/apps/web/src/routes/hosted/`) need:

#### Missing MFA Flows
| Route | Description | Priority |
|-------|-------------|----------|
| `/mfa/setup` | MFA enrollment wizard | P0 |
| `/mfa/verify` | MFA challenge (TOTP/SMS) | P0 |
| `/mfa/recovery` | Backup codes & recovery | P0 |
| `/mfa/webauthn` | Security key registration | P1 |

#### Missing Auth Flows
| Route | Description | Priority |
|-------|-------------|----------|
| `/reset-password` | Password reset flow | P0 |
| `/verify-email` | Email verification | P0 |
| `/invite` | Organization invitation | P1 |
| `/sso` | Enterprise SSO landing | P1 |

### 5. Real-Time Features (P1)

Currently using mock data. Need WebSocket/SSE:

```typescript
// Required real-time endpoints
ws://api/v1/realtime/security-alerts       # Live security alerts
ws://api/v1/realtime/session-updates       # Session changes
ws://api/v1/realtime/audit-stream          # Live audit log
```

### 6. Advanced Security (P2)

#### Step-Up Authentication UI
- Modal for sensitive operations
- Re-authentication flows
- Risk-based challenge UI

#### Just-In-Time Access
- Request temporary elevated access
- Approval workflow UI
- Time-bounded access display

### 7. Analytics & Reporting (P2)

#### Missing Analytics Pages
- Cohort analysis
- Login funnel visualization
- Geographic access heatmap
- Security incident timeline

#### Reports
- Compliance reports (SOC2, ISO27001)
- User activity reports
- Security audit reports

---

## Implementation Roadmap

### Phase 1: Backend API Foundation (Week 1-2)

Priority: P0 - Blocking all UI work

#### Week 1: Device & Session APIs
- [ ] Device management endpoints
- [ ] Session management endpoints
- [ ] Trust policy storage & enforcement

#### Week 2: Privacy & Security APIs
- [ ] GDPR export generation (async job)
- [ ] Account deletion workflow
- [ ] Security dashboard data endpoints
- [ ] Real-time WebSocket infrastructure

**Deliverable:** All new UI components can fetch real data

---

### Phase 2: User Self-Service Portal (Week 3-4)

Priority: P0 - Critical for user experience

#### Week 3: User Profile & Security
- [ ] `/profile` route & components
- [ ] `/security` route (MFA, password)
- [ ] `/sessions` route (session management)
- [ ] `/devices` route (device trust)

#### Week 4: Privacy & Onboarding
- [ ] `/privacy` route (GDPR controls)
- [ ] Enhanced `/mfa/setup` wizard
- [ ] Password reset flow
- [ ] Email verification flow

**Deliverable:** Users can fully self-manage security & privacy

---

### Phase 3: Admin Operational Tools (Week 5-6)

Priority: P1 - Required for SaaS operations

#### Week 5: Configuration Tools
- [ ] Rate limiting configuration UI
- [ ] API key management (detailed)
- [ ] Custom domain wizard
- [ ] Webhook delivery logs

#### Week 6: Advanced Features
- [ ] Email template editor
- [ ] SAML debugger/troubleshooter
- [ ] Bulk operations UI
- [ ] Maintenance mode controls

**Deliverable:** Admins have full operational control

---

### Phase 4: Real-Time & Advanced (Week 7-8)

Priority: P2 - Competitive differentiation

#### Week 7: Real-Time Features
- [ ] WebSocket integration
- [ ] Live security alerts
- [ ] Real-time audit log stream
- [ ] Live session monitoring

#### Week 8: Advanced Security
- [ ] Step-up authentication UI
- [ ] Risk score visualization
- [ ] Anomaly detection dashboard
- [ ] Security recommendations engine

**Deliverable:** 10/10 Zero Trust implementation

---

## Technical Requirements

### Database Schema Additions

```sql
-- Device tracking
CREATE TABLE user_devices (
    id UUID PRIMARY KEY,
    user_id UUID REFERENCES users(id),
    tenant_id UUID REFERENCES tenants(id),
    fingerprint_hash VARCHAR(255),
    trust_score INT,
    is_trusted BOOLEAN DEFAULT false,
    device_name VARCHAR(255),
    device_type VARCHAR(50),
    os VARCHAR(100),
    browser VARCHAR(100),
    ip_address INET,
    location VARCHAR(255),
    encryption_status VARCHAR(50),
    last_seen_at TIMESTAMP,
    created_at TIMESTAMP DEFAULT NOW()
);

-- Session tracking (extend existing)
ALTER TABLE sessions ADD COLUMN risk_score INT;
ALTER TABLE sessions ADD COLUMN factors TEXT[]; -- ['password', 'mfa_totp']
ALTER TABLE sessions ADD COLUMN is_suspicious BOOLEAN DEFAULT false;

-- Data exports (GDPR)
CREATE TABLE data_exports (
    id UUID PRIMARY KEY,
    user_id UUID REFERENCES users(id),
    tenant_id UUID REFERENCES tenants(id),
    status VARCHAR(50), -- pending, processing, ready, expired
    format VARCHAR(50), -- json, csv
    file_path VARCHAR(500),
    file_size BIGINT,
    expires_at TIMESTAMP,
    created_at TIMESTAMP DEFAULT NOW()
);

-- Security alerts
CREATE TABLE security_alerts (
    id UUID PRIMARY KEY,
    tenant_id UUID REFERENCES tenants(id),
    user_id UUID REFERENCES users(id),
    severity VARCHAR(50), -- critical, high, medium, low
    category VARCHAR(50), -- login, device, anomaly, policy
    title VARCHAR(255),
    description TEXT,
    metadata JSONB,
    acknowledged_at TIMESTAMP,
    created_at TIMESTAMP DEFAULT NOW()
);
```

### Rust Backend Structure

```
packages/apps/server/src/
├── devices/           # NEW
│   ├── mod.rs
│   ├── routes.rs
│   ├── models.rs
│   └── service.rs
├── sessions/          # NEW (extend existing)
│   ├── enhanced.rs
│   └── risk_scoring.rs
├── privacy/           # NEW
│   ├── mod.rs
│   ├── export.rs
│   ├── deletion.rs
│   └── consent.rs
├── security/          # NEW (dashboard)
│   ├── mod.rs
│   ├── score.rs
│   ├── alerts.rs
│   └── recommendations.rs
└── realtime/          # NEW
    ├── mod.rs
    ├── websocket.rs
    └── events.rs
```

### Frontend State Management

```typescript
// New stores needed for packages/apps/web-admin/src/store/

interface DeviceStore {
  devices: Device[];
  policy: DeviceTrustPolicy;
  fetchDevices: () => Promise<void>;
  updateTrustStatus: (id: string, trusted: boolean) => Promise<void>;
  revokeDevice: (id: string) => Promise<void>;
}

interface SessionStore {
  sessions: Session[];
  currentSession: Session | null;
  fetchSessions: () => Promise<void>;
  revokeSession: (id: string) => Promise<void>;
  revokeAllOthers: () => Promise<void>;
}

interface PrivacyStore {
  consents: ConsentRecord[];
  dataCategories: DataCategory[];
  exportHistory: DataExport[];
  requestExport: () => Promise<void>;
  updateConsent: (id: string, granted: boolean) => Promise<void>;
  requestAccountDeletion: () => Promise<void>;
}

interface SecurityDashboardStore {
  score: number;
  alerts: SecurityAlert[];
  recommendations: SecurityRecommendation[];
  mfaStats: MfaStats;
  acknowledgeAlert: (id: string) => Promise<void>;
  subscribeToAlerts: () => void;
}
```

---

## Testing Strategy

### Unit Tests
- Device trust score calculation
- Session risk scoring algorithm
- GDPR export data aggregation
- Security alert severity classification

### Integration Tests
- Device registration flow
- Session revocation propagation
- Export generation & download
- Real-time event broadcasting

### E2E Tests
- User self-service flows
- Admin operational workflows
- MFA enrollment & recovery
- Account deletion workflow

---

## Success Metrics

### Technical
- All new APIs have <100ms response time
- WebSocket connections stable (99.9% uptime)
- Export generation <5 minutes for 1GB data
- Zero security regressions

### User Experience
- User can complete MFA setup in <2 minutes
- Device revocation propagates in <5 seconds
- Privacy export available in <10 minutes
- Security alerts show in real-time

### Business
- 100% GDPR compliance (data portability & deletion)
- Zero Trust features increase enterprise adoption
- Self-service reduces support tickets by 50%

---

## Next Immediate Actions

1. **Create backend API module structure** (Day 1-2)
   - Create `devices/`, `privacy/`, `security/` modules
   - Define database migrations
   - Implement basic CRUD

2. **Wire UI to real APIs** (Day 3-4)
   - Replace mock data in DeviceManagement
   - Replace mock data in SessionManager
   - Replace mock data in DataPrivacy
   - Replace mock data in SecurityDashboard

3. **Create user self-service routes in web app** (Day 5-7)
   - `/profile` with edit capability
   - `/security` with MFA setup
   - `/devices` with trust management
   - `/privacy` with GDPR controls

4. **Test end-to-end flows** (Day 8-10)
   - Device trust workflow
   - Session management
   - Data export & deletion
   - Security alerts

**Estimated Time to 10/10:** 8 weeks (4 sprints)
