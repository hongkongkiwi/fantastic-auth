# FedRAMP System Security Plan (SSP)

## FantasticAuth Identity Platform

**Version:** 1.0  
**Date:** 2026-02-09  
**Classification:** FedRAMP Confidential  
**System Owner:** FantasticAuth Security Team  
**Authorizing Official:** TBD

---

## 1. Executive Summary

### 1.1 System Description

FantasticAuth is a cloud-native identity and access management (IAM) platform providing authentication, authorization, and user management services. The system supports OAuth 2.0, OpenID Connect, SAML 2.0, and WebAuthn protocols.

### 1.2 System Category

**Impact Level:** High (FISMA)

**Security Categorization:**
- Confidentiality: High
- Integrity: High
- Availability: High

### 1.3 Cloud Service Model

**SaaS (Software as a Service)**

### 1.4 Deployment Model

**Hybrid Cloud:**
- Primary: AWS GovCloud (US)
- DR: Azure Government
- Edge: Cloudflare

---

## 2. System Boundaries

### 2.1 System Components

| Component | Technology | Purpose |
|-----------|------------|---------|
| API Gateway | AWS API Gateway | Entry point for all API requests |
| Auth Server | Rust/Axum | Core authentication services |
| Database | PostgreSQL (RDS) | User and session storage |
| Cache | Redis (ElastiCache) | Session and rate limiting |
| HSM | AWS CloudHSM | Key storage and crypto operations |
| Vault | HashiCorp Vault | Secrets management |
| Monitoring | Datadog Gov | Security monitoring and SIEM |

### 2.2 Network Architecture

```
Internet
    │
    ▼
[Cloudflare WAF/DDoS]
    │
    ▼
[AWS GovCloud]
    │
    ├─► [API Gateway] ◄─► [Auth Server]
    │                            │
    │                            ├─► [PostgreSQL RDS]
    │                            ├─► [Redis ElastiCache]
    │                            └─► [CloudHSM]
    │
    └─► [HashiCorp Vault]
```

### 2.3 Data Flows

**Authentication Flow:**
1. Client → API Gateway (mTLS)
2. API Gateway → Auth Server (mTLS)
3. Auth Server → HSM (signing)
4. Auth Server → Redis (session)
5. Auth Server → PostgreSQL (audit)

---

## 3. Control Implementation

### 3.1 Access Control (AC)

#### AC-2: Account Management

**Implementation:**
- Automated user provisioning via SCIM
- Role-based access control (RBAC) with 7 default roles
- Service accounts use mTLS with SPIFFE identities
- Quarterly access reviews via automated reports

**Evidence:**
- `packages/apps/server/src/scim/auth.rs`
- `packages/apps/server/src/permissions/mod.rs`

#### AC-3: Access Enforcement

**Implementation:**
- Enforced at API Gateway and application layer
- Attribute-based access control (ABAC) for fine-grained permissions
- Dynamic authorization based on device posture and risk score

**Evidence:**
- `packages/apps/server/src/middleware/auth.rs`
- `packages/apps/server/src/security/risk/mod.rs`

#### AC-17: Remote Access

**Implementation:**
- All remote access via HTTPS with mTLS
- No direct SSH access to production systems
- Session timeout: 15 minutes idle, 8 hours max
- Concurrent session limits per user

### 3.2 Audit and Accountability (AU)

#### AU-6: Audit Review

**Implementation:**
- Real-time audit log streaming to SIEM
- Automated anomaly detection using ML
- 99.9% of events processed within 5 minutes
- 77 distinct audit event types tracked

**Evidence:**
- `packages/apps/server/src/audit.rs`
- `packages/apps/server/src/security/risk/anomaly_detection.rs`

#### AU-12: Audit Generation

**Implementation:**
- Immutable audit logs with cryptographic signatures
- Separate audit database with write-once access
- All administrative actions logged
- Failed authentication attempts logged with IP/device fingerprint

### 3.3 Identification and Authentication (IA)

#### IA-2: Identification and Authentication

**Implementation:**
- Multi-factor authentication required for all users
- FIDO2/WebAuthn supported
- TOTP and SMS (with rate limiting)
- Biometric authentication for mobile apps

**Evidence:**
- `packages/apps/server/src/mfa/mod.rs`
- `packages/apps/server/src/auth/webauthn.rs`

#### IA-5: Authenticator Management

**Implementation:**
- Password policy: 12+ chars, complexity requirements
- Have I Been Pwned integration for breach detection
- Automatic password rotation for service accounts
- Hardware security keys (YubiKey) supported

**Evidence:**
- `packages/apps/server/src/security/password_policy.rs`
- `packages/apps/server/src/security/hibp.rs`

### 3.4 System and Communications Protection (SC)

#### SC-8: Transmission Confidentiality and Integrity

**Implementation:**
- TLS 1.3 for all connections
- mTLS for service-to-service communication
- Certificate pinning for critical endpoints
- Certificate rotation every 30 days

**Evidence:**
- `packages/apps/server/src/security/mtls.rs`

#### SC-12: Cryptographic Key Establishment

**Implementation:**
- All keys generated within FIPS 140-2 Level 3 HSM
- AWS CloudHSM for production key storage
- Key rotation automated (90 days for data encryption, 1 year for signing)
- No key material ever exported from HSM

**Evidence:**
- `packages/apps/server/src/security/hsm.rs`
- `packages/apps/server/src/security/fips.rs`

#### SC-13: Cryptographic Protection

**Implementation:**
- FIPS 140-2 validated algorithms only
- AES-256-GCM for data encryption
- ECDSA P-384 for signing
- SHA-384 for hashing

**Evidence:**
- `packages/apps/server/src/security/fips.rs`

### 3.5 System and Information Integrity (SI)

#### SI-4: Information System Monitoring

**Implementation:**
- Real-time security event monitoring
- ML-based behavioral analysis
- Automated threat response (blocking, rate limiting)
- Integration with threat intelligence feeds

**Evidence:**
- `packages/apps/server/src/ai/behavioral.rs`
- `packages/apps/server/src/security/bot_protection.rs`

---

## 4. Continuous Monitoring

### 4.1 Vulnerability Scanning

| Tool | Frequency | Scope |
|------|-----------|-------|
| Trivy | Daily | Container images |
| Snyk | Daily | Dependencies |
| OWASP ZAP | Weekly | API endpoints |
| Nessus | Monthly | Infrastructure |

### 4.2 Penetration Testing

- **Annual:** Full-scope penetration test by FedRAMP-approved 3PAO
- **Quarterly:** Internal penetration testing
- **On-demand:** After significant changes

### 4.3 Security Metrics

| Metric | Target | Current |
|--------|--------|---------|
| Vulnerability remediation (Critical) | 24 hours | 12 hours |
| Vulnerability remediation (High) | 7 days | 5 days |
| Security event detection | 5 minutes | 2 minutes |
| Failed login threshold | 5 attempts | Configurable |
| MFA enrollment rate | 100% | 100% |

---

## 5. Incident Response

### 5.1 Incident Classification

| Level | Definition | Response Time |
|-------|------------|---------------|
| Critical | Data breach, system compromise | 15 minutes |
| High | Unauthorized access attempt | 1 hour |
| Medium | Policy violation | 4 hours |
| Low | Minor security event | 24 hours |

### 5.2 Incident Response Team

| Role | Responsibility |
|------|----------------|
| Incident Commander | Overall incident coordination |
| Security Lead | Technical investigation |
| Communications Lead | External and internal communications |
| Legal Counsel | Regulatory and legal implications |

### 5.3 Notification Requirements

- **FedRAMP JAB:** Within 1 hour of confirmed breach
- **CISA:** Within 1 hour of confirmed breach
- **Affected Agencies:** Within 24 hours
- **Public:** Per agency guidance

---

## 6. Contingency Planning

### 6.1 Backup Strategy

| Data Type | Frequency | Retention | Encryption |
|-----------|-----------|-----------|------------|
| Database | Hourly (incremental), Daily (full) | 90 days | AES-256-GCM (HSM) |
| Audit Logs | Real-time replication | 7 years | AES-256-GCM (HSM) |
| Configuration | On change | 30 versions | AES-256-GCM (HSM) |

### 6.2 Disaster Recovery

**RTO (Recovery Time Objective):** 4 hours  
**RPO (Recovery Point Objective):** 1 hour

**Recovery Procedures:**
1. Automated failover to secondary region
2. Database restore from latest snapshot
3. Cache warm-up from persistent storage
4. DNS cutover
5. Health verification

### 6.3 Business Continuity

- Multi-region deployment (active-active)
- Circuit breakers for external dependencies
- Degraded mode operation (read-only)

---

## 7. Configuration Management

### 7.1 Baseline Configuration

All configurations stored in Git with:
- Signed commits required
- Branch protection rules
- Automated security scanning in CI/CD
- Immutable infrastructure

### 7.2 Change Management

| Change Type | Approval Required | Testing |
|-------------|-------------------|---------|
| Emergency | Security Lead + On-call | Minimal |
| Standard | Change Advisory Board | Full |
| Maintenance | Automated | Regression |

---

## 8. Personnel Security

### 8.1 Screening

- Background checks for all personnel with system access
- Citizenship verification for FedRAMP-related roles
- Non-disclosure agreements

### 8.2 Training

- Annual security awareness training
- FedRAMP-specific training for security team
- Role-based training (developers, ops, security)

---

## 9. Risk Assessment

### 9.1 Risk Rating

| Risk | Likelihood | Impact | Rating | Mitigation |
|------|------------|--------|--------|------------|
| Credential theft | Medium | High | High | MFA, DPoP, monitoring |
| Data breach | Low | Critical | High | Encryption, access controls |
| DDoS attack | Medium | Medium | Medium | Cloudflare, rate limiting |
| Insider threat | Low | High | Medium | Monitoring, least privilege |

### 9.2 Risk Mitigation

All high risks mitigated through:
- Technical controls (encryption, MFA)
- Administrative controls (policies, training)
- Physical controls (datacenter security)

---

## 10. Authorizing Official (AO) Signatures

**Authorizing Official:**

Name: _________________________

Title: _________________________

Date: _________________________

Signature: _________________________

---

## Appendix A: Acronyms

- **AC:** Access Control
- **AO:** Authorizing Official
- **CSP:** Cloud Service Provider
- **HSM:** Hardware Security Module
- **mTLS:** Mutual TLS
- **PIV:** Personal Identity Verification
- **RPO:** Recovery Point Objective
- **RTO:** Recovery Time Objective
- **SCIM:** System for Cross-domain Identity Management
- **SSP:** System Security Plan
- **3PAO:** Third Party Assessment Organization

## Appendix B: References

1. FedRAMP Security Assessment Framework
2. NIST SP 800-53 Rev 5
3. NIST SP 800-144 (Cloud Computing)
4. FIPS 140-2
5. FISMA Implementation Project
