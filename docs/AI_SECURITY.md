# AI-Powered Security System

Vault now includes a comprehensive AI-powered threat detection and security system that provides advanced protection against authentication attacks and account takeovers.

## Overview

The AI security system provides:

- **Real-time Risk Scoring**: ML-enhanced risk assessment for every authentication attempt
- **Behavioral Anomaly Detection**: Detects unusual login patterns, impossible travel, new devices
- **Attack Pattern Recognition**: Identifies brute force, credential stuffing, and bot traffic
- **Behavioral Biometrics**: Analyzes typing patterns, mouse movements, and touch gestures
- **Adaptive Learning**: Continuously improves based on feedback

## Architecture

```
vault-core/src/ai/
├── mod.rs                    # Main AI module and engine
├── error.rs                  # Error types
├── features.rs               # Feature extraction for ML models
├── ml_models.rs              # ML model management (Random Forest, Isolation Forest, etc.)
├── risk_engine.rs            # Real-time risk scoring
├── anomaly_detection.rs      # Behavioral anomaly detection
├── threat_detection.rs       # Attack pattern detection
└── behavioral.rs             # Behavioral biometrics

vault-server/src/ai/
├── mod.rs                    # Server AI module
├── risk_api.rs               # Risk score API endpoints
├── threat_api.rs             # Threat alert endpoints
└── middleware.rs             # AI-powered auth middleware
```

## Features

### 1. Real-Time Risk Scoring

Every authentication attempt is scored 0-100:
- **0-30**: Low risk - Allow
- **31-60**: Medium risk - Step-up auth or MFA
- **61-80**: High risk - Challenge (CAPTCHA + email verification)
- **81-100**: Critical risk - Block

Risk factors include:
- IP reputation (VPN, Tor, proxy)
- Device fingerprint (new device detection)
- Geographic anomalies (impossible travel)
- Time patterns (unusual login hours)
- Velocity checks (too many attempts)
- Behavioral biometrics

### 2. Anomaly Detection

Detects:
- **Unusual Location**: Login from previously unseen locations
- **Unusual Time**: Logins outside normal hours
- **New Device**: First-time device detection
- **Impossible Travel**: Logins from distant locations too quickly
- **Velocity Anomalies**: Too many login attempts
- **Behavioral Changes**: Changes in user behavior patterns

### 3. Attack Pattern Detection

Identifies:
- **Distributed Brute Force**: Coordinated attacks from multiple IPs
- **Credential Stuffing**: Automated use of stolen credentials
- **Account Enumeration**: Systematic username probing
- **Session Hijacking**: Unusual session behavior
- **Bot Traffic**: Automated client detection

### 4. Behavioral Biometrics

Analyzes:
- **Keystroke Dynamics**: Typing cadence and rhythm
- **Mouse Movements**: Movement patterns and velocity
- **Touch Gestures**: Pressure and swipe patterns
- **Form Interactions**: Time spent, corrections made

## API Endpoints

### Risk Score

```http
GET /ai/risk-score
```

Returns current risk score for the request context.

### User Risk Profile

```http
GET /api/v1/admin/ai/risk-profile/:user_id
```

Returns:
```json
{
  "user_id": "user_123",
  "baseline_score": 20,
  "recent_anomalies": [],
  "risk_history": [20, 15, 25, 18, 22],
  "anomaly_count_30d": 0,
  "last_updated": "2024-01-15T10:30:00Z"
}
```

### Threat List

```http
GET /api/v1/admin/ai/threats
```

Returns active threats:
```json
{
  "threats": [
    {
      "id": "threat_123",
      "attack_type": "distributed_brute_force",
      "severity": "high",
      "status": "active",
      "source_ip_count": 15,
      "target_count": 3,
      "attempt_count": 250,
      "confidence": 0.85
    }
  ],
  "total": 1
}
```

### Submit Feedback

```http
POST /api/v1/admin/ai/feedback
Content-Type: application/json

{
  "event_id": "evt_123",
  "was_threat": true,
  "notes": "False positive - user was traveling"
}
```

### System Status

```http
GET /api/v1/admin/ai/status
```

Returns:
```json
{
  "status": "healthy",
  "ml_risk_enabled": true,
  "anomaly_detection_enabled": true,
  "threat_detection_enabled": true,
  "behavioral_biometrics_enabled": true,
  "models_loaded": 3,
  "total_assessments": 15000,
  "total_anomalies_detected": 45,
  "total_threats_blocked": 12
}
```

## Configuration

Enable/disable via environment variable:

```bash
# Enable AI security (default: true)
VAULT_AI_ENABLED=true

# Configure thresholds (optional - uses sensible defaults)
VAULT_AI_MFA_THRESHOLD=50
VAULT_AI_BLOCK_THRESHOLD=80
VAULT_AI_ANOMALY_SENSITIVITY=0.7
```

## Middleware Integration

The AI security middleware can be added to protect authentication endpoints:

```rust
// In your route setup
Router::new()
    .route("/auth/login", post(login_handler))
    .layer(axum::middleware::from_fn_with_state(
        state.clone(),
        ai::ai_security_middleware,
    ))
```

The middleware will:
1. Analyze the request context
2. Calculate risk score
3. Detect anomalies
4. Take appropriate action (allow, step-up, require MFA, or block)

## ML Models

The system includes several lightweight models:

### Logistic Regression
- Fast, real-time scoring
- Rule-based with ML enhancement
- Always available

### Random Forest
- Ensemble of decision trees
- Higher accuracy than single models
- Good for risk classification

### Isolation Forest
- Unsupervised anomaly detection
- Detects outliers in user behavior
- No training data required

### LSTM (planned)
- Sequence-based detection
- Learns temporal patterns
- Good for detecting gradual behavior changes

## Integration with Existing Risk System

The AI system integrates seamlessly with Vault's existing risk-based authentication:

```rust
// AI-enhanced risk engine combines both approaches
let decision = ai_engine
    .evaluate_auth_attempt(user_id, &auth_context)
    .await?;

match decision.action {
    Action::Allow => { /* proceed */ }
    Action::StepUp => { /* require additional verification */ }
    Action::RequireMfa => { /* require MFA */ }
    Action::Block => { /* block request */ }
}
```

## Monitoring

The AI system exports metrics for monitoring:

- `vault_ai_risk_assessments_total` - Total assessments performed
- `vault_ai_anomalies_detected_total` - Anomalies detected
- `vault_ai_threats_blocked_total` - Threats blocked
- `vault_ai_ml_confidence_avg` - Average ML confidence

## Best Practices

1. **Enable Gradually**: Start with monitoring mode before blocking
2. **Tune Thresholds**: Adjust based on your user base and risk tolerance
3. **Review False Positives**: Submit feedback to improve models
4. **Monitor Metrics**: Watch for changes in attack patterns
5. **Combine with MFA**: Use AI to trigger step-up authentication

## Security Considerations

- AI models run locally - no data sent to external services
- Risk scores are cached for performance
- Behavioral data is hashed/anonymized
- All decisions are logged for audit
- Models can be updated without server restart

## Future Enhancements

- [ ] Deep learning models for complex pattern recognition
- [ ] Federated learning for privacy-preserving model updates
- [ ] Integration with external threat intelligence feeds
- [ ] Real-time attack correlation across tenants
- [ ] Predictive analytics for proactive security
