# Kratos OAuth Credential Management

## Overview

This document describes the OAuth credential management system for Bindu agents, enabling end-users to securely connect their third-party accounts (Notion, Gmail, GitHub, etc.) for agent execution at runtime.

---

## Architecture

### System Components

```
Ory Kratos (Identity) → HashiCorp Vault (Credentials) → PostgreSQL (Consent) → MCP Pool (Runtime)
```

**Key Components:**
- **Kratos**: User authentication and session management
- **Vault**: Encrypted OAuth token storage at `secret/oauth/users/{user_id}/{provider}`
- **PostgreSQL**: Consent records and audit logs
- **MCP Pool**: Server pool with dynamic credential injection

---

## Design Decisions

### 1. Credential Scope
**Decision:** Per-user global credentials with per-agent consent

**Flow:**
1. User connects Notion once (stored in Vault)
2. Each agent must request consent to use user's Notion credentials
3. User can revoke agent access without disconnecting Notion

### 2. Token Storage
**Decision:** HashiCorp Vault

**Path Structure:**
```
secret/oauth/users/{user_id}/{provider}/
  ├── access_token
  ├── refresh_token
  ├── expires_at
  └── scope
```

### 3. MCP Lifecycle
**Decision:** Pool of MCP servers with per-request credential injection

**Benefits:**
- No cold start overhead
- Credentials cleared after each request
- Auto-scaling based on load

### 4. Provider Management
**Decision:** Hybrid - common providers in code, custom in database

---

## User Journey

### Complete Flow

```
1. User Login (Kratos)
   → Session token issued

2. Connect OAuth Provider
   → User clicks "Connect Notion"
   → Redirect to Notion OAuth
   → User authorizes
   → Tokens stored in Vault

3. Use Agent
   → User selects agent requiring Notion
   → Consent screen: "Agent X wants Notion access"
   → User grants consent

4. Task Execution
   → Verify session
   → Check consent
   → Load credentials from Vault
   → Get MCP server from pool
   → Inject credentials
   → Execute task
   → Clear credentials
   → Return server to pool
```

---

## Data Models

### Vault Credentials
```json
{
  "access_token": "token...",
  "refresh_token": "refresh...",
  "expires_at": "2026-01-28T12:00:00Z",
  "scope": "read:workspace write:pages"
}
```

### Consent Table (PostgreSQL)
```sql
CREATE TABLE user_agent_consents (
    id UUID PRIMARY KEY,
    user_id UUID NOT NULL,
    agent_id UUID NOT NULL,
    provider VARCHAR(50) NOT NULL,
    scopes TEXT[],
    granted BOOLEAN DEFAULT FALSE,
    granted_at TIMESTAMP,
    revoked_at TIMESTAMP,
    UNIQUE(user_id, agent_id, provider)
);
```

### Audit Log
```sql
CREATE TABLE oauth_audit_log (
    id UUID PRIMARY KEY,
    user_id UUID NOT NULL,
    agent_id UUID,
    provider VARCHAR(50) NOT NULL,
    action VARCHAR(50) NOT NULL,
    success BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMP DEFAULT NOW()
);
```

---

## Implementation Components

### 1. Vault Integration (`bindu/auth/vault/`)
- `client.py` - Vault client wrapper
- `oauth_storage.py` - CRUD operations for OAuth credentials

### 2. Kratos Integration (`bindu/auth/kratos/`)
- `client.py` - Kratos API client
- `session.py` - Session verification

### 3. OAuth Flow (`bindu/auth/oauth/`)
- `flow.py` - Authorization flow
- `callback.py` - Callback handler
- `token_refresh.py` - Token refresh logic

### 4. Consent Management (`bindu/auth/consent/`)
- `manager.py` - Consent CRUD
- `middleware.py` - Consent verification

### 5. MCP Pool (`bindu/server/mcp/`)
- `pool.py` - Server pool management
- `credential_injector.py` - Credential injection

---

## API Endpoints

### OAuth
```
GET  /oauth/connect/{provider}        - Initiate OAuth
GET  /oauth/callback/{provider}       - OAuth callback
GET  /oauth/providers                 - List connected providers
DELETE /oauth/providers/{provider}    - Disconnect provider
```

### Consent
```
GET  /oauth/consent                   - Get consent screen
POST /oauth/consent                   - Grant consent
DELETE /oauth/consent/{agent}/{provider} - Revoke consent
GET  /oauth/consents                  - List all consents
```

---

## Security

### Token Storage
- All tokens encrypted in Vault
- Access control via Vault policies
- Audit logging enabled

### Token Refresh
- Automatic refresh when expires within 5 minutes
- Refresh token rotation every 30 days
- Graceful handling of expired refresh tokens

### Credential Isolation
- MCP servers cleared after each request
- No persistent credentials in MCP
- Per-user credential access control

### Audit Trail
- Log all OAuth actions (connect, refresh, revoke, access)
- Track which agent accessed which credentials
- IP address and user agent logging

---

## Deployment

### Prerequisites
- Ory Kratos running
- HashiCorp Vault with KV v2 enabled
- PostgreSQL database
- Redis for state tokens

### Environment Variables
```bash
KRATOS_ADMIN_URL=http://kratos:4434
KRATOS_PUBLIC_URL=http://kratos:4433
VAULT_ADDR=https://vault:8200
VAULT_TOKEN=your-vault-token
DATABASE_URL=postgresql://user:pass@localhost:5432/bindu
REDIS_URL=redis://localhost:6379

# OAuth Providers
NOTION_CLIENT_ID=...
NOTION_CLIENT_SECRET=...
GOOGLE_CLIENT_ID=...
GOOGLE_CLIENT_SECRET=...
```

### Vault Setup
```bash
vault secrets enable -path=secret kv-v2
vault policy write oauth-policy oauth-policy.hcl
vault token create -policy=oauth-policy
```

---

## Implementation Phases

### Phase 1: Foundation (Weeks 1-2)
- Vault client wrapper
- Kratos client integration
- Database migrations
- Basic OAuth flow

### Phase 2: OAuth Flow (Weeks 3-4)
- Authorization flow
- Callback handler
- Token refresh logic
- Provider registry

### Phase 3: Consent (Weeks 5-6)
- Consent manager
- Consent middleware
- Consent UI

### Phase 4: MCP Pool (Weeks 7-8)
- Server pool implementation
- Credential injection
- Pool monitoring

---

## Monitoring

### Metrics
- `oauth_connections_total` - Total OAuth connections
- `oauth_token_refreshes_total` - Token refreshes
- `mcp_pool_size` - Current pool size
- `mcp_credential_injection_duration` - Injection time

### Health Checks
```python
GET /health/oauth
{
  "status": "healthy",
  "checks": {
    "vault": true,
    "kratos": true,
    "database": true,
    "mcp_pool": true
  }
}
```

---

## Common OAuth Providers

```python
COMMON_PROVIDERS = {
    "notion": {
        "auth_url": "https://api.notion.com/v1/oauth/authorize",
        "token_url": "https://api.notion.com/v1/oauth/token",
        "scopes": ["read:workspace", "write:pages"]
    },
    "gmail": {
        "auth_url": "https://accounts.google.com/o/oauth2/v2/auth",
        "token_url": "https://oauth2.googleapis.com/token",
        "scopes": ["https://www.googleapis.com/auth/gmail.send"]
    },
    "github": {
        "auth_url": "https://github.com/login/oauth/authorize",
        "token_url": "https://github.com/login/oauth/access_token",
        "scopes": ["repo", "user"]
    }
}
```

---

## References

- [Ory Kratos Documentation](https://www.ory.sh/docs/kratos)
- [HashiCorp Vault Documentation](https://www.vaultproject.io/docs)
- [OAuth 2.0 RFC 6749](https://datatracker.ietf.org/doc/html/rfc6749)
- [Model Context Protocol](https://modelcontextprotocol.io/docs)
