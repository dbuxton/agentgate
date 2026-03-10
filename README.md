# agentgate ⛩️

**Identity-aware access control for AI agent tool permissions.**

When you deploy AI agents to many users, each person should have an access profile defining which tools their agent can use. agentgate is the enforcement layer: users get profiles, sessions get signed tokens, every tool call is checked against the user's profile, and access can be revoked instantly.

```
Alice (HR Manager)  → profile:hr-manager  → can use: crm_*, email_*, hr_*
Bob (Sales Rep)     → profile:sales        → can use: crm_read_*, email_*
Carol (IT Admin)    → profile:admin        → can use: *  (but not delete_*)
Dave (ex-employee)  → REVOKED             → immediate denial on all sessions
```

## The problem

You're deploying AI agents across 50 people at a company. Right now:
- Every agent has the same tool access
- When someone leaves, their agent sessions keep working until tokens expire
- You have no per-user record of which tools were called
- A junior employee's agent can do the same things as a senior's

agentgate fixes this as first-class infrastructure. Identity is the missing layer.

## Quick start

```bash
pip install agentgate
export AGENTGATE_SECRET="your-secret-key"

# Create a permission profile
agentgate profile create \
  --name "employee" \
  --allowed "crm_*,email_*" \
  --denied "crm_delete_*" \
  --rate 100

# Add a user
agentgate user create \
  --name "Alice" \
  --email alice@acme.com \
  --profile employee

# Issue a session token when a conversation starts
agentgate token issue --user alice@acme.com
# → TOKEN: eyJ...

# Check a tool call
agentgate enforce --token "eyJ..." --tool crm_get_contact
# → ✅ GRANTED

agentgate enforce --token "eyJ..." --tool crm_delete_contact
# → ✗ DENIED — reason: tool_explicitly_denied

# Offboard instantly — kills all active sessions
agentgate user revoke alice@acme.com
# → 🚫 User revoked: Alice (alice@acme.com)
#    tokens killed: 3
```

## How it works

```
Agent conversation starts
        │
        ▼
  agentgate.issue_token(user_id)
        │ returns signed session token
        ▼
Agent makes tool call
        │
        ▼
  agentgate.enforce(token, tool_name)
        │
        ├─ Verify token signature + expiry
        ├─ Check token not revoked
        ├─ Check user still active  ← catches post-issuance offboardings
        ├─ Match tool against profile allowlist/denylist
        ├─ Check hourly rate limit
        └─ Check daily token quota
        │
        ▼
  GRANT → increment counters, log event
  DENY  → log event, return deny_reason
```

The key insight: **user.active** is checked on every enforce call, not just at token issuance. So revoking a user instantly blocks all their active sessions — even tokens issued hours ago.

## Architecture

```
agentgate/
  db.py            — SQLite store (WAL mode, all queries here)
  models.py        — Profile, User, SessionToken, AuditEvent
  tokens.py        — HMAC-SHA256 token signing (no JWT lib needed)
  gate.py          — AgentGate enforcement engine
  server.py        — FastAPI server + dark-mode dashboard
  cli.py           — Full CLI (profile/user/token/enforce/audit/usage)
  integrations/
    django_adapter.py  — AgentProfile model, middleware, decorator
    openai_wrapper.py  — GatedOpenAI + GatedAnthropic wrappers
```

## Profiles

Profiles are named sets of rules. Glob matching, deny takes precedence.

```bash
# Wildcard profile (admin)
agentgate profile create --name admin --allowed "*"

# Restricted profile
agentgate profile create --name readonly \
  --allowed "*.read,*.get,*.list" \
  --denied "*.delete,*.destroy"

# With rate limiting and token quota
agentgate profile create --name free-tier \
  --allowed "chat_*" \
  --rate 20 \
  --tokens 50000
```

## API server

```bash
agentgate serve --host 0.0.0.0 --port 8765
# → Dashboard: http://localhost:8765/
# → API docs:  http://localhost:8765/docs
```

Key endpoints:
- `POST /enforce` — hot path, call on every tool use
- `POST /users/{id}/revoke` — offboard a user
- `POST /tokens/issue` — start a session
- `GET /audit?user_id=...` — audit trail

## Python API

```python
from agentgate import AgentGateDB, AgentGate, EnforceRequest
from agentgate.tokens import TokenManager

db = AgentGateDB("agentgate.db")
gate = AgentGate(db=db, token_manager=TokenManager(secret="your-secret"))

# Setup (once)
profile = db.create_profile(name="employee", allowed_tools=["crm_*"])
user = db.create_user(name="Alice", email="alice@acme.com", profile_id=profile.id)

# Per conversation
token = gate.issue_token(user_id=user.id, conversation_id="conv-123")

# Per tool call
result = gate.enforce(EnforceRequest(token=token.token, tool_name="crm_get_contact"))
if not result.granted:
    raise PermissionError(f"Denied: {result.deny_reason}")
```

## Django integration

```python
# settings.py
INSTALLED_APPS += ['agentgate']
MIDDLEWARE += ['agentgate.integrations.django_adapter.AgentGateMiddleware']
AGENTGATE_DB = '/var/lib/agentgate/agentgate.db'
AGENTGATE_SECRET = 'your-secret'

# In Django admin or management command:
from agentgate.integrations.django_adapter import AgentProfile
AgentProfile.objects.create(user=request.user, agentgate_profile_name='employee')

# In views — decorator approach:
from agentgate.integrations.django_adapter import enforce_tool

@enforce_tool('crm_create_contact')
def create_contact(request):
    ...  # X-AgentGate-Token header checked automatically

# Per-request token (for conversation sessions):
from agentgate.integrations.django_adapter import get_or_create_token
token = get_or_create_token(request, conversation_id=request.session['conv_id'])
```

## OpenAI / Anthropic wrappers

```python
from agentgate.integrations.openai_wrapper import GatedOpenAI, GateError

client = GatedOpenAI(gate=gate, token=session_token.token, openai_api_key="sk-...")

response = client.chat.completions.create(...)

for tool_call in response.choices[0].message.tool_calls or []:
    try:
        result = client.execute_tool_call(tool_call, your_tool_fn)
    except GateError as e:
        # Tool denied — surface to user or log
        print(f"Blocked: {e}")
```

## Offboarding

agentgate makes offboarding instant:

```bash
agentgate user revoke dave@acme.com
# → All Dave's active agent sessions are immediately denied
# → No waiting for tokens to expire
# → Full audit trail of what Dave's agent did
```

Under the hood: `user.active = False` is checked on every `enforce()` call, even for tokens issued before the revocation.

## Audit log

Every enforcement decision is logged:

```bash
agentgate audit --user alice@acme.com --limit 20

# TIME                   TYPE                 USER         TOOL                           RESULT
# 2026-03-10 01:15 UTC   tool_call            a3f2c891     crm_get_contact                ✅
# 2026-03-10 01:14 UTC   tool_call            a3f2c891     crm_delete_contact             ✗ tool_explicitly_denied
# 2026-03-10 01:13 UTC   token_issued         a3f2c891     —                              🔑
```

## Passes the Bitter Lesson filter

10x smarter models still can't:
- Know an employee was terminated yesterday
- Decide which business role maps to which tool access
- Enforce your company's HR policy on who can delete contacts
- Provide a tamper-evident audit trail for your employment tribunal

This is authorization infrastructure, not intelligence. It gets more important as models get more capable.

## Requirements

- Python 3.10+
- FastAPI + uvicorn (server mode)
- No external auth deps — HMAC-SHA256 token signing is stdlib

## License

MIT
