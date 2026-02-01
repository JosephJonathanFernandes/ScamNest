# Agentic Honeypot API - Implementation Guide

> **Quick Summary**: Build an AI-powered agentic honeypot API that detects scam messages, handles multi-turn conversations, extracts scam intelligence, and reports the final result back to the GUVI evaluation endpoint.

---

## 📋 Table of Contents

1. [System Overview](#system-overview)
2. [Authentication](#authentication)
3. [API Endpoint Specification](#api-endpoint-specification)
4. [Request Payload Structure](#request-payload-structure)
5. [Response Format](#response-format)
6. [Session Management](#session-management)
7. [Agent Behavior Guidelines](#agent-behavior-guidelines)
8. [Scam Detection Lifecycle](#scam-detection-lifecycle)
9. [Final Result Callback (CRITICAL)](#final-result-callback-critical)
10. [Evaluation Criteria](#evaluation-criteria)
11. [Ethics & Constraints](#ethics--constraints)

---

## System Overview

### ✅ In Scope
- Public REST API to receive incoming message events
- Session-based conversation handling using `sessionId`
- Scam intent detection
- Agentic multi-turn engagement
- Scam intelligence extraction
- Mandatory final callback to GUVI endpoint

### ❌ Out of Scope
- WhatsApp / SMS / Email automation
- UI or dashboards
- Redis-based session storage (explicitly not used)
- Message delivery guarantees

---

## Authentication

### Required Header
```http
x-api-key: YOUR_SECRET_API_KEY
Content-Type: application/json
```

### Behavior
- Requests without a valid `x-api-key` must be rejected
- Return HTTP `401 Unauthorized` for invalid/missing API keys

---

## API Endpoint Specification

### Endpoint
```
POST /<your-api-endpoint>
```

**Purpose**: Receives one incoming message event per request and returns one agent reply.

---

## Request Payload Structure

### First Message (Start of Conversation)

```json
{
  "sessionId": "wertyu-dfghj-ertyui",
  "message": {
    "sender": "scammer",
    "text": "Your bank account will be blocked today. Verify immediately.",
    "timestamp": "2026-01-21T10:15:30Z"
  },
  "conversationHistory": [],
  "metadata": {
    "channel": "SMS",
    "language": "English",
    "locale": "IN"
  }
}
```

### Follow-Up Message (Continuation)

```json
{
  "sessionId": "wertyu-dfghj-ertyui",
  "message": {
    "sender": "scammer",
    "text": "Share your UPI ID to avoid account suspension.",
    "timestamp": "2026-01-21T10:17:10Z"
  },
  "conversationHistory": [
    {
      "sender": "scammer",
      "text": "Your bank account will be blocked today. Verify immediately.",
      "timestamp": "2026-01-21T10:15:30Z"
    },
    {
      "sender": "user",
      "text": "Why will my account be blocked?",
      "timestamp": "2026-01-21T10:16:10Z"
    }
  ],
  "metadata": {
    "channel": "SMS",
    "language": "English",
    "locale": "IN"
  }
}
```

### Field Definitions

#### Root Object
| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `sessionId` | string | Yes | Unique identifier for a conversation |
| `message` | object | Yes | Latest incoming message |
| `conversationHistory` | array<object> | Optional | Previous messages in this session |
| `metadata` | object | Optional (Recommended) | Contextual information |

#### message Object
| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `sender` | string | Yes | Either "scammer" or "user" |
| `text` | string | Yes | Message content |
| `timestamp` | string | Yes | ISO-8601 formatted timestamp |

#### conversationHistory Array
Each element contains:
| Field | Type | Description |
|-------|------|-------------|
| `sender` | string | "scammer" or "user" |
| `text` | string | Message content |
| `timestamp` | string | ISO-8601 timestamp |

**Rules**:
- Empty array `[]` for first message
- Required for follow-up messages

#### metadata Object
| Field | Type | Description |
|-------|------|-------------|
| `channel` | string | "SMS", "WhatsApp", "Email", "Chat" |
| `language` | string | Language used |
| `locale` | string | Country or region |

---

## Response Format

### Response Structure
```json
{
  "status": "success",
  "reply": "Why is my account being suspended?"
}
```

### Field Types
| Field | Type | Description |
|-------|------|-------------|
| `status` | string | Must be "success" |
| `reply` | string | Agent-generated response |

---

## Session Management

### Requirements

#### Session Identification
- Sessions are identified **only** by `sessionId`
- Session state must be persisted between requests

#### ❌ NOT Allowed
- Redis-based session storage

#### ✅ Acceptable Alternatives
- In-memory store


### Session State Tracking

Track the following for each session:
- Conversation messages
- Scam detection status
- Extracted intelligence
- Total messages exchanged
- Callback completion flag

---

## Agent Behavior Guidelines

### ✅ The AI Agent MUST:
- Handle multi-turn conversations
- Adapt responses dynamically
- Avoid revealing scam detection
- Behave like a real human
- Perform self-correction if needed

### ❌ The Agent MUST NOT:
- Mention "scam detection"
- Reveal system behavior
- Break persona consistency

---

## Scam Detection Lifecycle

1. **Suspicion Phase**: Scam intent may be suspected early
2. **Engagement Phase**: Engagement may start before confirmation
3. **Confirmation Phase**: Scam intent is confirmed later
4. **Callback Phase**: Final callback sent only after confirmation

---

## Final Result Callback (CRITICAL)

### ⚠️ This is Mandatory

### Endpoint
```
POST https://hackathon.guvi.in/api/updateHoneyPotFinalResult
```

### Headers
```http
Content-Type: application/json
```

### Callback Payload

```json
{
  "sessionId": "abc123-session-id",
  "scamDetected": true,
  "totalMessagesExchanged": 18,
  "extractedIntelligence": {
    "bankAccounts": ["XXXX-XXXX-XXXX"],
    "upiIds": ["scammer@upi"],
    "phishingLinks": ["http://malicious-link.example"],
    "phoneNumbers": ["+91XXXXXXXXXX"],
    "suspiciousKeywords": ["urgent", "verify now", "account blocked"]
  },
  "agentNotes": "Scammer used urgency tactics and payment redirection"
}
```

### Field Definitions

| Field | Type | Description |
|-------|------|-------------|
| `sessionId` | string | Unique session identifier |
| `scamDetected` | boolean | Whether scam intent was confirmed |
| `totalMessagesExchanged` | number | Total messages in session |
| `extractedIntelligence` | object | All extracted scam intelligence |
| `agentNotes` | string | Summary of scammer behavior |

### When to Send Callback

Send the callback **only after**:
1. ✅ Scam intent is confirmed (`scamDetected = true`)
2. ✅ Agent engagement is complete
3. ✅ Intelligence extraction is finished

This is the **final step** of the conversation lifecycle.

### Callback Rules (Strict)

- ✅ Callback is **mandatory**
- ✅ Callback must be sent **once per session**
- ❌ Missing callback → solution **not evaluated**

### Implementation Example

```python
intelligence_dict = {
    "bankAccounts": intelligence.bankAccounts,
    "upiIds": intelligence.upiIds,
    "phishingLinks": intelligence.phishingLinks,
    "phoneNumbers": intelligence.phoneNumbers,
    "suspiciousKeywords": intelligence.suspiciousKeywords
}

payload = {
    "sessionId": session_id,
    "scamDetected": scam_detected,
    "totalMessagesExchanged": total_messages,
    "extractedIntelligence": intelligence_dict,
    "agentNotes": agent_notes
}

response = requests.post(
    "https://hackathon.guvi.in/api/updateHoneyPotFinalResult",
    json=payload,
    timeout=5
)
```

---

## Evaluation Criteria

The platform evaluates:
- ✅ Scam detection accuracy
- ✅ Quality of agentic engagement
- ✅ Intelligence extraction
- ✅ API stability and response time
- ✅ Ethical behavior

---

## Ethics & Constraints

### ❌ Prohibited
- No impersonation of real individuals
- No illegal instructions
- No harassment

### ✅ Required
- Responsible data handling
- Ethical AI behavior

**Note**: Violation may result in disqualification.

---

## Quick Reference Checklist

- [ ] API endpoint accepts POST requests
- [ ] Authentication via `x-api-key` header
- [ ] Handle first message (empty `conversationHistory`)
- [ ] Handle follow-up messages (populated `conversationHistory`)
- [ ] Persist session state (no Redis)
- [ ] Agent behaves like a human
- [ ] Detect scam intent
- [ ] Extract intelligence (bank accounts, UPI IDs, links, etc.)
- [ ] Send final callback to GUVI endpoint
- [ ] Return proper JSON response format
- [ ] Follow ethical guidelines

---

## Architecture Notes

### Recommended Flow

1. **Receive Message** → Authenticate → Load Session
2. **Analyze Intent** → Detect scam patterns
3. **Generate Response** → AI agent creates human-like reply
4. **Extract Intelligence** → Parse for scam indicators
5. **Update Session** → Save state
6. **Return Response** → Send agent reply
7. **Final Callback** → When scam confirmed and engagement complete

### Session State Schema (Recommended)

```python
{
    "sessionId": str,
    "messages": list,
    "scamDetected": bool,
    "scamSuspected": bool,
    "extractedIntelligence": {
        "bankAccounts": list,
        "upiIds": list,
        "phishingLinks": list,
        "phoneNumbers": list,
        "suspiciousKeywords": list
    },
    "totalMessages": int,
    "callbackSent": bool,
    "agentNotes": str,
    "metadata": dict
}
```

---

## Common Pitfalls to Avoid

1. ❌ Sending callback before scam is confirmed
2. ❌ Sending multiple callbacks for same session
3. ❌ Using Redis for session storage
4. ❌ Agent revealing it's detecting scams
5. ❌ Not persisting session state between requests
6. ❌ Forgetting to authenticate requests
7. ❌ Not handling empty `conversationHistory`

---

## Testing Scenarios

### Test Case 1: First Contact
- Empty conversation history
- Scammer sends initial message
- Agent responds naturally

### Test Case 2: Multi-Turn Engagement
- Conversation history present
- Agent maintains context
- Extracts intelligence gradually

### Test Case 3: Scam Confirmation
- Agent detects scam intent
- Continues engagement
- Prepares final callback

### Test Case 4: Final Callback
- Scam confirmed
- Intelligence extracted
- Callback sent to GUVI endpoint

---
 