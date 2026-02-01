# Agentic Honeypot API 🍯

An AI-powered agentic honeypot API that detects scam messages, handles multi-turn conversations, extracts scam intelligence, and reports results to the GUVI evaluation endpoint.

## 🚀 Features

- **🔐 API Key Authentication**: Secure endpoints with `x-api-key` header
- **🕵️ Scam Pattern Detection**: Rule-based and AI-powered scam detection
- **🤖 AI Agent Responses**: Human-like responses to engage scammers
- **📊 Intelligence Extraction**: Extract bank accounts, UPI IDs, phone numbers, links
- **📤 Automatic Callback**: Report confirmed scams to GUVI endpoint
- **💾 Session Persistence**: SQLite-backed session storage

## 📁 Project Structure

```
Honeypot/
├── app/
│   ├── __init__.py
│   ├── config.py              # Configuration settings
│   ├── main.py                # FastAPI application
│   ├── models/
│   │   ├── __init__.py
│   │   └── schemas.py         # Pydantic schemas
│   ├── services/
│   │   ├── __init__.py
│   │   ├── session_service.py     # Session management
│   │   ├── scam_detector.py       # Scam detection logic
│   │   ├── intelligence_extractor.py  # Data extraction
│   │   ├── agent_service.py       # AI agent responses
│   │   └── callback_service.py    # GUVI callback handling
│   ├── middleware/
│   │   ├── __init__.py
│   │   └── auth.py            # Authentication middleware
│   └── routers/
│       ├── __init__.py
│       └── honeypot.py        # API routes
├── tests/
│   ├── __init__.py
│   ├── test_api.py            # API tests
│   └── test_services.py       # Service unit tests
├── .env.example               # Environment template
├── .gitignore
├── requirements.txt
├── run.py                     # Run script
└── README.md
```

## 🛠️ Installation

### 1. Clone and Setup

```bash
cd Honeypot

# Create virtual environment
python -m venv venv

# Activate virtual environment
# Windows:
venv\Scripts\activate
# Linux/Mac:
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt
```

### 2. Configure Environment

```bash
# Copy example env file
copy .env.example .env  # Windows
# cp .env.example .env  # Linux/Mac

# Edit .env with your settings
```

**Required Configuration:**
```env
API_KEY=your-secret-api-key-here
OPENAI_API_KEY=your-openai-key  # Optional, for AI responses
```

### 3. Run the Server

```bash
# Using run.py
python run.py

# Or using uvicorn directly
uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload
```

The API will be available at `http://localhost:8000`

## 📚 API Documentation

### Interactive Docs
- Swagger UI: `http://localhost:8000/docs`
- ReDoc: `http://localhost:8000/redoc`

### Endpoints

#### POST /honeypot
Handle incoming scam message and return agent response.

**Headers:**
```http
x-api-key: your-secret-api-key
Content-Type: application/json
```

**Request Body:**
```json
{
  "sessionId": "unique-session-id",
  "message": {
    "sender": "scammer",
    "text": "Your bank account will be blocked. Verify now!",
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

**Response:**
```json
{
  "status": "success",
  "reply": "Oh no, what happened to my account?"
}
```

#### GET /session/{session_id}
Get session state for debugging.

#### DELETE /session/{session_id}
Delete a session.

#### GET /health
Health check endpoint (no auth required).

## 🧪 Testing

```bash
# Run all tests
pytest

# Run with coverage
pytest --cov=app tests/

# Run specific test file
pytest tests/test_api.py -v
```

## 📝 Example Usage

### Using cURL

```bash
# First message
curl -X POST http://localhost:8000/honeypot \
  -H "x-api-key: your-secret-api-key" \
  -H "Content-Type: application/json" \
  -d '{
    "sessionId": "test-session-123",
    "message": {
      "sender": "scammer",
      "text": "URGENT: Your SBI account will be blocked. Share OTP to verify.",
      "timestamp": "2026-01-21T10:15:30Z"
    }
  }'
```

### Using Python

```python
import requests

url = "http://localhost:8000/honeypot"
headers = {
    "x-api-key": "your-secret-api-key",
    "Content-Type": "application/json"
}
payload = {
    "sessionId": "test-session-123",
    "message": {
        "sender": "scammer",
        "text": "Your bank account will be blocked. Verify now!",
        "timestamp": "2026-01-21T10:15:30Z"
    }
}

response = requests.post(url, json=payload, headers=headers)
print(response.json())
```

## 🔄 Workflow

1. **Receive Message** → Validate API key → Load/Create session
2. **Analyze Intent** → Detect scam patterns using rules + AI
3. **Extract Intelligence** → Parse for bank accounts, UPI IDs, links, etc.
4. **Generate Response** → AI creates human-like reply
5. **Update Session** → Persist state to SQLite
6. **Return Response** → Send agent reply to caller
7. **Trigger Callback** → When scam confirmed, report to GUVI endpoint

## ⚙️ Configuration Options

| Variable | Description | Default |
|----------|-------------|---------|
| `API_KEY` | Secret API key for authentication | Required |
| `OPENAI_API_KEY` | OpenAI API key for AI responses | Optional |
| `OPENAI_MODEL` | OpenAI model to use | `gpt-4o-mini` |
| `GUVI_CALLBACK_URL` | GUVI evaluation endpoint | Set in config |
| `DEBUG` | Enable debug mode | `false` |
| `LOG_LEVEL` | Logging level | `INFO` |

## 🛡️ Security Notes

- Never commit `.env` file with real API keys
- Use strong, unique API keys in production
- Consider rate limiting for production deployment
- The honeypot database contains sensitive scam data

## 📄 License

This project is for educational and evaluation purposes as part of the GUVI Hackathon.
