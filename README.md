# AI Governance & Security Layer API

A plug-and-play, LLM-agnostic middleware that adds enterprise-grade security, compliance, and governance to any AI application.

## 🛡️ Key Features
- **Drop-in LLM Proxy**: OpenAI-compatible endpoint (`/v1/chat/completions`) routing to Groq, OpenAI, Anthropic, Gemini, etc.
- **Presidio PII Detection & Masking**: Automatically detects and masks sensitive entities (emails, phone numbers, SSNs, credit cards).
- **Prompt Injection Defense**: Multi-layer detection protecting against jailbreaks and prompt manipulation.
- **Policy Engine**: Built-in GDPR, HIPAA, PCI-DSS, and custom enterprise security rules.
- **Immutable Audit Trail**: Cryptographic SHA-256 integrity hash for every transaction.
- **Real-Time Observability**: Latency tracking, token usage, and security incident reporting.

## 🚀 Quick Start (Local Development)

### 1. Install Dependencies
```bash
cd backend
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
python -m spacy download en_core_web_sm
```

### 2. Configure Environment
Copy `.env.example` to `.env` and set your provider API keys:
```env
GROQ_API_KEY=your_groq_api_key
PII_DETECTION_ENABLED=true
PII_ACTION=mask
INJECTION_DETECTION_ENABLED=true
```

### 3. Run the Server
```bash
python main.py
```
- Interactive Swagger API Docs: `http://localhost:8001/docs`
- Health check: `http://localhost:8001/health`

## 🐳 Docker Deployment

```bash
docker build -t aigovernance-api backend/
docker run -p 8000:8000 -e GROQ_API_KEY="your_key" aigovernance-api
```
