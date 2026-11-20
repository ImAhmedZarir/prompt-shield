# PromptShield 🛡️

**Zero-Trust Security & Privacy Gateway for Large Language Model APIs**

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://opensource.org/licenses/MIT)
[![Node: >=20.0.0](https://img.shields.io/badge/Node->=20.0.0-green.svg)](https://nodejs.org/)
[![TypeScript](https://img.shields.io/badge/TypeScript-5.5-3178c6.svg)](https://www.typescriptlang.org/)
[![PRs Welcome](https://img.shields.io/badge/PRs-welcome-brightgreen.svg)](https://github.com/ImAhmedZarir/prompt-shield/pulls)

---

## ⚡ What is PromptShield?

**PromptShield** is a lightweight, high-performance security proxy designed to prevent sensitive data leakage and prompt injection attacks against LLM APIs (OpenAI, Anthropic, Gemini, Ollama, etc.).

It acts as an inline defensive guardrail: your application points its standard SDK `baseURL` to PromptShield, which inspects outgoing prompts, sanitizes sensitive tokens in real time, and proxies verified requests upstream with sub-millisecond latency.

```
┌─────────────────┐       HTTP / JSON       ┌────────────────────────┐       Clean API Call      ┌───────────────────────┐
│                 │ ──────────────────────> │      PromptShield      │ ────────────────────────> │      Upstream LLM     │
│  Client App /   │                         │     Security Gate      │                           │  (OpenAI / Anthropic  │
│  Agent Workflow │ <────────────────────── │                        │ <──────────────────────── │   Gemini / Ollama)    │
└─────────────────┘      Stream (SSE)       └────────────────────────┘        Stream (SSE)       └───────────────────────┘
                                                        │
                                            ┌───────────┴───────────┐
                                            │ Defense Pipelines:    │
                                            │ • Shannon Entropy     │
                                            │ • PII Anonymization   │
                                            │ • Secret Scanner      │
                                            │ • Jailbreak Heuristics│
                                            └───────────────────────┘
```

---

## 🔒 Core Defensive Capabilities

### 1. High-Entropy Secret Detection
Catches and blocks leaked credentials before they leave your infrastructure:
- **API Keys**: OpenAI, Anthropic, Google Cloud, AWS Access Keys, GitHub PATs, Slack Webhooks.
- **Tokens & Cryptographic Artifacts**: JWT tokens, RSA/SSH private keys, hashed secrets.
- **Shannon Entropy Verification**: Uses statistical entropy scoring to detect raw random keys while minimizing false positives on natural text.

### 2. Reversible PII Anonymization
Replaces personally identifiable information with deterministic token aliases:
- Emails (`[REDACTED_EMAIL_1]`)
- Credit Card numbers (validated via Luhn algorithm)
- Phone numbers (international E.164 and local formats)
- IPv4 / IPv6 addresses
- Government identification / SSNs

### 3. Prompt Injection & Jailbreak Defense
Detects adversarial inputs designed to manipulate LLM system prompts:
- System instruction override attempts (e.g., *"Ignore all previous instructions"*).
- Delimiter escape patterns (XML/Markdown tag exploitation).
- Role-hijacking and persona spoofing.

### 4. Low-Latency Streaming Support
Preserves native Server-Sent Events (SSE) streaming with negligible overhead (< 3ms p95), ensuring real-time token delivery to end users.

---

## 🚀 Quick Start

### 1. Installation

```bash
git clone https://github.com/ImAhmedZarir/prompt-shield.git
cd prompt-shield
npm install
npm run build
```

### 2. Run the Gateway

```bash
# Launch the proxy on default port 8080 routing to OpenAI
node dist/bin/cli.js --upstream https://api.openai.com
```

### 3. Connect Any Client

Update your application to point to the local proxy:

```typescript
import OpenAI from "openai";

const client = new OpenAI({
  apiKey: process.env.OPENAI_API_KEY,
  baseURL: "http://localhost:8080/v1" // Routes through PromptShield
});

// Any prompt containing sensitive credentials or PII is automatically sanitized
const response = await client.chat.completions.create({
  model: "gpt-4o",
  messages: [{ role: "user", content: "Debug this AWS key: AKIAIOSFODNN7EXAMPLE" }]
});
```

---

## ⚙️ Configuration Reference

PromptShield can be configured via `prompt-shield.config.json` or environment variables:

| Variable | Default | Description |
|---|---|---|
| `PORT` | `8080` | Local port for proxy listener |
| `UPSTREAM_URL` | `https://api.openai.com` | Target LLM provider endpoint |
| `BLOCK_SECRETS` | `true` | Reject prompts containing detected secrets |
| `ANONYMIZE_PII` | `true` | Mask PII fields into synthetic tokens |
| `BLOCK_INJECTIONS` | `true` | Reject prompts with detected jailbreak patterns |
| `STRICT_MODE` | `false` | Terminate request immediately on any policy alert |

---

## 🛠️ Architecture & Threat Model

PromptShield processes requests through a non-blocking linear pipeline:

1. **Intake & Decode**: Ingests request bodies without breaking chunked streams.
2. **Scanner Pipeline**:
   - `EntropyDetector`: Computes byte-level entropy distribution.
   - `SecretDetector`: Matches signatures against 20+ known credential patterns.
   - `PiiDetector`: Detects and substitutes sensitive entities.
   - `InjectionGuard`: Checks for known jailbreak vectors.
3. **Dispatch or Terminate**:
   - In *Audit Mode*: Logs warning metrics and forwards sanitized text.
   - In *Strict Mode*: Emits HTTP `400 Bad Request` with structured error metadata.

---

## 📄 License

Distributed under the MIT License. Developed by [Ahmed Ishtiaque Zarir](https://github.com/ImAhmedZarir).
