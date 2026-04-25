---
name: phishing-analyzer
description: >
  Analyze a .eml file for phishing. Use when asked whether an email is a phishing
  attempt. Returns a grounded binary verdict (PHISHING / NOT_PHISHING / UNCERTAIN)
  with a confidence level. States uncertainty upfront. Never escalates without
  explicit human confirmation.
---

# Phishing Email Analyzer

Accepts a `.eml` file. Runs two stages — technical extraction then AI judgment —
and requires human confirmation before any escalation action is taken.

## Folder Structure

```
phishing-analyzer/
├── SKILL.md               ← this file
├── scripts/
│   ├── analyzer.py        ← Stage 1: technical extraction
│   ├── skill.py           ← Stage 2: AI judgment (Anthropic SDK)
│   └── main.py            ← CLI entry point + HITL gate
├── references/
│   ├── known_brands.md    ← brand list used for lookalike detection
│   └── auth_headers_reference.md  ← SPF/DKIM/DMARC header guide
└── assets/
    └── sample_phishing.eml  ← test fixture
```

## Quick Start

```bash
export ANTHROPIC_API_KEY=sk-...
pip install -r requirements.txt          # from project root

# Run via root launcher
python main.py .claude/skills/phishing-analyzer/assets/sample_phishing.eml

# Or run the skill script directly
cd .claude/skills/phishing-analyzer/scripts
python main.py ../assets/sample_phishing.eml
python main.py ../assets/sample_phishing.eml --json
```

## Verdict

| Value | Meaning |
|---|---|
| `PHISHING` | Evidence clearly indicates malicious intent |
| `NOT_PHISHING` | Evidence clearly indicates legitimate email |
| `UNCERTAIN` | Data insufficient or contradictory — **stated upfront** |

## Stage 1 — Technical Extraction (`scripts/analyzer.py`)

| Feature | Detail |
|---|---|
| Headers | All headers; surfaces auth, originating IP, mailer |
| SPF / DKIM / DMARC | Parsed from `Authentication-Results` and `Received-SPF` |
| URL resolution | Follows redirects; records original → final URL, status code |
| Attachment hashes | MD5 + SHA-256 per attachment |
| Lookalike domains | Levenshtein ≤ 3 vs 30+ brands (see `references/known_brands.md`) |
| `data_availability` | Explicit flags for what was/wasn't found |

## Stage 2 — AI Judgment (`scripts/skill.py`)

- **Model:** `claude-opus-4-7` with adaptive thinking
- **Structured output:** Pydantic `PhishingVerdict` via `messages.parse()`
- **Prompt caching** on system prompt for repeated calls

### Anti-Hallucination Design

- Every `evidence` item must quote a **specific value from the extracted data**.
  Generic claims ("urgent language") are explicitly forbidden in the system prompt.
- `data_sufficient=false` forces `verdict=UNCERTAIN` when fewer than 2 concrete
  items can be cited, or when signals are contradictory.
- `uncertainty_statement` (required when `UNCERTAIN`) names what is missing.
- `data_availability` dict tells Claude exactly which fields are present vs null.

## Human-in-the-Loop Gate (`scripts/main.py`)

The skill **never acts automatically**. After displaying the analysis:

| Verdict | Prompt shown to human |
|---|---|
| `PHISHING` | *"Would you like to see escalation steps? [y/N]"* |
| `UNCERTAIN` | *"Would you like to see steps for flagging for manual review? [y/N]"* |
| `NOT_PHISHING` | Displays result and exits — no prompt needed |

`recommended_actions` are displayed **only after** the human types `y`.
Nothing is reported, forwarded, or deleted without explicit confirmation.

## JSON Output Schema

```json
{
  "verdict": "PHISHING | NOT_PHISHING | UNCERTAIN",
  "confidence": "HIGH | MEDIUM | LOW",
  "risk_score": 0-100,
  "data_sufficient": true,
  "uncertainty_statement": null,
  "evidence": ["SPF=fail", "URL redirects to paypa1.com (edit-distance 1 from paypal)"],
  "summary": "One factual sentence.",
  "user_message": "2-3 sentences for a non-technical reader.",
  "recommended_actions": ["Consider reporting to security@company.com", "..."]
}
```

## References

- `references/known_brands.md` — brand list, detection logic, known limitations
- `references/auth_headers_reference.md` — SPF/DKIM/DMARC result codes and meanings

## Assets

- `assets/sample_phishing.eml` — test fixture with SPF/DKIM/DMARC failures and
  a lookalike PayPal domain (`paypa1-verify.com`)
