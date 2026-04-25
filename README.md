# Reusable AI Skill Tool — Phishing Email Analyzer

A two-stage phishing email analyzer built as a reusable Claude Code skill. Drop in a `.eml` file and get a grounded, confidence-rated verdict. All escalation actions require explicit human confirmation — the tool never acts automatically.

---

## Features

- **Binary verdict** — `PHISHING`, `NOT_PHISHING`, or `UNCERTAIN` with a confidence level (`HIGH` / `MEDIUM` / `LOW`)
- **States uncertainty upfront** — when data is insufficient or contradictory, the tool says so clearly rather than guessing
- **Anti-hallucination** — output is enforced by a Pydantic schema; every evidence item must cite a specific value from the extracted data
- **Human-in-the-loop** — recommended actions are shown only after the user explicitly confirms; nothing is reported or deleted automatically
- **Technical extraction** — headers, SPF/DKIM/DMARC, URL redirect resolution, attachment hashes, lookalike-domain detection
- **AI judgment** — `claude-opus-4-7` with adaptive thinking and prompt caching

---

## Project Structure

```
reusable_ai_skill_tool/
├── main.py                          # Root launcher
├── requirements.txt
└── .claude/
    └── skills/
        └── phishing-analyzer/
            ├── SKILL.md             # Skill definition
            ├── scripts/             # Core logic
            │   ├── analyzer.py      # Stage 1: technical extraction
            │   ├── skill.py         # Stage 2: Claude API judgment
            │   └── main.py          # CLI + human-in-the-loop gate
            ├── references/
            │   ├── known_brands.md        # Brand list for lookalike detection
            │   └── auth_headers_reference.md  # SPF/DKIM/DMARC field guide
            └── assets/
                └── sample_phishing.eml    # Test fixture
```

---

## Setup

```bash
# 1. Clone the repo
git clone https://github.com/dRam51/reusable_ai_skill_tool.git
cd reusable_ai_skill_tool

# 2. Install dependencies
pip install -r requirements.txt

# 3. Set your Anthropic API key
export ANTHROPIC_API_KEY=sk-ant-...
```

---

## Usage

```bash
# Analyze an email (interactive — prompts for confirmation before showing actions)
python main.py path/to/email.eml

# Output raw JSON (skips interactive prompts, useful for piping)
python main.py path/to/email.eml --json

# Run the sample phishing fixture included in the repo
python main.py .claude/skills/phishing-analyzer/assets/sample_phishing.eml
```

### Example Output

```
==============================================================
  ⚠  PHISHING DETECTED
  Confidence: HIGH  |  Risk Score: 91/100
==============================================================

Summary: Email impersonates PayPal using a lookalike domain with SPF, DKIM, and DMARC all failing.

For you: This email is very likely a phishing attempt. The sender address uses
"paypa1-verify.com" — a fake domain designed to look like PayPal. Do not click
any links or provide any personal information.

Evidence found in this email's data:
  • SPF=fail (paypa1-verify.com not authorized)
  • DKIM=fail
  • DMARC=fail
  • Sender domain "paypa1.com" is edit-distance 1 from "paypal"
  • URL http://paypa1-verify.com/secure/login redirects to same suspicious domain

──────────────────────────────────────────────────────────────
  Recommended actions are pending YOUR approval.
  This system has taken NO automated action.
──────────────────────────────────────────────────────────────

⚠  This email appears to be phishing. Would you like to see the recommended escalation steps? [y/N]:
```

---

## How It Works

### Stage 1 — Technical Extraction (`scripts/analyzer.py`)

| Feature | Detail |
|---|---|
| Headers | Extracts all headers; surfaces auth results, originating IP, mailer |
| SPF / DKIM / DMARC | Parsed from `Authentication-Results` and `Received-SPF` |
| URL resolution | Follows redirects; records original → final URL and status code |
| Attachment hashes | MD5 + SHA-256 per attachment for threat-intel lookup |
| Lookalike domains | Levenshtein distance ≤ 3 against 30+ known brand names |
| `data_availability` | Explicit flags telling the AI what was and wasn't found |

### Stage 2 — AI Judgment (`scripts/skill.py`)

- **Model:** `claude-opus-4-7` with adaptive thinking
- **Structured output:** Pydantic `PhishingVerdict` via `client.messages.parse()`
- **Prompt caching** on the system prompt for repeated calls
- The system prompt explicitly forbids inventing indicators not present in the extracted data

### Human-in-the-Loop Gate (`scripts/main.py`)

| Verdict | What happens |
|---|---|
| `PHISHING` | Displays analysis → prompts *"Show escalation steps? [y/N]"* |
| `UNCERTAIN` | Displays analysis + uncertainty reason → prompts *"Flag for manual review? [y/N]"* |
| `NOT_PHISHING` | Displays analysis → exits (no prompt needed) |

Recommended actions are only shown after the human types `y`. The tool never sends, deletes, or reports anything on its own.

---

## JSON Schema

```json
{
  "verdict": "PHISHING | NOT_PHISHING | UNCERTAIN",
  "confidence": "HIGH | MEDIUM | LOW",
  "risk_score": 0,
  "data_sufficient": true,
  "uncertainty_statement": null,
  "evidence": ["SPF=fail", "domain paypa1.com is edit-distance 1 from paypal"],
  "summary": "One factual sentence.",
  "user_message": "2-3 sentences for a non-technical reader.",
  "recommended_actions": ["Consider reporting to security@company.com"]
}
```

---

## References

- [`references/known_brands.md`](.claude/skills/phishing-analyzer/references/known_brands.md) — full brand list, detection logic, and known limitations
- [`references/auth_headers_reference.md`](.claude/skills/phishing-analyzer/references/auth_headers_reference.md) — SPF, DKIM, and DMARC result codes explained

---

## Requirements

- Python 3.10+
- `anthropic >= 0.50.0`
- `pydantic >= 2.0.0`
- `requests >= 2.31.0`
- An [Anthropic API key](https://console.anthropic.com/)
