# Reusable AI Skill Tool — Phishing Email Analyzer

A two-stage phishing email analyzer built as a reusable Claude Code skill. Drop in a `.eml` file and get a grounded, confidence-rated verdict. All escalation actions require explicit human confirmation the tool never acts automatically.

---

## Features

- **Binary verdict**: `PHISHING`, `NOT_PHISHING`, or `UNCERTAIN` with a confidence level (`HIGH` / `MEDIUM` / `LOW`)
- **States uncertainty upfront**: when data is insufficient or contradictory, the tool says so clearly rather than guessing
- **Anti-hallucination**: output is enforced by a Pydantic schema; every evidence item must cite a specific value from the extracted data
- **Human-in-the-loop**: recommended actions are shown only after the user explicitly confirms; nothing is reported or deleted automatically
- **Technical extraction**: headers, SPF/DKIM/DMARC, URL redirect resolution, attachment hashes, lookalike-domain detection
- **AI judgment**: `claude-opus-4-7` with adaptive thinking and prompt caching

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
# Analyze an email (interactive: prompts for confirmation before showing actions)
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

```
main.py  →  analyzer.py        →  skill.py         →  main.py
reads       extracts facts        asks Claude          shows verdict
.eml        (no AI)               makes verdict        prompts human
```

---

## Script Reference

### `scripts/analyzer.py` — Stage 1: Technical Extraction

The data collector. Contains no AI — it purely reads the raw `.eml` file and extracts measurable facts. It parses all email headers, scrapes SPF/DKIM/DMARC authentication results, follows every URL through its redirect chain to find the final destination, computes MD5 and SHA-256 hashes of any attachments, and checks all sender domains and URL hosts against a list of 30+ known brands using Levenshtein edit distance to flag lookalike domains. All findings are packaged into an `EmailAnalysis` dataclass and passed to `skill.py`.

---

### `scripts/skill.py` — Stage 2: AI Judgment

The AI brain. Takes the structured data from `analyzer.py` and uses the Anthropic SDK to produce a verdict. It defines a Pydantic schema (`PhishingVerdict`) that constrains exactly what Claude can return, sends the extracted data to `claude-opus-4-7` with a system prompt that explicitly forbids inventing indicators not present in the data, and returns a validated verdict object. If the model cannot make a confident determination it is required to return `UNCERTAIN` rather than guess. Also contains the report formatter that turns the verdict into readable terminal output.

---

### `scripts/main.py` — CLI + Human-in-the-Loop Gate

The entry point and safety gate. Accepts the `.eml` file path as a CLI argument, validates the file, orchestrates the two-stage pipeline, and displays the result. After showing the verdict it prompts the user for explicit confirmation before revealing any recommended actions — nothing is reported, forwarded, or deleted automatically. Supports a `--json` flag to skip interactive prompts and output raw JSON for use in other tools or pipelines.

---

### `main.py` *(project root)* — Root Launcher

A minimal shim that adds `scripts/` to the Python path and delegates to the skill's `main.py`, allowing the tool to be run from the project root without navigating into the skill directory.

---

## Human-in-the-Loop Gate

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
