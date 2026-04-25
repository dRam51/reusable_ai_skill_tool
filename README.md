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

The data collector. Contains no AI — it purely reads the raw `.eml` file and pulls out measurable facts using Python's standard `email` library and `requests`.

| Function | What it does |
|---|---|
| `_extract_headers()` | Parses every email header into a dict (From, Subject, Received, X-Originating-IP, etc.) |
| `_extract_auth()` | Scrapes `Authentication-Results` and `Received-SPF` headers with regex to get SPF, DKIM, and DMARC pass/fail results |
| `_resolve_url()` | Follows a single URL through all redirects and records the original URL, final destination, and HTTP status code |
| `_extract_urls()` | Finds every link in the plain-text and HTML body parts, deduplicates them, and calls `_resolve_url()` on each (capped at 20) |
| `_extract_attachments()` | Reads each attachment's raw bytes and computes MD5 and SHA-256 hashes for threat-intel lookup |
| `_check_lookalikes()` | Collects all domains from From/Reply-To/Return-Path headers and URL hosts, then measures Levenshtein edit distance against 30+ known brand names — flags anything within distance ≤ 3 |
| `analyze_email()` | Public entry point — calls all of the above and returns an `EmailAnalysis` dataclass |

All findings are packaged into an `EmailAnalysis` dataclass that is passed directly to `skill.py`.

---

### `scripts/skill.py` — Stage 2: AI Judgment

The AI brain. Takes the structured `EmailAnalysis` from `analyzer.py` and uses the Anthropic SDK to produce a validated, schema-constrained verdict.

| Component | What it does |
|---|---|
| `PhishingVerdict` (Pydantic model) | Defines the exact output shape Claude must return — `verdict`, `confidence`, `risk_score`, `evidence`, `recommended_actions`, and more. Claude cannot return fields outside this model. |
| `_SYSTEM_PROMPT` | Instructs `claude-opus-4-7` to act as a phishing analyst. Contains explicit anti-hallucination rules: every `evidence` item must quote a specific value from the input data, generic claims are forbidden, and `UNCERTAIN` is required when fewer than 2 concrete evidence items can be cited. |
| `_build_payload()` | Converts `EmailAnalysis` into a clean JSON dict for the API call. Includes a `data_availability` section that explicitly tells Claude which fields are present vs null, preventing false inference. |
| `judge_email()` | Calls `client.messages.parse()` with adaptive thinking and a cached system prompt. Returns a validated `PhishingVerdict` object. Falls back to a safe `UNCERTAIN` verdict if the model declines or returns an unparseable response. |
| `format_report()` | Formats the `PhishingVerdict` into a readable terminal report with verdict banner, evidence bullets, and a reminder that no automated action has been taken. |

---

### `scripts/main.py` — CLI + Human-in-the-Loop Gate

The entry point and safety gate. The only script a user directly runs.

| Function | What it does |
|---|---|
| `main()` | Parses CLI arguments, validates the `.eml` file, orchestrates the two-stage pipeline, and routes output to either JSON or interactive mode |
| `_interactive_flow()` | Displays the formatted report then branches on verdict: prompts for confirmation before showing any actions for `PHISHING` or `UNCERTAIN`; exits quietly for `NOT_PHISHING` |
| `_prompt_confirm()` | Reads a `[y/N]` response from the user; treats EOF and Ctrl-C as `N` to prevent accidental escalation |
| `_show_actions()` | Prints the `recommended_actions` list only after the user has confirmed — nothing is executed automatically |

`--json` mode skips all interactive prompts and prints raw JSON, useful for piping the verdict into other tools or systems.

---

### `main.py` *(project root)* — Root Launcher

A four-line shim. Adds `scripts/` to `sys.path` and calls the skill's `main()` function so the tool can be run from the project root without needing to `cd` into the skill directory.

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
