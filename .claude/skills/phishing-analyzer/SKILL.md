---
name: phishing-analyzer
description: >
  Analyze a .eml file for phishing. Use when asked whether an email is a phishing
  attempt. Returns a grounded binary verdict (PHISHING / NOT_PHISHING / UNCERTAIN)
  with a confidence level. States uncertainty upfront. Never escalates without
  explicit human confirmation.
---

# Phishing Email Analyzer

## When to Use This Skill

- A user wants to know whether a specific email is a phishing attempt
- An email has been flagged as suspicious and needs triage
- A `.eml` file is available and needs automated pre-screening before human review
- You need a confidence-rated, evidence-backed verdict to inform a security decision
- You want attachment hashes or URL destinations checked before opening anything

## When NOT to Use This Skill

- The input is not a `.eml` file (e.g. a screenshot, forwarded text, or copy-paste) — the extractor requires raw RFC 2822 format to parse headers and attachments
- You need real-time inbox scanning or bulk processing of a mail queue — this skill analyzes one email at a time interactively
- A definitive legal or forensic conclusion is required — this skill provides a triage signal, not a formal security investigation
- The email has already been opened and links clicked — this skill assesses risk before action; post-exposure response requires a separate incident workflow
- You want the skill to automatically report, delete, or forward the email — all actions require explicit human confirmation; this skill will not act on your behalf

---

## Expected Inputs

| Input | Format | Required |
|---|---|---|
| Email file | Raw `.eml` file (RFC 2822 format) | Yes |
| `--json` flag | CLI flag for machine-readable output | No |

**How to pass the input:**
```bash
python main.py path/to/email.eml          # interactive mode
python main.py path/to/email.eml --json   # JSON output mode
```

The `.eml` file must contain the full raw email including headers. Emails exported
from mail clients (Outlook, Apple Mail, Gmail "Download message") are acceptable.
Forwarded plain-text copies without headers will result in an `UNCERTAIN` verdict
due to missing authentication data.

---

## Expected Output

### Verdict

| Value | Meaning |
|---|---|
| `PHISHING` | Evidence clearly indicates malicious intent |
| `NOT_PHISHING` | Evidence clearly indicates legitimate email |
| `UNCERTAIN` | Data insufficient or contradictory — stated upfront before anything else |

### Confidence Level

| Value | Meaning |
|---|---|
| `HIGH` | Multiple strong indicators point in the same direction |
| `MEDIUM` | Some indicators present but not conclusive |
| `LOW` | Minimal data available; verdict is a weak signal only |

### Full JSON Schema

```json
{
  "verdict": "PHISHING | NOT_PHISHING | UNCERTAIN",
  "confidence": "HIGH | MEDIUM | LOW",
  "risk_score": 0,
  "data_sufficient": true,
  "uncertainty_statement": null,
  "evidence": [
    "SPF=fail",
    "URL redirects to paypa1.com (edit-distance 1 from paypal)"
  ],
  "summary": "One factual sentence stating what was found.",
  "user_message": "2-3 sentences written for a non-technical reader.",
  "recommended_actions": [
    "Consider reporting to security@company.com",
    "Do not click any links in this email"
  ]
}
```

- `risk_score` — integer 0–100 (0 = definitely safe, 100 = definitely phishing)
- `data_sufficient` — `false` when the available data cannot support a confident verdict
- `uncertainty_statement` — always populated (non-null) when `verdict` is `UNCERTAIN`
- `evidence` — only cites specific values extracted from the email; never invented
- `recommended_actions` — pending human approval; none are executed automatically

---

## Important Limitations and Checks

### What the Skill Can Detect
- SPF / DKIM / DMARC authentication failures
- Lookalike sender domains within Levenshtein edit-distance ≤ 3 of 30+ known brands
- URL redirect chains to suspicious final destinations
- Suspicious attachment types via filename extension and MIME type
- Mismatch between `From:` display name and actual sending domain

### What the Skill Cannot Detect
- **Spear-phishing with no technical failures** — a well-crafted spear-phishing email from a legitimately registered domain with passing SPF/DKIM/DMARC may return `NOT_PHISHING` or `UNCERTAIN`. Technical signals alone cannot catch every social-engineering attack.
- **Email body content analysis** — the extractor does not parse free-form body text for urgency cues, grammar, or tone. The AI judge only sees structured extracted data, not the raw message body.
- **Homoglyph domain attacks** — lookalike detection uses ASCII Levenshtein distance only; Unicode homoglyphs (e.g. Cyrillic `а` vs Latin `a`) are not caught.
- **Zero-day or newly registered phishing domains** — domains with no brand resemblance and passing auth records will not be flagged.
- **Attachments opened in-session** — attachment hashes are returned for threat-intel lookup but are not automatically checked against any external database.
- **Images or QR codes inside the email body** — embedded images and QR codes in HTML bodies are not decoded or inspected.

### Anti-Hallucination Checks
- Output is enforced by a Pydantic schema — Claude cannot return fields outside the model
- Every `evidence` item must reference a specific extracted value; generic claims are forbidden in the system prompt
- `data_sufficient=false` is required when fewer than 2 concrete evidence items can be cited
- `UNCERTAIN` verdict is mandatory when signals are contradictory or data is sparse — the skill never guesses between `PHISHING` and `NOT_PHISHING` when unsure

### Human-in-the-Loop Policy
- `recommended_actions` are shown **only after** the human explicitly types `y`
- The skill takes **no automated action** — it does not send emails, call APIs, or modify any system state
- All escalation, reporting, and deletion must be performed manually by the user

---

## References

- `references/known_brands.md` — full brand list, detection logic, and known limitations
- `references/auth_headers_reference.md` — SPF/DKIM/DMARC result codes and meanings
- `assets/sample_phishing.eml` — test fixture with SPF/DKIM/DMARC failures and a lookalike PayPal domain
