import json
from typing import Literal, Optional

import anthropic
from pydantic import BaseModel, Field

from analyzer import EmailAnalysis


# ---------------------------------------------------------------------------
# Output schema — enforced by Pydantic + structured outputs.
# Claude cannot return fields outside this model.
# ---------------------------------------------------------------------------

class PhishingVerdict(BaseModel):
    verdict: Literal["PHISHING", "NOT_PHISHING", "UNCERTAIN"] = Field(
        description=(
            "PHISHING if evidence clearly indicates malicious intent. "
            "NOT_PHISHING if evidence clearly indicates legitimate email. "
            "UNCERTAIN when available data is insufficient or contradictory — "
            "never guess between PHISHING and NOT_PHISHING when unsure."
        )
    )
    confidence: Literal["HIGH", "MEDIUM", "LOW"] = Field(
        description="Confidence in the verdict based solely on available data."
    )
    risk_score: int = Field(
        ge=0, le=100,
        description="0 = definitely safe, 100 = definitely phishing.",
    )
    data_sufficient: bool = Field(
        description=(
            "False when the provided data cannot support a confident verdict. "
            "Must be False whenever verdict is UNCERTAIN."
        )
    )
    uncertainty_statement: Optional[str] = Field(
        default=None,
        description=(
            "Required when verdict is UNCERTAIN. "
            "State specifically what data is missing or contradictory. "
            "Do NOT leave null when verdict is UNCERTAIN."
        ),
    )
    evidence: list[str] = Field(
        description=(
            "Each item must be a specific value observed in the provided JSON data. "
            "Examples: 'SPF=fail', 'URL redirects from X to Y', "
            "'domain paypa1.com is edit-distance 1 from paypal'. "
            "NEVER invent indicators not present in the input. "
            "If no concrete evidence exists, return an empty list."
        )
    )
    summary: str = Field(description="One factual sentence stating what was found.")
    user_message: str = Field(
        description=(
            "2-3 sentences for a non-technical reader. "
            "If verdict is UNCERTAIN, say so explicitly upfront."
        )
    )
    recommended_actions: list[str] = Field(
        description=(
            "Actions a human should consider taking. "
            "These are RECOMMENDATIONS ONLY — they are not executed automatically. "
            "A human must approve each action before it is taken."
        )
    )


# ---------------------------------------------------------------------------
# System prompt — grounding and anti-hallucination rules are explicit.
# ---------------------------------------------------------------------------

_SYSTEM_PROMPT = """You are a cybersecurity analyst performing phishing email triage.

INPUT: Structured technical data automatically extracted from an email (headers, auth
results, URL resolution, attachment hashes, lookalike-domain distances). You did NOT
read the raw email body yourself — only the extracted data below is available to you.

OUTPUT: A PhishingVerdict JSON object with the following strict rules.

═══════════════════════════════════════════════════════
ANTI-HALLUCINATION RULES (violations invalidate results)
═══════════════════════════════════════════════════════
1. Every string in `evidence` must quote or reference a specific value present in the
   provided JSON. If a field in the input is null, absent, or empty — do NOT reference
   it as evidence and do NOT assume its value.

2. Do NOT invent indicators such as "urgent language", "grammar errors", "suspicious
   subject" unless that text was extracted and passed in the data.

3. Do NOT infer the email body's contents. You only know what the extractor found.

4. Set data_sufficient=false and verdict=UNCERTAIN when:
   - Fewer than 2 concrete evidence items can be cited, OR
   - Auth results (SPF/DKIM/DMARC) are all null AND no URLs or attachments exist, OR
   - Signals are contradictory with no clear preponderance.

5. uncertainty_statement is REQUIRED (non-null) whenever verdict=UNCERTAIN.
   It must name specifically what is missing or contradictory.

6. If verdict is UNCERTAIN, state that upfront in user_message.
   Never silently guess between PHISHING and NOT_PHISHING when uncertain.

═══════════════════════════════════════════════════════
HUMAN-IN-THE-LOOP POLICY
═══════════════════════════════════════════════════════
recommended_actions lists what a human SHOULD CONSIDER doing.
The system NEVER escalates, reports, or deletes automatically.
A human must review and approve every action before it is taken.
Use phrases like "Consider reporting…", "You may want to…", not "Report now."

═══════════════════════════════════════════════════════
VERDICT GUIDANCE
═══════════════════════════════════════════════════════
PHISHING indicators (cite only if present in data):
  - SPF/DKIM/DMARC failure on a domain impersonating a known brand
  - URL redirects to a domain with edit-distance ≤ 2 from a known brand
  - Lookalike sender domain (edit-distance ≤ 2 from a brand)
  - Suspicious attachment type (exe, js, vbs, docm, xlsm)

NOT_PHISHING indicators (cite only if present in data):
  - SPF=pass + DKIM=pass + DMARC=pass from a recognized domain
  - No lookalike domains, no redirecting URLs, no suspicious attachments

UNCERTAIN: when evidence is mixed or data is sparse."""


# ---------------------------------------------------------------------------
# Public interface
# ---------------------------------------------------------------------------

def _build_payload(analysis: EmailAnalysis) -> dict:
    notable = {
        k: v for k, v in analysis.headers.items()
        if k in (
            "Received", "X-Originating-IP", "X-Mailer", "User-Agent",
            "Authentication-Results", "Received-SPF", "DKIM-Signature",
            "X-Spam-Status", "X-Spam-Score",
        )
    }
    return {
        "from": analysis.raw_from,
        "subject": analysis.raw_subject,
        "reply_to": analysis.raw_reply_to,
        "auth": {
            "spf": analysis.spf,
            "dkim": analysis.dkim,
            "dmarc": analysis.dmarc,
        },
        "urls": analysis.urls,
        "attachments": analysis.attachment_hashes,
        "lookalike_domains": analysis.lookalike_domains,
        "notable_headers": notable,
        "data_availability": {
            "spf_present": analysis.spf is not None,
            "dkim_present": analysis.dkim is not None,
            "dmarc_present": analysis.dmarc is not None,
            "url_count": len(analysis.urls),
            "attachment_count": len(analysis.attachment_hashes),
            "lookalike_count": len(analysis.lookalike_domains),
        },
    }


def judge_email(analysis: EmailAnalysis) -> PhishingVerdict:
    client = anthropic.Anthropic()
    payload = _build_payload(analysis)

    response = client.messages.parse(
        model="claude-opus-4-7",
        max_tokens=4096,
        thinking={"type": "adaptive"},
        system=[{
            "type": "text",
            "text": _SYSTEM_PROMPT,
            "cache_control": {"type": "ephemeral"},
        }],
        messages=[{
            "role": "user",
            "content": (
                "Analyze the extracted email data below and return a PhishingVerdict.\n\n"
                + json.dumps(payload, indent=2)
            ),
        }],
        output_format=PhishingVerdict,
    )

    if response.parsed_output is None:
        return PhishingVerdict(
            verdict="UNCERTAIN",
            confidence="LOW",
            risk_score=0,
            data_sufficient=False,
            uncertainty_statement="The model declined to analyze this email or returned an unparseable response.",
            evidence=[],
            summary="Analysis could not be completed.",
            user_message=(
                "UNCERTAIN: The system was unable to complete its analysis. "
                "Please forward this email to your IT or security team for manual review."
            ),
            recommended_actions=["Forward email to IT Security for manual review."],
        )

    return response.parsed_output


def format_report(verdict: PhishingVerdict) -> str:
    bar = "=" * 62

    verdict_label = {
        "PHISHING": "⚠  PHISHING DETECTED",
        "NOT_PHISHING": "✓  NOT PHISHING",
        "UNCERTAIN": "?  UNCERTAIN — HUMAN REVIEW NEEDED",
    }.get(verdict.verdict, verdict.verdict)

    lines = [
        bar,
        f"  {verdict_label}",
        f"  Confidence: {verdict.confidence}  |  Risk Score: {verdict.risk_score}/100",
        bar,
    ]

    if verdict.verdict == "UNCERTAIN" and verdict.uncertainty_statement:
        lines += [
            "",
            "IMPORTANT — System cannot determine with confidence:",
            f"  {verdict.uncertainty_statement}",
        ]

    lines += ["", f"Summary: {verdict.summary}", "", f"For you: {verdict.user_message}"]

    if verdict.evidence:
        lines += ["", "Evidence found in this email's data:"]
        for item in verdict.evidence:
            lines.append(f"  • {item}")
    else:
        lines += ["", "Evidence: none — insufficient data to cite concrete indicators."]

    lines += [
        "",
        "─" * 62,
        "  Recommended actions are pending YOUR approval.",
        "  This system has taken NO automated action.",
        "─" * 62,
    ]
    return "\n".join(lines)
