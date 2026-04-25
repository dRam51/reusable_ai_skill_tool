# Email Authentication Headers Reference

Used by `analyzer.py` to parse SPF, DKIM, and DMARC results from raw email headers.

---

## SPF (Sender Policy Framework)

**Header:** `Received-SPF` or `Authentication-Results: spf=...`

| Result | Meaning | Phishing Signal |
|---|---|---|
| `pass` | Sending IP is authorized by the domain's DNS | Low risk |
| `fail` | Sending IP is NOT authorized — hard fail | High risk |
| `softfail` | Sending IP is NOT authorized — soft fail | Medium risk |
| `neutral` | Domain owner makes no assertion | Low signal |
| `none` | Domain has no SPF record | Low signal |
| `permerror` | Permanent error in SPF record | Medium risk |
| `temperror` | Temporary DNS lookup failure | Inconclusive |

**Example header:**
```
Received-SPF: fail (domain of attacker.com does not designate
  192.0.2.1 as permitted sender) client-ip=192.0.2.1;
```

---

## DKIM (DomainKeys Identified Mail)

**Header:** `Authentication-Results: dkim=...`

| Result | Meaning | Phishing Signal |
|---|---|---|
| `pass` | Signature verified — email not tampered | Low risk |
| `fail` | Signature invalid — email may be forged or altered | High risk |
| `neutral` | Signature present but policy neutral | Low signal |
| `none` | No DKIM signature | Low signal |
| `policy` | Signature valid but policy disallows | Medium risk |
| `permerror` | Permanent DKIM error | Medium risk |
| `temperror` | Temporary error | Inconclusive |

**Example header:**
```
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
  d=legit-company.com; s=selector1; ...
```

---

## DMARC (Domain-based Message Authentication, Reporting & Conformance)

**Header:** `Authentication-Results: dmarc=...`

| Result | Meaning | Phishing Signal |
|---|---|---|
| `pass` | SPF or DKIM aligns with From: domain | Low risk |
| `fail` | Neither SPF nor DKIM align with From: domain | High risk |
| `bestguesspass` | No DMARC record; best-guess pass | Low signal |
| `none` | Domain has no DMARC record | Low signal |

**Combined high-risk pattern:**
```
spf=fail + dkim=fail + dmarc=fail
```
This triple failure on a domain that resembles a known brand is the strongest
single phishing signal available from headers alone.

---

## Authentication-Results Header (Combined)

Modern mail servers consolidate all results in one header:

```
Authentication-Results: mx.example.com;
  dkim=pass header.i=@legit.com header.s=selector1 header.b=AbCdEfGh;
  spf=pass (example.com: domain of sender@legit.com designates
    203.0.113.1 as permitted sender) smtp.mailfrom=sender@legit.com;
  dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=legit.com
```

---

## Parsing Notes

`analyzer.py` extracts auth results using regex on `Authentication-Results`
and `Received-SPF`. If these headers are absent, `spf`, `dkim`, and `dmarc`
are returned as `None` — the AI judge is informed via `data_availability` and
must not invent values for missing fields.
