# Known Brands — Lookalike Domain Reference

Used by `analyzer.py` to flag sender domains and URL hosts that are within
Levenshtein edit-distance ≤ 3 of a known brand name.

## Brand List

| Brand Name | Category | Common Phishing Patterns |
|---|---|---|
| paypal | Payments | paypa1, paypai, paypa-l, pay-pal |
| amazon | E-commerce | arnazon, amaz0n, amazon-support |
| google | Tech | g00gle, gooogle, google-security |
| microsoft | Tech | micros0ft, microsofft, rnicrosft |
| apple | Tech | app1e, appie, apple-id |
| facebook | Social | faceb00k, facebolk, faceb0ok |
| netflix | Streaming | netfIix, netfl1x, netlfix |
| instagram | Social | instaqram, lnstagram |
| twitter | Social | tw1tter, twiter, twitterr |
| linkedin | Professional | linkedln, llnkedin |
| dropbox | Storage | dr0pbox, dropb0x |
| github | Dev | gıthub, githubb |
| chase | Banking | chas3, chace, chase-bank |
| bankofamerica | Banking | bankofamerica-secure, b0famerica |
| wellsfargo | Banking | wellsfarg0, wells-fargo |
| citibank | Banking | c1tibank, citibank-alert |
| irs | Government | irs-refund, irs-gov |
| usps | Shipping | usps-tracking, u5ps |
| fedex | Shipping | fed-ex, fedex-delivery, fedEx |
| ups | Shipping | ups-tracking, upss |
| dhl | Shipping | dh1, dhl-express |
| outlook | Email | 0utlook, outlookk |
| yahoo | Email | yah00, yahooo |
| gmail | Email | gmai1, gmaill |
| docusign | Documents | docusiqn, docu-sign |
| coinbase | Crypto | c0inbase, coinbas3 |
| binance | Crypto | binanse, b1nance |
| stripe | Payments | str1pe, stripee |
| shopify | E-commerce | sh0pify, shopifv |
| ebay | E-commerce | 3bay, ebay-motors |
| walmart | Retail | wa1mart, walmaart |

## Detection Logic

```python
# From analyzer.py
for brand in KNOWN_BRANDS:
    dist = levenshtein_distance(domain_name, brand)
    if 0 < dist <= 3:
        flag_as_suspicious()
```

Edit-distance of 0 is an exact match (legitimate or confirmed fake).
Edit-distance > 3 is too loose and produces too many false positives.

## Limitations

- Only checks the second-level domain (e.g. `paypa1` from `paypa1.com`).
- Does not check for homoglyph attacks (e.g. Cyrillic `а` vs Latin `a`).
- Does not validate WHOIS registration age.
- False positives possible for short generic words (e.g. `ups` can match unrelated domains).
