# Detection Evaluation (honest numbers)

ScamShield's message analyzer is **rule-based and explainable**. It is not a trained model and has no live threat intelligence, so it will miss novel scam wording. This page reports exactly how it was measured.

"Flagged" means the verdict was `suspicious` or `likely_scam`. "Strict" means a scam was rated `likely_scam` and a benign message was rated `safe`.

| Set | Size | What it is | Precision | Recall | Strict accuracy | Notes |
|---|---|---|---|---|---|---|
| `tests/data/labeled.jsonl` | 30 (20 scam, 10 benign) | Original benchmark used while building the rules | 1.00 | 1.00 | 30/30 | **Tuned on**, so this is a development set, not proof of generalization |
| `tests/data/regression_probe.jsonl` | 20 (13 scam, 7 benign) | Mixed review set; its one miss (a tax-refund SMS with a shortened link) drove the fixes below | 1.00 | 1.00 | 19/20 | **Tuned on** after review. The remaining non-strict case is an emotional "hospital emergency" payment appeal, deliberately rated `suspicious` |
| `tests/data/fresh_eval.jsonl` | 20 (12 scam, 8 benign) | Written *before* the fixes and never used for tuning | 1.00 | 1.00 | 17/20 | Best estimate of generalization. Before the fixes it scored 16/20 strict |

Interpretation: no scam in any set was rated `safe`, and no benign message was flagged. A few scams are only `suspicious` rather than `likely_scam`, which is the conservative failure mode we prefer. Twenty to thirty hand-written messages is a small sample, so treat these as sanity checks, not production accuracy.

## Fixes made after review
- URL extraction now recognizes bare shortener and abuse-prone domains (`bit.ly/...`, `tinyurl.com/...`, `.tk`, `.ly`, ...). Previously a shortened link in a tax-refund SMS was ignored and the message was rated `safe`.
- New red flags: fake refund/reward claims, payment-method update lures, fake virus alerts, guaranteed-returns investment pitches, emotional payment appeals; plus Hinglish OTP and "card block ho gaya" phrasings and a `tax_refund` category.
- Benign messages now return category `none` instead of `general_fraud`.

## Reproduce
```bash
pytest tests/test_detection.py tests/test_improvements.py -v
```

## Known limitations
- Rules and regexes, not machine learning; novel wording can slip through.
- English and Hinglish only; regional-language scripts are not analyzed.
- Link analysis is static: it cannot know whether a domain is newly registered or already reported.
- Not a replacement for official reporting channels or professional advice.
