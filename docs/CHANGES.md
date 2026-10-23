# Review fixes (23 Oct 2026)

**Detection**
- Shortened and abuse-prone links without `http://` (for example `bit.ly/...`, `tinyurl.com/...`, `.tk`) are now extracted and scored. Previously a tax-refund scam hidden behind `bit.ly` was rated `safe`.
- Added red flags (fake refund claims, payment-method update lures, fake virus alerts, guaranteed returns, emotional payment appeals), Hinglish OTP phrasings, and a `tax_refund` category. Benign messages now report category `none`.

**Correctness bugs**
- `open_case` could crash with `sqlite3.IntegrityError` when a random speakable case ID collided with an existing one. It now retries.
- `fallback.py` referenced an undefined `logger` inside an error path (would raise `NameError`). Fixed.
- Tests wrote to the real `data/auralert.db` and could fail intermittently. They now use an isolated temporary database.

**Honesty fixes**
- `notify_family` claimed "I have sent an emergency alert" and "blocked the funds transfer" although nothing is sent. It now says the alert is prepared and **not sent**, with status `simulated`.
- Removed unverifiable claims ("100% precision/recall", "verified official numbers", "SSRF immunity", "sub-50ms guarantee", "35/38 tests"). Real numbers are in `docs/EVALUATION.md`.
- UK reporting updated: Action Fraud was replaced by **Report Fraud** on 4 Dec 2025 (same phone number).
- Removed internal "Prompt 10B" labels from tool descriptions and the UI.

**Bedrock**
- The Bedrock loop now keeps conversation history across turns.
- Added `GET /api/status` (which brains are configured, no secrets) and `scripts/check_bedrock.py` to prove Bedrock works before you claim it.

**Project hygiene**
- Explicit ruff rule set in `pyproject.toml`; lint and format clean. 54 tests (was 39).
- Added `render.yaml`, `.dockerignore`, complete `.env.example`; `.env` and the database are not included in the delivered zip.
- Rewrote `docs/DEVPOST.md` and `docs/SUBMISSION-CHECKLIST.md` so nothing is pre-ticked.


# Review round 2 (new features)
- **Live Call Guard false alarms fixed:** a genuine bank warning ("never share your OTP") triggered "hang up now"; a normal DHL delivery call and a "Hi dad, lost my charger" call were flagged; the user's own words were scored as threats. Now only the caller is scored, protective phrasing is ignored, and courier / "Hi mom" rules need a real threat or money ask.
- **Family alerts now require the user to ask.** Removed three code paths that auto-"notified" a made-up contact ("Rohan (Son)") on every high-risk turn.
- Removed duplicate function definitions in `cases/service.py` (four earlier copies were silently overridden).
- Fixed safe-word verification by voice: it read the wrong word ("my") from sentences like "he is my son and the safe word is banana".
- Broader natural-language intents for safe word, repeat-offender and family-alert commands (with negation guard so a scammer's "do not inform your family" is analyzed, not obeyed).
- 81 tests, lint and format clean.
