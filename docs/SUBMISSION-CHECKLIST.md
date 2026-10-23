# Submission Checklist: AURALERT for Alexa+

Deadline: **23 Oct 2026, 12:00 PM PT** (about 12:30 AM IST on 24 Oct). Aim to submit by 6 PM IST on 23 Oct. Confirm the time on the Devpost page.

Tick a box only after you have actually done and checked it. Nothing below is pre-ticked on purpose.

## 1. Code and tests
- [ ] `pytest` passes locally (expected: 81 passed) and `ruff check .` is clean
- [ ] `data/auralert.db` and `.env` are not in the repo (`git ls-files | grep -E "\.env$|\.db$"` prints nothing)
- [ ] No API keys anywhere in git history (`git log -p | grep -i "sk-or-\|AKIA"` prints nothing)
- [ ] OpenRouter key rotated if it was ever shared outside your machine

## 2. Bedrock (optional; skip if you cannot get model access)
- [ ] Model access enabled in the Bedrock console for your region; `BEDROCK_MODEL_ID` is a model or inference profile you can call
- [ ] `python scripts/check_bedrock.py` prints SUCCESS
- [ ] A live demo turn returns `"brain": "bedrock"` (check `/api/status` and the chip in the UI)
- [ ] If any of the above fails: do **not** tick AWS Builder and remove "Amazon Bedrock" from Built With

## 3. Deployment
- [ ] Deployed (see `docs/DEPLOY.md` or `render.yaml`) and public HTTPS URL recorded: `__________________`
- [ ] `ALLOWED_ORIGINS` and `ALLOWED_HOSTS` include that URL
- [ ] `python scripts/smoke_prod.py https://<your-url>` passes
- [ ] MCP Inspector connects to `https://<your-url>/mcp` and lists 17 tools
- [ ] The 6 scenarios in `docs/SCENARIOS.md` work on the live URL
- [ ] Server warmed 5 minutes before recording (free tiers sleep)

## 4. Repo
- [ ] Public GitHub repo with MIT license, README, topics (alexa, mcp, hackathon, security, scam-detection)
- [ ] README renders correctly; badges and links work
- [ ] `docs/FRICTION-LOG.md` entries are true to your experience (edit anything you did not actually run into)

## 5. Video (under 3:00)
- [ ] Follows `docs/DEMO-SCRIPT.md`; says "simulated Alexa+ experience" on screen and aloud
- [ ] Public YouTube/Vimeo, English, no copyrighted music; URL: `__________________`

## 6. Devpost form (see `docs/DEVPOST.md`)
- [ ] Title, tagline, description pasted; product feedback filled in with your real experience
- [ ] Track: Alexa+; mini-challenges: Open Source (and AWS Builder only if section 2 is fully ticked)
- [ ] Repo URL, live URL, video URL entered; Built With list matches reality
- [ ] Re-verify helplines in `data/regions.json` against official sites
- [ ] Submitted, and the confirmation page or email checked

## Biggest risks and mitigations
| Risk | Mitigation |
|---|---|
| Free host sleeps or is slow during judging | Warm it before recording; mention `?mock=1` offline mode in the README |
| Bedrock not available to you | Say so honestly; the fallback brain still demonstrates the full MCP flow |
| Judge tries an unusual scam message | Be upfront that detection is rule-based (`docs/EVALUATION.md`) |
| Microphone not available | The console has typed input and quick-start chips |
| Claims that cannot be reproduced | Keep every number in the docs tied to a command in this repo |
