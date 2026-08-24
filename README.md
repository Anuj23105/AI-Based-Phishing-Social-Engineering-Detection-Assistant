# PhishGuard AI

An explainable phishing and social-engineering detection assistant. Paste an email, SMS, chat
message, link or website and it returns a 0–100 risk score, the specific reasons behind it, and the
actions to take — in language a non-technical user can act on.

Built for the problem statement *AI-Based Phishing & Social Engineering Detection Assistant*.

---

## The detection pipeline

```
                          Input
                            │
              Text & URL Preprocessing
                            │
                    Feature Extraction
        ┌───────────────────┼───────────────────┐
   Suspicious          Urgency /           Sender & domain
   language            manipulation        signals
        │                   │                   │
   URL characteristics      Credential / payment requests
        └───────────────────┼───────────────────┘
                            │
                   AI/ML Risk Analysis
         (trained classifiers · threat intel · optional LLM)
                            │
                      Risk Scoring
                            │
              Explanation + Safe Action
```

Every request executes these stages in order, and the API returns the trace — which stage ran, what
it produced, and how long it took. The UI renders it live, so a user can see *why* a verdict exists
rather than being handed a number.

---

## Architecture

Three tiers, each independently runnable:

| Tier | Stack | Responsibility |
|---|---|---|
| `client/` | React 18 + Vite | Analyser workspace, explanation UI, dashboard, awareness module |
| `server/` | Node 22 + Express | Rule engine, pipeline orchestration, persistence, REST API |
| `ml/` | Python 3.12 + FastAPI + scikit-learn | Trained message and URL classifiers with per-feature explanations |

**The tiers degrade independently.** The rule engine runs fully offline and always produces a
complete explainable verdict. If the ML service is down, the API says so in the response and the
verdict stands on rules alone; a circuit breaker stops a dead service costing latency on every
request. The LLM layer is off unless an API key is configured. No layer can fail a request.

---

## Quick start

Requires Node 18+ and Python 3.10+.

```bash
# 1. install everything
npm run install:all
cd ml && python -m venv .venv && .venv\Scripts\pip install -r requirements.txt && cd ..

# 2. build the corpus and train the models (~2 minutes, fully offline)
cd ml
.venv\Scripts\python training/generate_corpus.py
.venv\Scripts\python training/train_message_model.py
.venv\Scripts\python training/train_url_model.py
.venv\Scripts\python training/evaluate.py
cd ..
```

Then run the three tiers (three terminals):

```bash
# terminal 1 — ML service
cd ml && .venv\Scripts\python -m uvicorn app.main:app --port 8000

# terminal 2 + 3 — API and UI together
npm run dev
```

Open **http://localhost:5173**. The status strip at the top shows which tiers are live.

Configuration is optional — copy `.env.example` to `server/.env` only if you want the LLM layer,
Google Safe Browsing, or an API key. Everything works with no keys at all.

---

## Measured results

Two datasets, and the difference between them matters:

* **Generated corpus** (`ml/training/datasets/`) — 8,000 messages and 9,000 URLs composed from
  templates and slot banks. Used for training.
* **Gold set** (`datasets/gold-eval.csv`, `datasets/gold-urls.csv`) — 120 messages and 70 URLs
  written by hand, independently of the templates, including deliberate hard negatives: genuine OTP
  alerts, genuine blocked-sign-in notices, genuine failed-payment mail, real bank debit alerts.

Both tiers are scored on the *same* gold set, so they are directly comparable.

### Full pipeline (rules + ML) — `npm run evaluate:pipeline`

| Metric | Result | Target |
|---|---|---|
| Accuracy | **100.0%** | > 90% |
| Precision / Recall | 100.0% / 100.0% | — |
| False positive rate | **0.0%** | < 10% |
| Latency (mean / p95 / max) | **14 ms / 29 ms / 132 ms** | < 5 s |
| Explanation for every prediction | yes | yes |

### Rule engine alone (no ML, fully offline) — `npm run evaluate`

| Decision rule | Accuracy | FPR | Recall |
|---|---|---|---|
| Medium-or-High counts as a detection | **97.5%** | 1.7% | 96.7% |
| High Risk only counts as a detection | 84.2% | 0.0% | 68.3% |
| URLs, Medium-or-High | 98.6% | 0.0% | 97.1% |

Worst-case latency 45 ms. Both decision rules are reported because the product treats *Medium* as
"do not act until you verify", which is already a successful intervention.

### Individual models — `cd ml && .venv\Scripts\python training/evaluate.py`

| Model | Gold set | Held-out split of generated corpus |
|---|---|---|
| Message classifier | 100% accuracy, 0% FPR, ROC-AUC 1.000 | 100% (not informative) |
| URL classifier | 100% accuracy, 0% FPR | 99.8% |

### Read these numbers honestly

* **The ~1.000 on the generated corpus is meaningless on its own.** Train and test rows come from
  the same template banks, so the task is trivially separable. It confirms the pipeline fits; nothing
  more. It is reported only so the gap to the gold set is visible.
* **The gold-set 100% is an upper bound, not a field estimate.** After the first evaluation exposed
  missed attack families (chat-delivered vishing, QR collect-request fraud, sideloaded APK malware),
  the corpus was extended to cover them and rules were tightened. Those are real and important
  attack families, but the gold set informed that work, so it is no longer a fully blind test. A
  120-sample set also has wide confidence intervals.
* **The threshold was chosen out-of-sample.** `training/tune_threshold.py` splits the gold set 50/50
  three hundred times, picks the operating point on one half and scores the other, then ships the
  median pick (0.34). Held-out accuracy across those splits: 1.000, worst split 1.000.
* **What would make these numbers trustworthy** is a blind evaluation on live traffic that nobody
  tuned against. Both training scripts accept `--data`, so a real corpus drops in without code
  changes — see *Training on real data* below.

---

## What it detects

**Phishing:** fake login pages, credential harvesting, malicious links, brand impersonation,
Business Email Compromise, fake banking and payment requests, urgent-action scams, malware
delivery.

**Social engineering — 17 named tactics**, each with weighted patterns and a plain-language
explanation of why it works: artificial urgency, fear and threat of loss, authority impersonation,
credential harvesting, prize and lottery bait, payment redirection, fake technical support, fake job
offers, emotional manipulation, vague link lures, impersonal addressing, channel switching to
WhatsApp/Telegram, secrecy pressure, BEC patterns, delivery pretexts, unsolicited security alerts.

**URLs:** typosquatting (edit-distance to real brand domains), homograph and punycode attacks,
brand names in subdomains, URL shorteners, high-abuse TLDs, free hosting, raw IP hosts, `@`
obfuscation, open redirects, identity parameters, dangerous file extensions, deep subdomain chains.

**Websites:** login-form detection, cross-domain credential posting, exfiltration to Telegram bots
and form services, hotlinked brand assets, obfuscated scripts, blocked paste and right-click, hidden
iframes, thin single-page clones, missing legal pages.

**Email headers:** display-name spoofing, reply-to redirection, envelope mismatch, SPF/DKIM/DMARC
verdicts, disposable and free-mail senders, look-alike sender domains, fake reply threads.

---

## How scoring works

Signals carry weights. Weights are summed **per category with a cap**, so a message shouting five
urgency phrases still scores as one urgency finding with a bounded bonus — this is the main lever
keeping false positives low. Trust signals (verified official domain, SPF pass, genuine transactional
phrasing) subtract, but their effect is damped when the evidence is strong, so a compromised
mailbox with valid SPF is not excused by it. The net total passes through a saturating curve
`100 × (1 − e^(−net/29))`, and individually conclusive findings apply a score floor.

Bands: **0–30 Low · 31–70 Medium · 71–100 High**.

Every number is inspectable in the API response and in the UI's "How the score was calculated"
panel: evidence points, damping, which categories were capped, and the curve output.

Constants live in `server/src/engine/riskScorer.js` (`SCORING`) and are published through
`GET /api/education/tactics`, so results can be audited rather than trusted.

---

## Explainability

Both served ML models are linear, which is a deliberate choice over a stronger transformer:

```
logit = intercept + Σ (coefficient_i × value_i)
```

Each term is one token or one engineered feature, so `top_indicators` in the API response is the
actual arithmetic behind the probability — not a SHAP or LIME approximation that could disagree with
the decision. Inference is ~1–13 ms on CPU. `ml/app/inference.py` only requires `predict_proba`, so a
fine-tuned DistilBERT can replace the artifact later without touching the API or the UI.

Marker tokens are translated for display: the user sees "shortened link that hides its destination",
not `<url_shortener>`.

---

## API

| Method | Path | Purpose |
|---|---|---|
| POST | `/api/analyze` | message, email, SMS, chat or pasted HTML |
| POST | `/api/analyze/url` | a single link, without opening it |
| POST | `/api/analyze/website` | fetch the live page (SSRF-guarded), then analyse |
| POST | `/api/analyze/batch` | up to 25 items |
| GET | `/api/analyze/pipeline` | stage definitions |
| GET | `/api/history` `/api/stats` | dashboard data |
| POST/GET | `/api/reports` | report phishing; feeds the threat-intel stage |
| GET | `/api/education/tips` `/api/education/tactics` | awareness content, tactic library, scoring rules |
| GET | `/api/health` `/api/model/info` | tier status, model card, gold-set metrics |

```bash
curl -X POST http://localhost:4000/api/analyze \
  -H "content-type: application/json" \
  -d '{"content":"Your bank account will be suspended within 24 hours. Click here to verify your identity."}'
```

Returns `score`, `level`, `confidence`, `explanation` (summary, reasons, whyDangerous,
recommendations, tactics, trustIndicators), `signals`, `featureGroups`, `breakdown`, `entities`,
`ml`, `ai`, `intel`, `pipeline` and `timings`.

---

## Training on real data

The generated corpus exists because public phishing datasets cannot be redistributed in a repo and
the popular ones miss UPI, Aadhaar, KYC and courier pretexts. To train on a real corpus:

```bash
.venv\Scripts\python training/train_message_model.py --data path/to/real.csv --text-col body --label-col is_phishing
.venv\Scripts\python training/train_url_model.py --data path/to/urls.csv --url-col url --label-col label
.venv\Scripts\python training/evaluate.py          # re-scores against the gold set
.venv\Scripts\python training/tune_threshold.py    # re-picks the operating point
curl -X POST http://localhost:8000/admin/reload    # hot-reload without a restart
```

Nothing else changes: the feature extractors, API contract and UI are unaffected.

---

## Security notes

* **Live URL fetching is SSRF-guarded**: http/https only, private/loopback/link-local/metadata
  addresses refused before and after redirects, size and time capped, HTML/text only, no cookies.
* **Message bodies are never stored.** History keeps a 160-character redacted preview. Reporter IPs
  are hashed, never retained.
* **API endpoints are unauthenticated by default** — appropriate for local development, not for a
  public deployment. Set `API_KEY` in `server/.env` to require `x-api-key` on every `/api` request,
  and put the service behind TLS and a real rate limiter (the built-in one is in-process and does not
  survive a restart or coordinate across replicas).
* Secrets stay server-side. The browser never sees an LLM or Safe Browsing key.

---

## Project structure

```
datasets/                  gold-eval.csv, gold-urls.csv   (shared, hand written)
ml/
  app/
    knowledge.py           brands, TLDs, shorteners, suffix rules
    features/text.py        message normalisation and marker tokens
    features/url.py         50 engineered lexical features
    inference.py           loading, prediction, exact contributions
    main.py                FastAPI service
  training/
    generate_corpus.py     template + slot corpus generator
    train_message_model.py TF-IDF (word + char) → LogisticRegression
    train_url_model.py     scaled features → LogisticRegression (+ RF benchmark)
    evaluate.py            in-distribution vs gold-set metrics
    tune_threshold.py      out-of-sample operating point selection
server/
  src/engine/              rule engine: constants, url/text/header/page analyzers,
                           riskScorer, explainer, pipeline orchestrator (index.js)
  src/services/            ML client (circuit breaker), LLM client, threat intel,
                           SSRF-guarded fetcher, pipeline orchestration
  src/routes/ middleware/ store/
  evaluation/              gold-set harness for the rule engine and full pipeline
client/src/
  components/              Verdict, Reasons, PipelineTrace, MlPanel, Evidence,
                           AnalyzerView, DashboardView, AwarenessView
```

---

## Limitations

* Detection is **advisory**. It reduces risk; it does not replace verifying anything involving money
  or credentials through an official channel. The UI says so on every screen.
* Tuned for English and Hinglish phishing with an Indian-context brand and pretext list. Other
  languages will under-perform until the tactic library and corpus are extended.
* No live domain-age, WHOIS or certificate-transparency lookups. Community reports and optional Safe
  Browsing are the only external intelligence.
* Website analysis reads the HTML the server receives. A page that renders its login form purely
  through JavaScript after load will look thinner than it is; headless-browser rendering would fix
  this and is not implemented.
* Accessibility has been built for (semantic landmarks, keyboard operation, focus-visible styles,
  reduced-motion support, and risk never conveyed by colour alone) but full WCAG conformance needs
  manual testing with assistive technology and an expert review.
#   A I - B a s e d - P h i s h i n g - S o c i a l - E n g i n e e r i n g - D e t e c t i o n - A s s i s t a n t  
 