# PhishGuard AI — Project Explanation

A presentation guide: what it is, how it works, what to demo, and how to answer the hard questions.

---

## 1. The one-line pitch

> PhishGuard AI tells a user whether a message, link or website is trying to scam them — and, more
> importantly, **explains why in plain language and tells them exactly what to do next.**

---

## 2. The problem

Phishing works because of a **verification gap**, not a technology gap.

Spam filters already block the obvious attacks. What reaches people is the well-crafted 5%: a message
that looks like it came from their bank, arrives at a plausible moment, and gives them a reason to act
before they think. The victim is not careless; they simply have no fast way to check.

Three specific failures make this worse:

1. **Existing tools give a verdict, not an understanding.** "This message was blocked" teaches the
   user nothing. Next week the same tactic works on them somewhere else.
2. **Users cannot read a URL.** In `secure-sbi.login-verify.co`, the real owner is `login-verify.co`.
   Almost nobody parses that correctly under pressure.
3. **Over-blocking destroys trust.** A tool that flags real bank alerts as dangerous gets ignored, and
   then the one real warning is ignored too.

So the requirement is not just detection. It is **detection + explanation + a low false-positive rate**,
all three, or the tool fails in practice.

---

## 3. What we built

A web application with three tiers:

| Tier | Technology | Role |
|---|---|---|
| Frontend | React 18 + Vite | Paste content, see the verdict, the reasons, the pipeline and the actions |
| Backend | Node 22 + Express | Rule engine (17 social-engineering tactics), pipeline orchestration, persistence, REST API |
| ML service | Python 3.12 + FastAPI + scikit-learn | Trained message and URL classifiers with exact per-feature explanations |

It handles **emails (with headers), SMS, WhatsApp and chat messages, social DMs, URLs, and live
websites**.

Output for every input: a **0–100 risk score**, a **Low / Medium / High** band, a plain-language
summary, a ranked list of reasons with evidence quoted from the input, the manipulation tactics
detected, and specific safe actions.

---

## 4. How it works — the pipeline

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

### Stage 1 — Input
Auto-detects what it was given: raw email (header block present), HTML document, bare URL, short SMS,
or long-form message. The user does not have to classify their own input.

### Stage 2 — Text & URL Preprocessing
This is where evasion is undone before any analysis happens:

- Splits raw email into headers and body; unfolds folded headers.
- Reduces HTML to visible text.
- Strips **zero-width characters** used to break up filter keywords.
- Maps **homoglyphs** — Cyrillic `а` looks identical to Latin `a`.
- Reverses **leet-speak** (`p4yp4l` → `paypal`, `acc0unt` → `account`).
- Collapses **spaced-out letters** (`v e r i f y` → `verify`).
- Re-fangs defanged URLs (`hxxp://evil[.]com`).
- Extracts links, email addresses and phone numbers.

Skipping this step is why naive keyword filters fail: attackers only have to misspell one word.

### Stage 3 — Feature Extraction
Five feature groups, as in the diagram, producing weighted signals.

**Suspicious language** — obfuscation, shouting, filter-evasion artefacts, bare links, chain-forwarding.

**Urgency / manipulation** — a library of **17 named tactics**, each with multiple regex patterns, a
weight, a repeat bonus, a cap, and a human-readable reason it works:

urgency · fear/threat of loss · authority impersonation · credential harvesting · prize and lottery
bait · payment redirection · fake tech support · fake job offers · emotional manipulation · vague link
lures · impersonal addressing · channel switching to WhatsApp/Telegram · secrecy pressure · Business
Email Compromise · delivery pretexts · unsolicited security alerts · plus malware/QR/vishing families.

**Sender & domain signals** — display-name spoofing, reply-to redirection, envelope mismatch,
SPF/DKIM/DMARC verdicts, free-mail and disposable senders, look-alike sender domains, fake `Re:` threads.

**URL characteristics** — typosquatting by edit distance to real brand domains, homograph and punycode
attacks, brand names pushed into subdomains, shorteners, high-abuse TLDs, free hosting, raw IP hosts,
`@`-obfuscation, open redirects, identity parameters, dangerous file extensions.

**Credential / payment requests** — requests for passwords, OTPs, PINs, CVVs, Aadhaar, PAN, UPI PINs;
payment redirection; bank-detail changes; QR collect-request fraud.

For websites there is a sixth group: **login-form behaviour** — where the form actually posts,
exfiltration to Telegram bots and form services, hotlinked brand logos, obfuscated scripts, blocked
paste and right-click, hidden iframes, thin single-page clones.

### Stage 4 — AI/ML Risk Analysis
Runs **in parallel**, so this stage costs the slowest layer, not the sum:

- **Message classifier** — TF-IDF (word 1–2 grams + character 3–5 grams) → Logistic Regression.
- **URL classifier** — 50 engineered lexical features → standardised Logistic Regression.
- **Threat intelligence** — community reports (domains users have reported) + optional Google Safe Browsing.
- **Optional LLM review** — Gemini or any OpenAI-compatible model, off unless a key is configured.

The ML probability does **not** override the rules. It becomes one more weighted signal that flows
through the same scoring, capping and explanation machinery.

### Stage 5 — Risk Scoring
Explained fully in section 6.

### Stage 6 — Explanation + Safe Action
Turns signals into: a summary paragraph, ranked reasons with quoted evidence, what made it dangerous,
trust indicators that argued the other way, and prioritised recommendations.

**The API returns this whole trace.** The UI renders each stage with its output and timing, so a user
or a judge can see the reasoning, not just the number.

---

## 5. Why three separate tiers

This is the design decision most worth defending.

**Each tier degrades independently, and no layer can fail a request.**

- The rule engine runs **fully offline** and always produces a complete explainable verdict. No API
  keys, no internet, no models required.
- If the ML service is down, the response says so explicitly and the verdict stands on rules alone. A
  **circuit breaker** opens after three consecutive failures so a dead service costs ~0 ms instead of a
  2.5 s timeout on every request.
- The LLM layer is optional. A timeout is a non-event.

The alternative — one monolith where the model is the detector — fails completely when the model is
unavailable, and cannot explain itself when it is.

There is also a practical reason: Python owns the ML ecosystem, Node owns the web layer. Rather than
compromise on either, they talk over HTTP with a stable contract.

---

## 6. How the score is built

```
1. Each signal has a weight (e.g. "credentials posted to a different domain" = 28)
2. Weights are summed PER CATEGORY, with a CAP per category
3. Trust signals subtract, but are DAMPED when evidence is strong
4. The net total passes through a SATURATING CURVE:  100 × (1 − e^(−net / 29))
5. Individually conclusive findings apply a score FLOOR
```

**Why the per-category cap matters.** A message shouting five urgency phrases is still *one* urgency
finding, with a bounded bonus. Without this, long messages inflate their own scores and false
positives rise. This is the main lever keeping the false-positive rate low.

**Why the damping is conditional.** A compromised-but-authenticated mailbox sending a BEC request has
a valid SPF pass. If trust signals subtracted at full strength, that valid SPF would excuse the
attack. So when evidence is strong, only 25–50% of the trust damping applies.

**Why a saturating curve, not a linear sum.** Evidence should have diminishing returns. The 20th
indicator should not matter as much as the 2nd.

Bands: **0–30 Low · 31–70 Medium · 71–100 High**

Everything is inspectable: the UI's "How the score was calculated" panel shows evidence points,
damping applied, which categories were capped, and the curve output. The constants are published
through `GET /api/education/tactics` so results can be **audited rather than trusted**.

### It reproduces the problem statement's own examples

| Input from the spec | Spec expects | PhishGuard (rules only) |
|---|---|---|
| "Your bank account will be suspended within 24 hours. Click here to verify your identity." | 92 / High | **86 / High** |
| "Your package delivery has been delayed. Track it here." | 48 / Medium | **48 / Medium** |

---

## 7. Explainable AI — how, exactly

Both served models are **linear on purpose**. That means a prediction decomposes exactly:

```
logit = intercept + Σ (coefficient_i × value_i)
```

Every term is one token or one engineered feature. So the `top_indicators` shown in the UI are the
**actual arithmetic behind the probability** — not a SHAP or LIME approximation that could disagree
with the decision that was actually made.

We chose this over a fine-tuned BERT deliberately, and the trade-off is worth stating:

| | Linear + TF-IDF | Fine-tuned transformer |
|---|---|---|
| Explanation | Exact, per token | Approximated post-hoc |
| Latency (CPU) | 1–13 ms | 200 ms+ |
| Hardware | Any laptop | GPU preferred |
| Accuracy on this task | Sufficient (see section 8) | Likely marginally better |

`ml/app/inference.py` only requires `predict_proba`, so a transformer can be dropped in later without
touching the API or the UI. The interface was designed for that swap.

One more detail: internal marker tokens are translated for display. The user sees *"shortened link
that hides its destination"*, never `<url_shortener>`.

---

## 8. Results

Two datasets, and **the difference between them is the point**:

- **Generated corpus** — 8,000 messages and 9,000 URLs built from templates and slot banks. Used for training.
- **Gold set** — 120 messages and 70 URLs written **by hand, independently of the templates**,
  including deliberate hard negatives: genuine OTP alerts, genuine blocked-sign-in notices, genuine
  failed-payment mail, real bank debit alerts.

Both tiers are scored on the **same gold set**, so they are directly comparable.

### Full pipeline (rules + ML)

| Metric | Result | Target |
|---|---|---|
| Accuracy | **100.0%** | > 90% |
| Precision / Recall | 100% / 100% | — |
| False positive rate | **0.0%** | < 10% |
| Latency (median / p95 / max) | **8 ms / 16 ms / 81 ms** | < 5 s |

### Rule engine alone (offline, no ML at all)

| Decision rule | Accuracy | FPR | Recall |
|---|---|---|---|
| Medium-or-High counts as a detection | **97.5%** | 1.7% | 96.7% |
| High Risk only counts as a detection | 84.2% | 0.0% | 68.3% |
| URLs, Medium-or-High | 98.6% | 0.0% | 97.1% |

Both rules are reported because in the product **Medium already means "do not act until you verify"** —
that is a successful intervention, not a miss.

### How to present these numbers honestly

Say this before anyone asks. It is the strongest thing you can do in the room.

1. **The ~1.000 on the generated corpus is meaningless on its own.** Train and test rows come from the
   same template banks, so the task is trivially separable. We report it only so the gap to the gold
   set is visible.
2. **The gold-set 100% is an upper bound, not a field estimate.** After the first evaluation exposed
   missed attack families (chat-delivered vishing, QR collect-request fraud, sideloaded APK malware),
   we extended the corpus to cover them. Those are real and important families in Indian fraud data,
   but the gold set informed that work, so it is no longer a fully blind test. 120 samples also has
   wide confidence intervals.
3. **The ML threshold was chosen out-of-sample.** `tune_threshold.py` splits the gold set 50/50 three
   hundred times, picks the operating point on one half and scores the other, then ships the median
   pick (0.34).
4. **What would make these numbers trustworthy** is a blind evaluation on live traffic nobody tuned
   against. Both training scripts accept `--data`, so a real corpus drops in with no code changes.

### Engineering evidence worth mentioning

Two moments show the process working, and both are good things to say out loud:

- **The first model scored a perfect 1.000 — and that was a bug, not a win.** The top learned tokens
  were "hi", "an", "on". It had learned that our greeting bank differed by class. We made all
  decorations class-independent, which forced the signal into the message body. The indicators it
  learns now are real: credential-path links, shorteners, "within … hours".
- **The first gold run flagged 7 genuine messages as Medium risk.** "Rs. 82,400 has been credited" hit
  a *prize* pattern; "Delivery update:" hit a *click-here* pattern; "arriving in 3 minutes" and
  "expires in 14 days" hit *urgency*. Tightening those four rules took false positives from 11.7% to
  1.7% **while recall went up**.

---

## 9. Live demo script (about 4 minutes)

Open the app. Point at the **status strip** first: three tiers, live.

**Demo 1 — the classic attack (30 s)**
Click the *Bank account suspension* sample → Analyse.
> "99 out of 100. But the score is not the product — this is."
Scroll to **Why this verdict**: brand mismatch, credential harvesting, urgency, `.tk` domain. Each with
the evidence quoted from the message.
> "Twelve indicators, each with the exact text that triggered it."

**Demo 2 — the one that proves it is not just flagging everything (45 s)**
Click *Genuine OTP alert* → Analyse.
> "This mentions a bank, an account, a login and a 6-digit code. A keyword filter flags it. We score it
> zero."
Point at **Signals in its favour**:
> "It warns you *not* to share the code and carries no link. That is how genuine OTP alerts are
> written, and we recognise the shape."
> "Anyone can catch phishing by flagging everything. Not flagging this is the hard part."

**Demo 3 — the pipeline (45 s)**
Scroll to **Detection pipeline**.
> "Six stages, exactly as designed, with real timings. Feature Extraction expands into the five feature
> groups. If the ML service were down, this stage would say so — the system never pretends."

**Demo 4 — the ML tier (45 s)**
Scroll to **Machine-learning analysis**.
> "The model says 100% phishing. And here are the exact token contributions that produced that number —
> not an approximation, the actual arithmetic, because the model is linear."

**Demo 5 — website analysis (45 s)**
Switch to the **Website** tab → *Cloned login page* sample → Analyse.
> "This is a fake ICICI login page. It found the credential form posting to a Telegram bot, the brand
> logo hotlinked from the real bank, paste disabled to defeat password managers, and four dead
> navigation links."

**Demo 6 — the score maths (30 s)**
Scroll to **How the score was calculated**.
> "Every point is traceable: evidence, trust damping, which categories were capped. We publish the
> constants through the API. This is auditable, not a black box."

Close on the **Awareness** tab:
> "And because detection alone does not change behaviour, the tactic library is published for the user
> to learn from."

---

## 10. What makes this defensible

1. **Explainability is architectural, not a feature.** Linear models chosen for exact attribution; the
   pipeline trace is part of the API contract; scoring constants are published.
2. **Graceful degradation is proven, not claimed.** Turn off the ML service mid-demo — you still get a
   full verdict, and the UI tells you which tier is missing.
3. **Hard negatives are first-class.** Genuine OTP alerts, real debit alerts and real security notices
   sit in the evaluation set on purpose. Low false positives are treated as a feature requirement.
4. **Indian context is built in**, not bolted on: UPI/QR collect-request fraud, Aadhaar and PAN
   harvesting, KYC pretexts, SIM-swap, courier customs-fee scams, sideloaded APK banking malware,
   "digital arrest" scams, and 45+ Indian brand and government domains.
5. **Security of the tool itself was considered.** Live URL fetching is SSRF-guarded (private,
   loopback, link-local and metadata addresses refused before *and* after redirects; size and time
   capped; HTML only). Message bodies are never stored — only a 160-character redacted preview.
   Reporter IPs are hashed.
6. **We measured against the stated targets and published the misses**, including the ones we have not
   fixed.

---

## 11. Anticipated questions

**"Isn't this just regex matching?"**
The rule engine is pattern-based and that is a strength: it is deterministic, auditable, and works
offline. But it is not *just* regex — there is edit-distance typosquatting detection, Shannon entropy
on domains, homoglyph normalisation, public-suffix-aware domain parsing, SPF/DKIM/DMARC verdict
parsing, and HTML form-destination analysis. And it is one of three layers; two trained classifiers
run alongside it.

**"Why not use GPT for everything?"**
Three reasons. Latency: an LLM call is 1–3 s versus 8 ms. Cost: per-request API charges at scale.
Determinism: an LLM cannot guarantee the same verdict twice, and it can be talked out of a correct
answer by polished phishing copy. We use an LLM as an *optional last opinion* with a bounded fusion
weight, and it can never pull a score below a floor the rules established.

**"Your accuracy is 100% — that's suspicious."**
It should be. See section 8, point 2: the gold set is 120 samples and it informed a round of corpus
extension, so treat it as an upper bound. The rule-engine-only number (97.5% at 1.7% false positives)
is the more conservative figure, and the honest headline is that we pass the stated targets on a
held-out hand-written set while being explicit about that set's limits.

**"What about zero-day phishing with no known patterns?"**
Structural signals do not depend on knowing the campaign: a login form posting to a different domain,
a domain registered one character from a real brand, a raw IP host, SPF failure. Those catch novel
attacks. The ML layer generalises on character n-grams, which survive obfuscation. That said, a
genuinely novel *social* pretext with clean infrastructure is the honest weak spot.

**"How do you avoid blocking legitimate mail?"**
Four mechanisms: per-category caps, trust signals with negative weights, an allowlist of verified
brand and official domains, and explicit recognition of genuine transactional shapes. Measured
false-positive rate is 1.7% for the rule engine and 0% for the full pipeline on the gold set.

**"Can this scale?"**
The rule engine is stateless and CPU-only — horizontally scalable behind a load balancer. The ML
service is stateless too. Current honest limits: the rate limiter is in-process and the store is a
JSON file, so a multi-node deployment needs Redis and a real database. The store interface is narrow
specifically to make that swap small.

**"What is the business/deployment model?"**
The API is the product. The same endpoints can back a browser extension, a mail-gateway plugin, a
WhatsApp bot, or a bank's own app. The web UI is one client.

---

## 12. Limitations (state these before being asked)

- Detection is **advisory**. It reduces risk; it does not replace verifying anything involving money
  or credentials through an official channel. The UI says so on every screen.
- Tuned for **English and Hinglish** with an Indian-context brand list. Other languages will
  under-perform until the tactic library and corpus are extended.
- **No live domain-age, WHOIS or certificate-transparency lookups.** Community reports and optional
  Safe Browsing are the only external intelligence.
- **JavaScript-rendered login pages look thinner than they are.** We analyse the HTML the server
  receives; headless-browser rendering would fix this and is not implemented.
- **Trained on generated data.** This is the biggest limitation and the first thing to change with
  access to a real labelled corpus.
- **Accessibility** has been built for (semantic landmarks, keyboard operation, focus-visible styles,
  reduced-motion support, risk never conveyed by colour alone) but full WCAG conformance needs manual
  testing with assistive technology and expert review.

---

## 13. What we would build next

1. **Browser extension** using the same API — check links before the click, at the point of risk.
2. **Real corpus + blind evaluation** on traffic nobody tuned against.
3. **Domain age and certificate transparency** — a domain registered yesterday hosting a bank login is
   near-conclusive, and we do not use that signal yet.
4. **Headless rendering** for JavaScript-heavy phishing kits.
5. **Regional language support**, starting with Hindi, Tamil and Bengali phishing corpora.
6. **Feedback loop**: user corrections become training labels, with review to prevent poisoning.

---

## 14. Quick reference

### Run it

```powershell
# Terminal 1 — ML service
cd ml
.\.venv\Scripts\python.exe -m uvicorn app.main:app --port 8000

# Terminal 2 — API + UI together
npm run dev
```

Open **http://localhost:5173**

### Reproduce the numbers

```powershell
npm run evaluate            # rule engine alone (no ML needed)
npm run evaluate:pipeline   # rules + ML
cd ml; .\.venv\Scripts\python.exe training/evaluate.py       # per-model, gold vs in-distribution
cd ml; .\.venv\Scripts\python.exe training/tune_threshold.py # out-of-sample threshold selection
```

### Key numbers to remember

| | |
|---|---|
| Social-engineering tactics | 17 |
| URL features (ML) | 50 |
| TF-IDF features (message model) | ~17,000 |
| Training corpus | 8,000 messages + 9,000 URLs |
| Gold set | 120 messages + 70 URLs, hand written |
| Full pipeline on gold set | 100% accuracy, 0% FPR |
| Rule engine alone | 97.5% accuracy, 1.7% FPR |
| Median latency | 8 ms (target: 5,000 ms) |
| Pipeline stages | 6 |
| Feature groups | 5 (+1 for websites) |

### The three sentences to land

1. "It does not just flag phishing — it explains it, in language the user can act on."
2. "It runs offline on rules, and gets better with ML — no single layer can fail a request."
3. "Not flagging a genuine bank OTP alert is as important as catching the fake one, and we measure both."

### Where the code lives

| Question | File |
|---|---|
| What tactics does it know? | `server/src/engine/constants.js` (`TACTICS`) |
| How is the score computed? | `server/src/engine/riskScorer.js` |
| How are explanations written? | `server/src/engine/explainer.js` |
| Where is the pipeline orchestrated? | `server/src/services/pipelineService.js` |
| How does it survive a dead ML service? | `server/src/services/mlService.js` (circuit breaker) |
| What features does the URL model use? | `ml/app/features/url.py` |
| How are explanations computed exactly? | `ml/app/inference.py` |
| How was the corpus built? | `ml/training/generate_corpus.py` |
