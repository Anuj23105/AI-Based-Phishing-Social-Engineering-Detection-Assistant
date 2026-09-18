/**
 * The main workspace: choose an input kind, paste content, analyse, read the
 * explanation.
 */

import { useCallback, useEffect, useMemo, useState } from 'react';

import api from '../api.js';
import SAMPLES from '../samples.js';
import Verdict from './Verdict.jsx';
import PipelineTrace from './PipelineTrace.jsx';
import MlPanel from './MlPanel.jsx';
import { Reasons, Recommendations, Tactics, TrustIndicators } from './Reasons.jsx';
import { Entities, PageFindings, ScoreMath } from './Evidence.jsx';

const TABS = [
  { id: 'message', label: 'Message / SMS / Chat', hint: 'Paste an SMS, WhatsApp message or social media DM.' },
  { id: 'email', label: 'Email', hint: 'Paste the whole email including headers for sender and SPF/DKIM checks.' },
  { id: 'url', label: 'Link', hint: 'Check a single URL without opening it.' },
  { id: 'website', label: 'Website', hint: 'Fetch a live page, or paste its HTML source, and inspect the login form.' }
];

const PLACEHOLDERS = {
  message: 'Dear Customer, your account will be suspended within 24 hours. Click here to verify your identity...',
  email: `From: "Support" <no-reply@example-bank.co>
Reply-To: recovery@mail-secure.top
Subject: Action required on your account
Authentication-Results: spf=fail dkim=none dmarc=fail

Paste the full message, headers included.`,
  website: '<!doctype html><html><head><title>Bank Login</title></head>...'
};

export default function AnalyzerView({ onAnalysed }) {
  const [tab, setTab] = useState('message');
  const [content, setContent] = useState('');
  const [url, setUrl] = useState('');
  const [channel, setChannel] = useState('sms');
  const [fetchLive, setFetchLive] = useState(true);
  const [useMl, setUseMl] = useState(true);
  const [useAi, setUseAi] = useState(true);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);
  const [result, setResult] = useState(null);
  const [reportState, setReportState] = useState(null);

  const tabSamples = useMemo(() => SAMPLES.filter((s) => s.tab === tab), [tab]);
  const activeTab = TABS.find((t) => t.id === tab);

  const loadSample = useCallback((sample) => {
    setResult(null);
    setError(null);
    setReportState(null);
    setTab(sample.tab);
    setContent(sample.content || sample.html || '');
    setUrl(sample.url || '');
    if (sample.type) setChannel(sample.type);
    if (sample.tab === 'website') setFetchLive(!sample.html);
  }, []);

  const canSubmit = tab === 'url' ? url.trim().length > 3 : tab === 'website' ? (url.trim() || content.trim()) : content.trim().length > 0;

  const submit = useCallback(async (event) => {
    event?.preventDefault();
    if (!canSubmit || loading) return;

    setLoading(true);
    setError(null);
    setReportState(null);
    try {
      let response;
      if (tab === 'url') {
        response = await api.analyzeUrl({ url: url.trim(), useMl, useAi });
      } else if (tab === 'website') {
        if (content.trim()) {
          response = await api.analyze({ type: 'website', html: content, url: url.trim() || undefined, useMl, useAi });
        } else if (fetchLive) {
          response = await api.analyzeWebsite({ url: url.trim(), useMl, useAi });
        } else {
          response = await api.analyzeUrl({ url: url.trim(), useMl, useAi });
        }
      } else {
        response = await api.analyze({
          type: tab === 'email' ? 'email' : channel,
          content,
          url: url.trim() || undefined,
          useMl,
          useAi
        });
      }
      setResult(response);
      onAnalysed?.(response);
    } catch (err) {
      setError(err.message);
      setResult(null);
    } finally {
      setLoading(false);
    }
  }, [canSubmit, loading, tab, url, content, channel, fetchLive, useMl, useAi, onAnalysed]);

  // Ctrl/Cmd + Enter submits from anywhere in the form.
  useEffect(() => {
    const handler = (event) => {
      if ((event.ctrlKey || event.metaKey) && event.key === 'Enter') submit();
    };
    window.addEventListener('keydown', handler);
    return () => window.removeEventListener('keydown', handler);
  }, [submit]);

  const report = useCallback(async () => {
    if (!result) return;
    try {
      const response = await api.report({
        url: result.input.url || result.entities?.urls?.[0]?.url || null,
        text: result.input.preview,
        level: result.level,
        reason: result.explanation.reasons[0]?.title || null
      });
      setReportState({ ok: true, message: response.message });
    } catch (err) {
      setReportState({ ok: false, message: err.message });
    }
  }, [result]);

  const reset = () => {
    setContent('');
    setUrl('');
    setResult(null);
    setError(null);
    setReportState(null);
  };

  return (
    <div className="grid analyzer">
      {/* --------------------------- input side --------------------------- */}
      <form className="panel" onSubmit={submit}>
        <div className="panel-head">
          <h2>Analyse content</h2>
          <span className="panel-sub">Ctrl + Enter</span>
        </div>

        <div className="tabs" role="tablist" aria-label="Type of content to analyse">
          {TABS.map((item) => (
            <button
              key={item.id}
              type="button"
              role="tab"
              className="tab"
              aria-selected={tab === item.id}
              onClick={() => { setTab(item.id); setResult(null); setError(null); }}
            >
              {item.label}
            </button>
          ))}
        </div>

        <p className="panel-sub" style={{ marginBottom: 14 }}>{activeTab?.hint}</p>

        {(tab === 'url' || tab === 'website') && (
          <label className="field">
            <span>{tab === 'url' ? 'Link to check' : 'Website address'}</span>
            <input
              type="text"
              inputMode="url"
              value={url}
              onChange={(event) => setUrl(event.target.value)}
              placeholder="https://example-bank.verify-login.tk/signin"
              autoComplete="off"
              spellCheck="false"
            />
          </label>
        )}

        {tab === 'message' && (
          <label className="field">
            <span>Channel</span>
            <select value={channel} onChange={(event) => setChannel(event.target.value)}>
              <option value="sms">SMS</option>
              <option value="whatsapp">WhatsApp</option>
              <option value="chat">Chat / DM</option>
              <option value="social">Social media</option>
              <option value="message">Other</option>
            </select>
          </label>
        )}

        {tab !== 'url' && (
          <label className="field">
            <span>
              {tab === 'website' ? 'Page HTML (optional if fetching live)' : tab === 'email' ? 'Full email' : 'Message text'}
            </span>
            <textarea
              value={content}
              onChange={(event) => setContent(event.target.value)}
              placeholder={PLACEHOLDERS[tab] || ''}
              spellCheck="false"
              aria-describedby="content-help"
            />
          </label>
        )}

        {tab === 'email' && (
          <p id="content-help" className="panel-sub" style={{ marginTop: -6, marginBottom: 12 }}>
            Headers matter: with them PhishGuard can check display-name spoofing, reply-to
            redirection and SPF/DKIM/DMARC results.
          </p>
        )}

        {tab === 'website' && !content.trim() && (
          <label className="toggles" style={{ marginBottom: 13 }}>
            <input type="checkbox" checked={fetchLive} onChange={(e) => setFetchLive(e.target.checked)} />
            <span>Fetch the live page and inspect it (server-side, sandboxed)</span>
          </label>
        )}

        <div className="toggles" style={{ marginBottom: 15 }}>
          <label>
            <input type="checkbox" checked={useMl} onChange={(e) => setUseMl(e.target.checked)} />
            <span>ML models</span>
          </label>
          <label>
            <input type="checkbox" checked={useAi} onChange={(e) => setUseAi(e.target.checked)} />
            <span>LLM review (if configured)</span>
          </label>
        </div>

        <div className="row" style={{ marginBottom: 16 }}>
          <button className="btn" type="submit" disabled={!canSubmit || loading}>
            {loading ? <><span className="spinner" /> Analysing…</> : 'Analyse'}
          </button>
          <button className="btn ghost" type="button" onClick={reset} disabled={loading}>Clear</button>
        </div>

        <div>
          <p className="panel-sub" style={{ marginBottom: 8 }}>Try a sample:</p>
          <div className="samples">
            {tabSamples.map((sample) => (
              <button key={sample.id} type="button" className="sample-btn" onClick={() => loadSample(sample)}>
                {sample.label}
                <span className={`badge ${sample.expected}`}>{sample.expected}</span>
              </button>
            ))}
          </div>
        </div>
      </form>

      {/* --------------------------- result side -------------------------- */}
      <div>
        {error && (
          <div className="notice error" role="alert">
            <strong>Analysis failed.</strong> {error}
          </div>
        )}

        {!result && !error && (
          <div className="panel">
            <div className="empty">
              <p style={{ marginBottom: 8, color: 'var(--text-dim)' }}>
                Paste something suspicious, or pick a sample, and PhishGuard will explain what it
                finds.
              </p>
              <p>
                Nothing is analysed until you press Analyse. Message bodies are never stored — only a
                short redacted preview is kept in history.
              </p>
            </div>
          </div>
        )}

        {result && (
          <>
            <Verdict result={result} />

            <div className="panel" style={{ paddingTop: 14, paddingBottom: 14 }}>
              <div className="row spread">
                <span className="panel-sub">
                  Was this useful? Reporting adds the domain to shared threat intelligence.
                </span>
                <button className="btn small ghost" type="button" onClick={report}>
                  Report as phishing
                </button>
              </div>
              {reportState && (
                <div className={`notice ${reportState.ok ? 'ok' : 'error'}`} style={{ marginTop: 10 }}>
                  {reportState.message}
                </div>
              )}
            </div>

            <Reasons reasons={result.explanation.reasons} />
            <Recommendations recommendations={result.explanation.recommendations} level={result.level} />
            <TrustIndicators indicators={result.explanation.trustIndicators} />
            <MlPanel ml={result.ml} />
            <Tactics tactics={result.explanation.tactics} />
            <PipelineTrace pipeline={result.pipeline} featureGroups={result.featureGroups} />
            <Entities entities={result.entities} sender={result.sender} input={result.input} />
            <PageFindings page={result.page} fetchInfo={result.fetch} />
            <ScoreMath
              breakdown={result.breakdown}
              categories={result.explanation.categoryBreakdown}
              intel={result.intel}
            />

            <details className="raw">
              <summary>Raw API response (for judges and integrators)</summary>
              <pre>{JSON.stringify(result, null, 2)}</pre>
            </details>
          </>
        )}
      </div>
    </div>
  );
}
