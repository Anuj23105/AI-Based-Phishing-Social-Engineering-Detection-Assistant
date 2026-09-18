/**
 * The technical detail panels: extracted entities, sender authentication,
 * website findings and the raw score arithmetic.
 *
 * This is the "show your working" section. Anything the verdict relied on should
 * be inspectable here, including the exact evidence/damping figures, so a
 * sceptical reviewer can audit the number rather than trust it.
 */

function Chip({ children, tone }) {
  return <span className={`mini-chip ${tone || ''}`}>{children}</span>;
}

export function Entities({ entities, sender, input }) {
  const hasUrls = entities?.urls?.length > 0;
  const hasSender = Boolean(sender?.from);
  const hasContacts = entities?.emails?.length > 0 || entities?.phones?.length > 0;
  if (!hasUrls && !hasSender && !hasContacts && !entities?.claimedBrands?.length) return null;

  return (
    <section className="panel" aria-labelledby="entities-heading">
      <div className="panel-head">
        <h3 id="entities-heading">Extracted details</h3>
        <span className="panel-sub">what preprocessing pulled out</span>
      </div>

      {entities?.claimedBrands?.length > 0 && (
        <div className="row" style={{ marginBottom: 14 }}>
          <span className="panel-sub">Claims to be from:</span>
          {entities.claimedBrands.map((brand) => <Chip key={brand}>{brand}</Chip>)}
        </div>
      )}

      {hasSender && (
        <div className="kv" style={{ marginBottom: hasUrls ? 16 : 0 }}>
          <div><span className="k">Sender</span><span className="v">{sender.from}</span></div>
          {sender.displayName && (
            <div><span className="k">Display name</span><span className="v">{sender.displayName}</span></div>
          )}
          {sender.replyTo && (
            <div><span className="k">Reply goes to</span><span className="v">{sender.replyTo}</span></div>
          )}
          {sender.returnPath && (
            <div><span className="k">Return path</span><span className="v">{sender.returnPath}</span></div>
          )}
          {sender.auth?.present && (
            <div>
              <span className="k">Authentication</span>
              <span className="v">
                {['spf', 'dkim', 'dmarc']
                  .filter((key) => sender.auth[key])
                  .map((key) => `${key.toUpperCase()}=${sender.auth[key]}`)
                  .join('  ') || 'no verdicts found'}
              </span>
            </div>
          )}
        </div>
      )}

      {hasUrls && (
        <div>
          <p className="panel-sub" style={{ marginBottom: 8 }}>
            Links found ({entities.urls.length}), riskiest first:
          </p>
          {[...entities.urls]
            .sort((a, b) => b.riskPoints - a.riskPoints)
            .map((url) => (
              <div key={url.url} className="url-item">
                <div className="u">{url.url}</div>
                <div className="meta">
                  <Chip>{url.registrableDomain || url.host}</Chip>
                  <Chip tone={url.scheme === 'https' ? '' : 'hit'}>{url.scheme}</Chip>
                  {url.isShortener && <Chip tone="hit">shortener</Chip>}
                  {url.impersonates && <Chip tone="hit">imitates {url.impersonates}</Chip>}
                  <Chip tone={url.riskPoints > 20 ? 'hit' : ''}>
                    {url.signalCount} finding{url.signalCount === 1 ? '' : 's'} · +{url.riskPoints}
                  </Chip>
                </div>
              </div>
            ))}
        </div>
      )}

      {hasContacts && (
        <div className="row" style={{ marginTop: 14 }}>
          {entities.emails.map((email) => <Chip key={email}>{email}</Chip>)}
          {entities.phones.slice(0, 4).map((phone) => <Chip key={phone}>{phone}</Chip>)}
        </div>
      )}

      {input?.subject && (
        <div className="kv" style={{ marginTop: 14 }}>
          <div><span className="k">Subject</span><span className="v">{input.subject}</span></div>
        </div>
      )}
    </section>
  );
}

export function PageFindings({ page, fetchInfo }) {
  if (!page && !fetchInfo) return null;

  return (
    <section className="panel" aria-labelledby="page-heading">
      <div className="panel-head">
        <h3 id="page-heading">Website analysis</h3>
        {fetchInfo && (
          <span className="panel-sub">
            {fetchInfo.ok
              ? `fetched ${fetchInfo.bytes} bytes in ${fetchInfo.durationMs} ms`
              : 'page could not be loaded'}
          </span>
        )}
      </div>

      {fetchInfo && !fetchInfo.ok && (
        <div className="notice info" style={{ marginBottom: page ? 14 : 0 }}>
          <strong>The page did not load: {fetchInfo.error}.</strong> The verdict is based on the link
          itself. Phishing sites are usually taken down within hours, so a dead page is normal rather
          than reassuring.
        </div>
      )}

      {page && (
        <div className="kv">
          {page.features?.title && (
            <div><span className="k">Page title</span><span className="v">{page.features.title}</span></div>
          )}
          <div><span className="k">Domain</span><span className="v">{page.facts.registrableDomain || 'unknown'}</span></div>
          <div>
            <span className="k">Connection</span>
            <span className="v">{page.facts.https ? 'HTTPS (encrypted)' : 'HTTP (not encrypted)'}</span>
          </div>
          <div>
            <span className="k">Login page</span>
            <span className="v">{page.facts.isLoginPage ? 'yes — collects credentials' : 'no'}</span>
          </div>
          {page.facts.sensitiveFields?.length > 0 && (
            <div>
              <span className="k">Fields requested</span>
              <span className="v">{page.facts.sensitiveFields.join(', ')}</span>
            </div>
          )}
          {page.facts.impersonates && (
            <div><span className="k">Branded as</span><span className="v">{page.facts.impersonates}</span></div>
          )}
          <div>
            <span className="k">Structure</span>
            <span className="v">
              {page.features.formCount} form(s), {page.features.inputCount} input(s),{' '}
              {page.features.scriptCount} script(s), {page.features.iframeCount} iframe(s)
            </span>
          </div>
        </div>
      )}

      {fetchInfo?.ok && fetchInfo.redirected && (
        <div className="notice info" style={{ marginTop: 14 }}>
          This link redirected to <strong>{fetchInfo.finalUrl}</strong>. Redirects are how a harmless
          looking link delivers you somewhere else.
        </div>
      )}
    </section>
  );
}

export function ScoreMath({ breakdown, categories = [], intel }) {
  if (!breakdown) return null;
  const max = Math.max(1, ...categories.map((c) => c.points ?? c.applied ?? 0));

  return (
    <section className="panel" aria-labelledby="math-heading">
      <div className="panel-head">
        <h3 id="math-heading">How the score was calculated</h3>
        <span className="panel-sub">every point is traceable</span>
      </div>

      {categories.length > 0 && (
        <div className="bars" style={{ marginBottom: 16 }}>
          {categories.map((cat) => {
            const points = cat.points ?? cat.applied ?? 0;
            return (
              <div className="bar-row" key={cat.category}>
                <span>{cat.label || cat.category}</span>
                <span className="bar-track">
                  <span className="bar-fill" style={{ width: `${(points / max) * 100}%` }} />
                </span>
                <span className="bar-num">+{points}</span>
              </div>
            );
          })}
        </div>
      )}

      <div className="kv">
        <div><span className="k">Evidence points</span><span className="v">{breakdown.evidence}</span></div>
        <div>
          <span className="k">Trust damping</span>
          <span className="v">
            -{breakdown.damping}
            {breakdown.dampingFactor !== 1 && (
              <span style={{ color: 'var(--text-faint)' }}>
                {' '}({breakdown.rawDamping} available, {Math.round(breakdown.dampingFactor * 100)}% applied
                because the evidence is strong)
              </span>
            )}
          </span>
        </div>
        <div><span className="k">Net evidence</span><span className="v">{breakdown.netEvidence}</span></div>
        <div>
          <span className="k">Saturating curve</span>
          <span className="v">{breakdown.curveScore} / 100</span>
        </div>
        {breakdown.floorApplied && (
          <div>
            <span className="k">Minimum applied</span>
            <span className="v">
              {breakdown.floorApplied} — one finding alone was conclusive
            </span>
          </div>
        )}
        {breakdown.cappedCategories?.length > 0 && (
          <div>
            <span className="k">Capped categories</span>
            <span className="v">{breakdown.cappedCategories.join(', ')}</span>
          </div>
        )}
        {breakdown.fusion?.aiUsed && (
          <div>
            <span className="k">Score fusion</span>
            <span className="v">
              rules {breakdown.fusion.heuristicScore} + model {breakdown.fusion.aiScore} at weight{' '}
              {breakdown.fusion.weightApplied}
            </span>
          </div>
        )}
        {intel?.checked && (
          <div>
            <span className="k">Threat intelligence</span>
            <span className="v">{intel.verdict} ({intel.sources.join(', ')})</span>
          </div>
        )}
      </div>

      <p className="panel-sub" style={{ marginTop: 12 }}>
        Points are capped per category so one repeated tactic cannot dominate, damped by trust
        signals, then mapped through a saturating curve. Bands: 0-30 low, 31-70 medium, 71-100 high.
      </p>
    </section>
  );
}
