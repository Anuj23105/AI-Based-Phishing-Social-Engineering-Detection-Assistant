/**
 * Persistence.
 *
 * Two drivers, one interface:
 *
 *   file   (default) — JSON files under server/data, written atomically and
 *                      debounced. Zero setup, survives restarts, good enough for
 *                      a demo or a single-node deployment.
 *   memory           — nothing on disk, used by tests and the evaluation harness.
 *
 * The interface is deliberately narrow (append/list/aggregate) so swapping in
 * MongoDB or PostgreSQL later means writing one more driver rather than touching
 * the routes. Analyses are stored with the message body reduced to a short
 * preview: keeping full copies of what users paste in — which is exactly the
 * sensitive content they are worried about — would be a liability, not a feature.
 */

import fs from 'node:fs/promises';
import path from 'node:path';

import { config } from '../config.js';
import { hash, registrableDomain, safeParseUrl, truncate } from '../engine/utils.js';

const FILES = { analyses: 'analyses.json', reports: 'reports.json' };

function createState() {
  return { analyses: [], reports: [] };
}

class Store {
  constructor(driver) {
    this.driver = driver;
    this.state = createState();
    this.ready = driver === 'file' ? this.#load() : Promise.resolve();
    this.pendingWrite = null;
  }

  async #load() {
    await fs.mkdir(config.storage.dataDir, { recursive: true });
    for (const [key, file] of Object.entries(FILES)) {
      const target = path.join(config.storage.dataDir, file);
      try {
        const raw = await fs.readFile(target, 'utf8');
        const parsed = JSON.parse(raw);
        if (Array.isArray(parsed)) this.state[key] = parsed;
      } catch (error) {
        if (error.code !== 'ENOENT') {
          // A corrupt data file must not stop the server from booting.
          console.warn(`[store] could not read ${file}: ${error.message}`);
        }
      }
    }
  }

  /** Debounced atomic flush: write to a temp file, then rename. */
  #schedulePersist() {
    if (this.driver !== 'file') return;
    if (this.pendingWrite) return;
    this.pendingWrite = setTimeout(async () => {
      this.pendingWrite = null;
      try {
        await fs.mkdir(config.storage.dataDir, { recursive: true });
        for (const [key, file] of Object.entries(FILES)) {
          const target = path.join(config.storage.dataDir, file);
          const temp = `${target}.tmp`;
          await fs.writeFile(temp, JSON.stringify(this.state[key], null, 2), 'utf8');
          await fs.rename(temp, target);
        }
      } catch (error) {
        console.warn(`[store] persist failed: ${error.message}`);
      }
    }, 400);
  }

  /* ----------------------------- analyses ------------------------------ */

  /**
   * Record one analysis. Only a redacted summary is kept.
   */
  async recordAnalysis(result) {
    await this.ready;
    const record = {
      id: result.id,
      analyzedAt: result.analyzedAt,
      type: result.input.type,
      channel: result.input.channel,
      score: result.score,
      level: result.level,
      confidence: result.confidence,
      preview: truncate(result.input.preview || '', 160),
      url: result.input.url || null,
      domains: (result.entities?.urls || []).map((u) => u.registrableDomain).filter(Boolean).slice(0, 5),
      topReason: result.explanation?.reasons?.[0]?.title || null,
      tactics: (result.tactics || []).map((t) => t.id).slice(0, 8),
      categories: (result.categories || []).map((c) => c.category),
      mlProbability: result.ml?.used ? result.ml.probability : null,
      aiUsed: Boolean(result.ai?.used),
      durationMs: result.durationMs
    };
    this.state.analyses.unshift(record);
    if (this.state.analyses.length > config.storage.historyLimit) {
      this.state.analyses.length = config.storage.historyLimit;
    }
    this.#schedulePersist();
    return record;
  }

  async listAnalyses({ limit = 25, level = null, offset = 0 } = {}) {
    await this.ready;
    const filtered = level ? this.state.analyses.filter((a) => a.level === level) : this.state.analyses;
    return { total: filtered.length, items: filtered.slice(offset, offset + limit) };
  }

  async getAnalysis(id) {
    await this.ready;
    return this.state.analyses.find((a) => a.id === id) || null;
  }

  /* ------------------------------ reports ------------------------------ */

  /**
   * A user-submitted phishing report. Domains extracted here feed the
   * reputation lookup used by the intelligence stage.
   */
  async recordReport({ url, text, reason, level, reporter }) {
    await this.ready;
    const urls = [url].filter(Boolean);
    const domains = [...new Set(
      urls.map((u) => {
        const parsed = safeParseUrl(u);
        return parsed ? registrableDomain(parsed.hostname) : null;
      }).filter(Boolean)
    )];

    const record = {
      id: hash(`${Date.now()}|${url || ''}|${truncate(text || '', 80)}`),
      reportedAt: new Date().toISOString(),
      url: url || null,
      domains,
      preview: truncate(text || '', 160),
      reason: reason ? truncate(reason, 240) : null,
      level: level || null,
      // Never store a raw identifier: a coarse hash is enough to spot one user
      // spamming reports without retaining anything personal.
      reporter: reporter ? hash(reporter) : null
    };
    this.state.reports.unshift(record);
    if (this.state.reports.length > 2000) this.state.reports.length = 2000;
    this.#schedulePersist();
    return record;
  }

  async listReports({ limit = 25 } = {}) {
    await this.ready;
    return { total: this.state.reports.length, items: this.state.reports.slice(0, limit) };
  }

  /** Report counts per domain, used as community threat intelligence. */
  async reputationFor(domains = []) {
    await this.ready;
    const wanted = new Set(domains);
    const tally = new Map();
    for (const report of this.state.reports) {
      for (const domain of report.domains || []) {
        if (!wanted.has(domain)) continue;
        const entry = tally.get(domain) || { domain, reports: 0, lastReportedAt: report.reportedAt, reporters: new Set() };
        entry.reports += 1;
        if (report.reporter) entry.reporters.add(report.reporter);
        if (report.reportedAt > entry.lastReportedAt) entry.lastReportedAt = report.reportedAt;
        tally.set(domain, entry);
      }
    }
    return [...tally.values()].map((e) => ({
      domain: e.domain,
      reports: e.reports,
      distinctReporters: e.reporters.size,
      lastReportedAt: e.lastReportedAt
    }));
  }

  /* ------------------------------- stats ------------------------------- */

  async stats() {
    await this.ready;
    const analyses = this.state.analyses;
    const byLevel = { low: 0, medium: 0, high: 0 };
    const byType = {};
    const tacticTally = {};
    const domainTally = {};
    let scoreTotal = 0;
    let durationTotal = 0;

    for (const item of analyses) {
      byLevel[item.level] = (byLevel[item.level] || 0) + 1;
      byType[item.type] = (byType[item.type] || 0) + 1;
      scoreTotal += item.score;
      durationTotal += item.durationMs || 0;
      for (const tactic of item.tactics || []) tacticTally[tactic] = (tacticTally[tactic] || 0) + 1;
      for (const domain of item.domains || []) domainTally[domain] = (domainTally[domain] || 0) + 1;
    }

    const trend = {};
    for (const item of analyses) {
      const day = item.analyzedAt.slice(0, 10);
      trend[day] = trend[day] || { date: day, total: 0, high: 0, medium: 0, low: 0 };
      trend[day].total += 1;
      trend[day][item.level] += 1;
    }

    return {
      totalAnalyses: analyses.length,
      totalReports: this.state.reports.length,
      byLevel,
      byType,
      averageScore: analyses.length ? Math.round(scoreTotal / analyses.length) : 0,
      averageDurationMs: analyses.length ? Math.round(durationTotal / analyses.length) : 0,
      threatsBlocked: byLevel.high || 0,
      topTactics: Object.entries(tacticTally).sort((a, b) => b[1] - a[1]).slice(0, 8).map(([id, count]) => ({ id, count })),
      topDomains: Object.entries(domainTally).sort((a, b) => b[1] - a[1]).slice(0, 8).map(([domain, count]) => ({ domain, count })),
      trend: Object.values(trend).sort((a, b) => a.date.localeCompare(b.date)).slice(-14),
      driver: this.driver
    };
  }

  /** Used by tests and the evaluation harness. */
  async reset() {
    await this.ready;
    this.state = createState();
    this.#schedulePersist();
  }
}

export const store = new Store(config.storage.driver === 'memory' ? 'memory' : 'file');
export default store;
