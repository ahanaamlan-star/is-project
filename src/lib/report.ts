// Report generators: HTML (print → PDF), JSON, CSV and STIX 2.1.
import type { AnalysisResult, Finding } from '../engine/types';
import type { AuditEvent, CaptureRec, CaseRec } from '../store/useStore';
import { DETECTORS } from '../engine/detectors';
import { fmtBytes, fmtTs, fmtDur, humanize } from './format';
import { uid } from '../engine/util';

export interface ReportInput {
  c: CaseRec;
  cap: CaptureRec;
  run: AnalysisResult;
  events: AuditEvent[];
  analyst: string;
  signoff?: string;
  includeSuppressed?: boolean;
  includeDismissed?: boolean;
}

const esc = (s: unknown) => String(s ?? '').replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[c]!);

export function selectFindings(i: ReportInput): Finding[] {
  return i.run.findings.filter((f) => (i.includeSuppressed || !f.suppressed) && (i.includeDismissed || f.status !== 'benign_false_positive'));
}

export function htmlReport(i: ReportInput): string {
  const { c, cap, run } = i;
  const s = run.summary;
  const findings = selectFindings(i);
  const sevColor: Record<string, string> = { critical: '#be123c', high: '#b45309', medium: '#a16207', low: '#0369a1', informational: '#475569' };
  const row = (k: string, v: unknown) => `<tr><th>${esc(k)}</th><td>${esc(v)}</td></tr>`;
  const list = (a: string[]) => (a.length ? `<ul>${a.map((x) => `<li>${esc(x)}</li>`).join('')}</ul>` : '<p class="muted">None recorded.</p>');
  const findingHtml = findings.map((f) => `
    <section class="finding">
      <div class="fhead"><span class="sev" style="background:${sevColor[f.severity]}">${f.severity.toUpperCase()}</span>
      <span class="fid">${esc(f.id)}</span><span class="pill">${esc(humanize(f.category))}</span><span class="pill">${esc(f.source)}</span>
      <span class="pill">status: ${esc(humanize(f.status))}</span>${f.incidentId ? `<span class="pill">${esc(f.incidentId)}</span>` : ''}</div>
      <h3>${esc(f.title)}</h3>
      <p>${esc(f.explanation.summary)}</p>
      <table class="kv">
        ${row('Detector', `${f.detectorId} v${f.detectorVersion}`)}
        ${row('Score', `${f.score} (${f.scoreType}) — relative, not a probability`)}
        ${row('Priority', `${f.risk?.score ?? '—'} / 100 (severity ${f.risk?.components.severity}, anomaly ${f.risk?.components.anomaly}, evidence ${f.risk?.components.evidence}, corroboration ${f.risk?.components.corroboration}, context ${f.risk?.components.context})`)}
        ${row('Evidence confidence', f.confidence)}
        ${row('Time range', `${fmtTs(f.evidence.tsRange[0])} → ${fmtTs(f.evidence.tsRange[1])}`)}
        ${row('ATT&CK (hypothesis)', f.mitre.map((m) => `${m.id} ${m.name} [${m.tactic}]`).join('; ') || '—')}
      </table>
      <div class="cols">
        <div><h4>Observed facts</h4>${list(f.explanation.observedFacts)}</div>
        <div><h4>Detection rationale</h4>${list([...f.explanation.ruleEvidence, ...(f.explanation.modelSignal ? [f.explanation.modelSignal] : [])])}</div>
      </div>
      <h4>Interpretation</h4><p>${esc(f.explanation.interpretation)}</p>
      <div class="cols">
        <div><h4>Alternative explanations</h4>${list(f.explanation.alternatives)}</div>
        <div><h4>Next analyst checks</h4>${list(f.explanation.nextChecks)}</div>
      </div>
      <h4>Evidence references</h4>
      <p class="mono">Packets: ${esc(f.evidence.packetIdx.slice(0, 40).map((p) => '#' + p).join(', ') || '—')}${f.evidence.packetIdx.length > 40 ? ' …' : ''}<br/>
      Flows: ${esc(f.evidence.flowIds.slice(0, 20).join(', ') || '—')}</p>
      ${f.evidence.contributions ? `<h4>Feature attribution (approximate, path-based)</h4><table class="grid"><tr><th>Feature</th><th>Observed</th><th>Capture median</th><th>z</th><th>Share</th></tr>${f.evidence.contributions.slice(0, 6).map((x) => `<tr><td>${esc(x.feature)}</td><td>${x.observed}</td><td>${x.baseline}</td><td>${x.z}</td><td>${Math.round(x.share * 100)}%</td></tr>`).join('')}</table>` : ''}
      <h4>Limitations &amp; caveats</h4>${list([f.caveats, ...f.explanation.limitations])}
    </section>`).join('');

  const incidents = run.incidents.map((inc) => `<tr><td>${esc(inc.id)}</td><td>${esc(inc.title)}</td><td>${esc(inc.severity)}</td><td>${inc.findingIds.length}</td><td>${esc(inc.tactics.join(' → '))}</td><td>${esc(inc.reasons.slice(0, 2).join('; '))}</td></tr>`).join('');
  const audit = i.events.slice(0, 200).map((e) => `<tr><td class="mono">${esc(e.ts)}</td><td>${esc(e.actor)}</td><td>${esc(e.action)}</td><td>${esc(e.findingId || '')}</td><td>${esc(e.note)}</td></tr>`).join('');
  return `<!doctype html><html lang="en"><head><meta charset="utf-8"/><meta name="viewport" content="width=device-width,initial-scale=1"/>
<title>NetSentry XAI Report — ${esc(c.name)}</title>
<style>
  :root{--ink:#0f172a;--muted:#64748b;--line:#e2e8f0;--accent:#0369a1}
  *{box-sizing:border-box} body{font:13px/1.55 Inter,-apple-system,Segoe UI,Roboto,sans-serif;color:var(--ink);margin:0;background:#fff}
  .wrap{max-width:960px;margin:0 auto;padding:40px 32px}
  h1{font-size:26px;margin:0 0 4px} h2{font-size:16px;margin:32px 0 10px;padding-bottom:6px;border-bottom:2px solid var(--ink);text-transform:uppercase;letter-spacing:.06em}
  h3{font-size:15px;margin:6px 0} h4{font-size:11px;text-transform:uppercase;letter-spacing:.08em;color:var(--muted);margin:14px 0 4px}
  .muted{color:var(--muted)} .mono{font-family:'JetBrains Mono',ui-monospace,monospace;font-size:11.5px;word-break:break-all}
  table{border-collapse:collapse;width:100%} .kv th{width:200px;text-align:left;color:var(--muted);font-weight:500;padding:3px 8px 3px 0;vertical-align:top} .kv td{padding:3px 0}
  .grid th,.grid td{border:1px solid var(--line);padding:5px 7px;text-align:left;vertical-align:top} .grid th{background:#f8fafc;font-size:11px;text-transform:uppercase;letter-spacing:.05em;color:var(--muted)}
  .stats{display:grid;grid-template-columns:repeat(4,1fr);gap:10px} .stat{border:1px solid var(--line);border-radius:8px;padding:10px} .stat b{display:block;font-size:20px}
  .finding{border:1px solid var(--line);border-radius:10px;padding:16px 18px;margin:14px 0;page-break-inside:avoid}
  .fhead{display:flex;gap:6px;flex-wrap:wrap;align-items:center} .sev{color:#fff;font-weight:700;font-size:10px;padding:2px 8px;border-radius:4px;letter-spacing:.06em}
  .pill{border:1px solid var(--line);border-radius:999px;padding:1px 8px;font-size:11px;color:var(--muted)} .fid{font-family:monospace;font-size:11px;color:var(--accent)}
  .cols{display:grid;grid-template-columns:1fr 1fr;gap:16px} ul{margin:4px 0;padding-left:18px}
  .banner{background:#fffbeb;border:1px solid #fcd34d;border-radius:8px;padding:10px 14px;margin:16px 0;font-size:12px}
  .sign{margin-top:28px;display:grid;grid-template-columns:1fr 1fr;gap:24px} .sign div{border-top:1px solid var(--ink);padding-top:6px}
  @media print{.wrap{padding:0} h2{page-break-after:avoid} a{color:inherit}}
</style></head><body><div class="wrap">
<div class="muted" style="font-size:11px;letter-spacing:.12em;text-transform:uppercase">NetSentry XAI · Explainable Network Forensics Report</div>
<h1>${esc(c.name)}</h1>
<p class="muted">${esc(c.description || 'No case description provided.')}</p>
<div class="banner"><b>Interpretation notice.</b> Findings are evidence-linked hypotheses produced by transparent rules, statistical baselines and an unsupervised model. Scores are relative indicators, not calibrated probabilities of malicious activity. All conclusions require analyst review.</div>

<h2>1. Executive summary</h2>
<div class="stats">
  <div class="stat"><span class="muted">Findings</span><b>${findings.length}</b></div>
  <div class="stat"><span class="muted">Incidents</span><b>${run.incidents.length}</b></div>
  <div class="stat"><span class="muted">Packets</span><b>${s.parsedPackets.toLocaleString()}</b></div>
  <div class="stat"><span class="muted">Flows</span><b>${s.totalFlows.toLocaleString()}</b></div>
</div>
<p>By severity: ${Object.entries(s.bySeverity).map(([k, v]) => `${v} ${k}`).join(', ') || 'no findings'}. Highest-priority item: ${findings[0] ? esc(findings[0].title) + ` (priority ${findings[0].risk?.score})` : 'none'}.</p>

<h2>2. Capture provenance</h2>
<table class="kv">
${row('File', cap.filename)}${row('Size', fmtBytes(cap.size))}${row('Format', `${cap.format.toUpperCase()} · ${s.linktypes.join(', ')}`)}
${row('SHA-256', cap.sha256)}${row('Data provenance', humanize(cap.provenance))}${row('Ingested', cap.uploadedAt)}
${row('Capture window', `${fmtTs(s.start)} → ${fmtTs(s.end)} (${fmtDur(s.duration)})`)}
${row('Packets (parsed / total)', `${s.parsedPackets.toLocaleString()} / ${s.totalPackets.toLocaleString()}`)}${row('Bytes on wire', fmtBytes(s.totalBytes))}
${row('Hosts', `${s.hostsInternal} internal, ${s.hostsExternal} external`)}
</table>

<h2>3. Incidents (candidate correlations)</h2>
${run.incidents.length ? `<table class="grid"><tr><th>ID</th><th>Title</th><th>Severity</th><th>Findings</th><th>Tactics (hypothesis)</th><th>Why grouped</th></tr>${incidents}</table>${run.incidents.map((inc) => `<p><b>${esc(inc.id)}:</b> ${esc(inc.narrative)}</p>`).join('')}` : '<p class="muted">No correlated incidents.</p>'}

<h2>4. Findings</h2>
${findingHtml || '<p class="muted">No findings met the report filters.</p>'}

<h2>5. Analysis configuration &amp; versions</h2>
<table class="kv">
${row('Run ID', run.runId)}${row('Config hash', run.configHash)}${row('Started / finished', `${run.startedAt} / ${run.finishedAt}`)}
${Object.entries(run.versions).map(([k, v]) => row(k, v)).join('')}
${row('Stage timings', run.timings.map((t) => `${t.stage} ${t.ms} ms`).join(', '))}
${row('Thresholds', Object.entries(run.config.thresholds).map(([k, v]) => `${k}=${v}`).join(', '))}
${row('Isolation Forest', `trees=${run.config.ml.trees}, ψ=${run.config.ml.sampleSize}, contamination=${run.config.ml.contamination}, seed=${run.config.ml.seed}, min score=${run.config.ml.minScore}`)}
${row('Risk weights', Object.entries(run.config.weights).map(([k, v]) => `${k}=${v}`).join(', '))}
${row('Allowlist', run.config.allowlist.join(', ') || 'none')}${row('Critical assets', run.config.criticalAssets.join(', ') || 'none')}
</table>

<h2>6. Limitations</h2>
${list([...run.warnings, 'Analysis used observable metadata only; encrypted payloads were not decrypted.', 'Findings reflect a single capture vantage point and time window; absence of a finding does not prove absence of activity.', 'ATT&CK mappings are hypotheses based on observable patterns, not attribution.'])}

<h2>7. Detector catalogue</h2>
<table class="grid"><tr><th>Detector</th><th>Layer</th><th>Description</th><th>Known blind spots</th></tr>
${DETECTORS.map((d) => `<tr><td class="mono">${d.id} v${d.version}</td><td>${d.source}</td><td>${esc(d.description)}</td><td>${esc(d.caveat)}</td></tr>`).join('')}</table>

<h2>8. Audit trail</h2>
${audit ? `<table class="grid"><tr><th>Time</th><th>Actor</th><th>Action</th><th>Finding</th><th>Note</th></tr>${audit}</table>` : '<p class="muted">No audit events.</p>'}

<div class="sign"><div>Prepared by: ${esc(i.analyst)}<br/><span class="muted">${new Date().toISOString()}</span></div><div>Reviewed / signed off: ${esc(i.signoff || '')}<br/><span class="muted">Signature &amp; date</span></div></div>
<p class="muted" style="margin-top:28px;font-size:11px">Generated locally by NetSentry XAI ${esc(run.versions.engine)} in the analyst's browser. No capture data was transmitted to any server.</p>
</div></body></html>`;
}

const csvCell = (v: unknown) => {
  const s = Array.isArray(v) ? v.join(' ') : typeof v === 'object' && v ? JSON.stringify(v) : String(v ?? '');
  return /[",\n]/.test(s) ? `"${s.replace(/"/g, '""')}"` : s;
};
export function toCsv(rows: Array<Record<string, unknown>>): string {
  if (!rows.length) return '';
  const cols = Object.keys(rows[0]);
  return [cols.join(','), ...rows.map((r) => cols.map((c) => csvCell(r[c])).join(','))].join('\n');
}

export function findingsCsv(i: ReportInput) {
  return toCsv(selectFindings(i).map((f) => ({
    id: f.id, severity: f.severity, priority: f.risk?.score, confidence: f.confidence, status: f.status, category: f.category, source: f.source,
    detector: `${f.detectorId}@${f.detectorVersion}`, title: f.title, score: f.score, score_type: f.scoreType,
    start: fmtTs(f.evidence.tsRange[0]), end: fmtTs(f.evidence.tsRange[1]), entities: f.evidence.entities, packets: f.evidence.packetIdx.slice(0, 30),
    flows: f.evidence.flowIds.slice(0, 20), mitre: f.mitre.map((m) => m.id), incident: f.incidentId || '', tags: f.tags, summary: f.explanation.summary,
  })));
}

export function flowsCsv(run: AnalysisResult) {
  return toCsv(run.flows.map((f) => ({
    id: f.id, transport: f.transport, app: f.app, src: f.src, sport: f.sport, dst: f.dst, dport: f.dport, start: fmtTs(f.start), end: fmtTs(f.end),
    duration_s: f.duration, pkts_fwd: f.pktsFwd, pkts_bwd: f.pktsBwd, bytes_fwd: f.bytesFwd, bytes_bwd: f.bytesBwd, state: f.state, flags: f.flagsSeen,
    sni: f.sni || '', http_host: f.httpHost || '', ja3: f.ja3Hash || '', anomaly_score: f.anomalyScore ?? '',
  })));
}

export function jsonReport(i: ReportInput) {
  const { run } = i;
  return JSON.stringify({
    schema: 'netsentry-xai.report/v2', generatedAt: new Date().toISOString(), analyst: i.analyst,
    case: i.c, capture: i.cap, run: { runId: run.runId, configHash: run.configHash, config: run.config, versions: run.versions, timings: run.timings, warnings: run.warnings, startedAt: run.startedAt, finishedAt: run.finishedAt },
    summary: run.summary, incidents: run.incidents, findings: selectFindings(i), hosts: run.hosts, auditTrail: i.events,
    disclaimer: 'Scores are relative indicators, not probabilities. ATT&CK mappings are hypotheses.',
  }, null, 2);
}

export function stixBundle(i: ReportInput) {
  const ts = new Date().toISOString();
  const identity = { type: 'identity', spec_version: '2.1', id: `identity--${uuid()}`, created: ts, modified: ts, name: i.analyst, identity_class: 'individual' };
  const objects: unknown[] = [identity];
  for (const f of selectFindings(i)) {
    const refs: string[] = [];
    for (const e of f.evidence.entities.slice(0, 10)) {
      if (/^\d+\.\d+\.\d+\.\d+$/.test(e) || e.includes(':')) {
        const o = { type: e.includes(':') ? 'ipv6-addr' : 'ipv4-addr', spec_version: '2.1', id: `${e.includes(':') ? 'ipv6-addr' : 'ipv4-addr'}--${uuid()}`, value: e };
        objects.push(o);
        refs.push(o.id);
      } else if (/\./.test(e)) {
        const o = { type: 'domain-name', spec_version: '2.1', id: `domain-name--${uuid()}`, value: e };
        objects.push(o);
        refs.push(o.id);
      }
    }
    if (!refs.length) continue;
    const od = {
      type: 'observed-data', spec_version: '2.1', id: `observed-data--${uuid()}`, created: ts, modified: ts, created_by_ref: identity.id,
      first_observed: new Date(f.evidence.tsRange[0] * 1000).toISOString(), last_observed: new Date(Math.max(f.evidence.tsRange[0], f.evidence.tsRange[1]) * 1000).toISOString(),
      number_observed: Math.max(1, f.evidence.packetIdx.length), object_refs: refs,
    };
    objects.push(od);
    objects.push({
      type: 'note', spec_version: '2.1', id: `note--${uuid()}`, created: ts, modified: ts, created_by_ref: identity.id,
      abstract: `[${f.severity}] ${f.title}`, content: `${f.explanation.summary}\n\nInterpretation (hypothesis): ${f.explanation.interpretation}\nCaveat: ${f.caveats}\nATT&CK (hypothesis): ${f.mitre.map((m) => m.id).join(', ')}`,
      object_refs: [od.id], x_netsentry_finding_id: f.id, x_netsentry_score: f.score, x_netsentry_priority: f.risk?.score, x_netsentry_status: f.status,
    });
  }
  return JSON.stringify({ type: 'bundle', id: `bundle--${uuid()}`, objects }, null, 2);
}

function uuid() {
  if (typeof crypto !== 'undefined' && 'randomUUID' in crypto) return crypto.randomUUID();
  return uid('').padEnd(32, '0').replace(/^(.{8})(.{4})(.{4})(.{4})(.{12}).*/, '$1-$2-$3-$4-$5');
}
