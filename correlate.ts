// Incident correlation (shared entities + time proximity, union-find) and
// transparent, versioned risk prioritisation.
import type { AnalysisConfig, Finding, Incident, Severity } from './types';
import { isInternalIp, round } from './util';

export const SEV_RANK: Record<Severity, number> = { critical: 4, high: 3, medium: 2, low: 1, informational: 0 };
const SEV_VALUE: Record<Severity, number> = { critical: 1, high: 0.75, medium: 0.5, low: 0.25, informational: 0.1 };
const TACTIC_ORDER = ['Discovery', 'Credential Access', 'Lateral Movement', 'Command and Control', 'Exfiltration', 'Impact'];

export function correlate(findings: Finding[], cfg: AnalysisConfig): Incident[] {
  const n = findings.length;
  const parent = Array.from({ length: n }, (_, i) => i);
  const find = (x: number): number => (parent[x] === x ? x : (parent[x] = find(parent[x])));
  const reasons = new Map<string, Set<string>>();
  const union = (a: number, b: number, why: string) => {
    const ra = find(a), rb = find(b);
    if (ra !== rb) parent[ra] = rb;
    const key = `${Math.min(a, b)}-${Math.max(a, b)}`;
    (reasons.get(key) || reasons.set(key, new Set()).get(key)!).add(why);
  };
  const ents = findings.map((f) => new Set(f.evidence.entities.filter((e) => e && !e.endsWith('.255') && e !== '0.0.0.0')));
  for (let i = 0; i < n; i++) {
    for (let j = i + 1; j < n; j++) {
      const shared = [...ents[i]].filter((e) => ents[j].has(e));
      if (!shared.length) continue;
      const [a0, a1] = findings[i].evidence.tsRange;
      const [b0, b1] = findings[j].evidence.tsRange;
      const gap = Math.max(0, Math.max(a0, b0) - Math.min(a1, b1));
      if (gap > cfg.correlationWindow) continue;
      union(i, j, `shared entity ${shared.slice(0, 2).join(', ')}; ${gap === 0 ? 'overlapping in time' : `${round(gap, 1)}s apart`}`);
    }
  }
  const groups = new Map<number, number[]>();
  for (let i = 0; i < n; i++) (groups.get(find(i)) || groups.set(find(i), []).get(find(i))!).push(i);
  const incidents: Incident[] = [];
  let k = 0;
  for (const idx of groups.values()) {
    if (idx.length < 2) continue;
    k++;
    const fs = idx.map((i) => findings[i]);
    const entCount = new Map<string, number>();
    for (const i of idx) for (const e of ents[i]) entCount.set(e, (entCount.get(e) || 0) + 1);
    const pivot = [...entCount.entries()].sort((a, b) => b[1] - a[1])[0][0];
    const why = new Set<string>();
    for (const a of idx) for (const b of idx) {
      const r = reasons.get(`${Math.min(a, b)}-${Math.max(a, b)}`);
      if (r) r.forEach((x) => why.add(x));
    }
    const tactics = [...new Set(fs.flatMap((f) => f.mitre.map((m) => m.tactic)))].sort((a, b) => TACTIC_ORDER.indexOf(a) - TACTIC_ORDER.indexOf(b));
    const sev = fs.reduce<Severity>((s, f) => (SEV_RANK[f.severity] > SEV_RANK[s] ? f.severity : s), 'informational');
    const ordered = [...fs].sort((a, b) => a.evidence.tsRange[0] - b.evidence.tsRange[0]);
    const id = `INC-${String(k).padStart(3, '0')}`;
    const stages = ordered.map((f) => f.category.replace(/_/g, ' ')).filter((v, i, a) => a.indexOf(v) === i);
    incidents.push({
      id,
      title: tactics.length >= 2 ? `Multi-stage activity centred on ${pivot} (${tactics.length} ATT&CK tactics)` : `Related ${stages.slice(0, 2).join(' / ')} activity around ${pivot}`,
      severity: sev,
      riskMax: 0,
      start: Math.min(...fs.map((f) => f.evidence.tsRange[0])),
      end: Math.max(...fs.map((f) => f.evidence.tsRange[1])),
      findingIds: ordered.map((f) => f.id),
      entities: [...entCount.keys()].slice(0, 20),
      pivot,
      reasons: [...why].slice(0, 12),
      tactics,
      narrative:
        `Candidate incident grouping ${fs.length} findings that share ${pivot}. Sequence: ` +
        ordered.map((f) => `[${new Date(f.evidence.tsRange[0] * 1000).toISOString().slice(11, 19)}] ${f.title}`).join(' → ') +
        `. ${tactics.length > 1 ? `The observed ATT&CK tactics (${tactics.join(' → ')}) form a plausible progression, presented as a hypothesis for analyst review.` : ''}`,
    });
    for (const f of fs) f.incidentId = id;
  }
  return incidents.sort((a, b) => SEV_RANK[b.severity] - SEV_RANK[a.severity] || b.findingIds.length - a.findingIds.length);
}

export function scoreRisk(findings: Finding[], incidents: Incident[], flowsAnomaly: Map<string, number>, cfg: AnalysisConfig) {
  const w = cfg.weights;
  const wsum = w.severity + w.anomaly + w.evidence + w.corroboration + w.context || 1;
  const byId = new Map(findings.map((f) => [f.id, f]));
  const critical = new Set(cfg.criticalAssets.map((s) => s.trim()).filter(Boolean));
  for (const f of findings) {
    const severity = SEV_VALUE[f.severity];
    let anomaly = 0;
    if (f.source === 'model') anomaly = Math.min(1, Math.max(0, (f.score - 0.5) * 2));
    else if (f.source === 'statistical') anomaly = Math.min(1, f.score / 10);
    else for (const id of f.evidence.flowIds) anomaly = Math.max(anomaly, Math.min(1, Math.max(0, ((flowsAnomaly.get(id) || 0) - 0.5) * 2)));
    const pk = f.evidence.packetIdx.length;
    const evidence = Math.min(1, (Math.log10(1 + pk) / 1.6) * (f.evidence.flowIds.length > 0 ? 1 : 0.85)) * (f.confidence === 'low' ? 0.7 : 1);
    let corroboration = 0;
    if (f.incidentId) {
      const inc = incidents.find((i) => i.id === f.incidentId)!;
      const others = new Set(inc.findingIds.filter((x) => x !== f.id).map((x) => byId.get(x)!.detectorId).filter((d) => d !== f.detectorId));
      corroboration = Math.min(1, others.size / 3);
    }
    let context = 0.2;
    if (f.evidence.entities.some((e) => critical.has(e))) context = 1;
    else if (f.evidence.entities.some((e) => isInternalIp(e))) context = 0.5;
    const comps = { severity, anomaly, evidence, corroboration, context };
    const score = ((w.severity * severity + w.anomaly * anomaly + w.evidence * evidence + w.corroboration * corroboration + w.context * context) / wsum) * 100;
    f.risk = {
      score: Math.round(score),
      components: Object.fromEntries(Object.entries(comps).map(([k, v]) => [k, round(v, 3)])) as typeof comps,
      weights: { ...w },
    };
  }
  for (const inc of incidents) inc.riskMax = Math.max(...inc.findingIds.map((id) => byId.get(id)?.risk?.score || 0));
}
