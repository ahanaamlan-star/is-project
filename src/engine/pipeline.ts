// End-to-end analysis pipeline (runs inside a Web Worker).
import type { AnalysisConfig, AnalysisResult, CaptureSummary, Finding, StageTiming, Flow } from './types';
import { ENGINE_VERSION, PARSER_NAME, PARSER_VERSION } from './types';
import { parseCapture, LINKTYPE_NAMES } from './pcap';
import { buildFlows, buildHosts, buildDnsMap } from './flows';
import { runDetectors, resetFindingSeq } from './detectors';
import { correlate, scoreRisk, SEV_RANK } from './correlate';
import { stableHash, isInternalIp } from './util';

export type ProgressFn = (stage: string, pct: number, detail?: string) => void;

export function analyze(
  buf: ArrayBuffer,
  ids: { runId: string; captureId: string; caseId: string },
  cfg: AnalysisConfig,
  progress: ProgressFn = () => {},
): AnalysisResult {
  const timings: StageTiming[] = [];
  const started = new Date().toISOString();
  let t0 = performance.now();
  const lap = (stage: string) => {
    const t = performance.now();
    timings.push({ stage, ms: Math.round((t - t0) * 100) / 100 });
    t0 = t;
  };

  progress('Parsing packets', 0.02);
  const parsed = parseCapture(buf, { maxPackets: cfg.maxPackets, onProgress: (p, n) => progress('Parsing packets', 0.02 + p * 0.45, `${n.toLocaleString()} packets decoded`) });
  const packets = parsed.packets;
  lap('parse');

  progress('Reconstructing flows', 0.5, `${packets.length.toLocaleString()} packets`);
  const dnsMap = buildDnsMap(packets);
  const flows = buildFlows(packets, cfg.flowIdleTimeout);
  const hosts = buildHosts(flows, packets, dnsMap);
  lap('flows_features');

  progress('Running detectors', 0.65, `${flows.length.toLocaleString()} flows`);
  resetFindingSeq();
  const captureLimits: string[] = [];
  if (parsed.truncated > 0) captureLimits.push('Capture was truncated by snaplen; payload-derived metadata may be incomplete.');
  if (parsed.totalFrames > cfg.maxPackets) captureLimits.push('Only part of the capture was analysed (packet limit reached).');
  const ctx = { packets, flows, hosts, cfg, runId: ids.runId, captureLimits, claimed: new Set<string>() };
  const t1 = performance.now();
  const { findings, versions } = runDetectors(ctx);
  timings.push({ stage: 'detection', ms: Math.round((performance.now() - t1) * 100) / 100 });
  t0 = performance.now();

  // Allowlist suppression (kept for audit, hidden by default)
  const allow = new Set(cfg.allowlist.map((s) => s.trim().toLowerCase()).filter(Boolean));
  if (allow.size) for (const f of findings) if (f.evidence.entities.some((e) => allow.has(String(e).toLowerCase()))) { f.suppressed = true; f.tags.push('allowlisted'); }

  progress('Correlating incidents', 0.85);
  const active = findings.filter((f) => !f.suppressed);
  const incidents = correlate(active, cfg);
  const anomalyMap = new Map(flows.filter((f) => f.anomalyScore != null).map((f) => [f.id, f.anomalyScore!]));
  scoreRisk(findings, incidents, anomalyMap, cfg);
  findings.sort((a, b) => (b.risk?.score || 0) - (a.risk?.score || 0) || SEV_RANK[b.severity] - SEV_RANK[a.severity]);
  lap('correlation_scoring');

  progress('Building summary', 0.93);
  const summary = summarize(parsed.format, [...parsed.linktypes], packets, flows, findings, parsed.totalFrames, parsed.truncated, hosts.filter((h) => h.internal).length, hosts.filter((h) => !h.internal).length);
  lap('summary');

  for (const f of flows as Flow[]) { delete f._ts; delete f._sizes; }
  const warnings = [...parsed.warnings];
  if (flows.length && flows.length < 8 && cfg.runML) warnings.push('Fewer than 8 TCP/UDP flows: the Isolation Forest baseline was skipped (sample too small to be meaningful).');

  return {
    runId: ids.runId, captureId: ids.captureId, caseId: ids.caseId,
    configHash: stableHash(cfg), config: cfg,
    versions: { engine: ENGINE_VERSION, parser: `${PARSER_NAME} ${PARSER_VERSION}`, ...versions },
    startedAt: started, finishedAt: new Date().toISOString(), timings, warnings, summary,
    packets, flows, hosts, findings, incidents, dnsMap,
  };
}

function top<K>(m: Map<K, number>, n: number) {
  return [...m.entries()].sort((a, b) => b[1] - a[1]).slice(0, n);
}

function summarize(format: 'pcap' | 'pcapng', lts: number[], packets: AnalysisResult['packets'], flows: Flow[], findings: Finding[], total: number, truncated: number, hi: number, he: number): CaptureSummary {
  const protocols: Record<string, number> = {};
  const transports: Record<string, number> = {};
  const src = new Map<string, { p: number; b: number }>();
  const dst = new Map<string, { p: number; b: number }>();
  const domains = new Map<string, number>();
  const snis = new Map<string, number>();
  let bytes = 0;
  let start: number | null = null;
  let end: number | null = null;
  for (const p of packets) {
    protocols[p.proto] = (protocols[p.proto] || 0) + 1;
    transports[p.transport] = (transports[p.transport] || 0) + 1;
    bytes += p.len;
    if (p.ts > 0) {
      if (start === null || p.ts < start) start = p.ts;
      if (end === null || p.ts > end) end = p.ts;
    }
    if (p.src) { const s = src.get(p.src) || { p: 0, b: 0 }; s.p++; s.b += p.len; src.set(p.src, s); }
    if (p.dst) { const d = dst.get(p.dst) || { p: 0, b: 0 }; d.p++; d.b += p.len; dst.set(p.dst, d); }
    if (p.meta.dns?.qr === 'query' && p.meta.dns.query) domains.set(p.meta.dns.query, (domains.get(p.meta.dns.query) || 0) + 1);
    if (p.meta.tls?.sni) snis.set(p.meta.tls.sni, (snis.get(p.meta.tls.sni) || 0) + 1);
  }
  const duration = start !== null && end !== null ? end - start : 0;
  const nice = [1, 2, 5, 10, 15, 30, 60, 120, 300, 600, 900, 1800, 3600, 7200, 21600, 43200, 86400];
  const bucketSeconds = nice.find((s) => duration / s <= 120) || 86400;
  const buckets: CaptureSummary['buckets'] = [];
  if (start !== null) {
    const base = Math.floor(start / bucketSeconds) * bucketSeconds;
    const nb = Math.floor((end! - base) / bucketSeconds) + 1;
    for (let i = 0; i < nb; i++) buckets.push({ t: base + i * bucketSeconds, packets: 0, bytes: 0, findings: 0 });
    for (const p of packets) {
      if (p.ts <= 0) continue;
      const b = buckets[Math.floor((p.ts - base) / bucketSeconds)];
      if (b) { b.packets++; b.bytes += p.len; }
    }
    for (const f of findings) {
      if (f.suppressed) continue;
      const b = buckets[Math.floor((f.evidence.tsRange[0] - base) / bucketSeconds)];
      if (b) b.findings++;
    }
  }
  const ports = new Map<number, number>();
  for (const f of flows) if (f.dport != null && f.dport < 49152) ports.set(f.dport, (ports.get(f.dport) || 0) + 1);
  const bySeverity: Record<string, number> = {};
  const byCategory: Record<string, number> = {};
  for (const f of findings) {
    if (f.suppressed) continue;
    bySeverity[f.severity] = (bySeverity[f.severity] || 0) + 1;
    byCategory[f.category] = (byCategory[f.category] || 0) + 1;
  }
  return {
    format, linktypes: lts.map((l) => LINKTYPE_NAMES[l] || `LINKTYPE_${l}`),
    totalPackets: total, parsedPackets: packets.length, totalBytes: bytes, totalFlows: flows.length,
    start, end, duration, protocols, transports,
    topSrc: [...src.entries()].sort((a, b) => b[1].b - a[1].b).slice(0, 10).map(([ip, v]) => ({ ip, packets: v.p, bytes: v.b })),
    topDst: [...dst.entries()].sort((a, b) => b[1].b - a[1].b).slice(0, 10).map(([ip, v]) => ({ ip, packets: v.p, bytes: v.b })),
    topPorts: top(ports, 10).map(([port, n]) => ({ port, flows: n })),
    topDomains: top(domains, 10).map(([name, count]) => ({ name, count })),
    topSni: top(snis, 10).map(([name, count]) => ({ name, count })),
    hostsInternal: hi, hostsExternal: he, buckets, bucketSeconds, truncatedPackets: truncated, bySeverity, byCategory,
  };
}

export { isInternalIp };
