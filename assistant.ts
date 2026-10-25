// Evidence-grounded investigation assistant. Deterministic: it answers only
// from structured case evidence and cites finding / flow / host IDs. No data
// leaves the browser and no external language model is used.
import type { AnalysisResult, Finding } from '../engine/types';
import { fmtBytes, fmtTs, fmtDur, humanize } from './format';
import { WELL_KNOWN } from '../engine/util';

export type Cite = { kind: 'finding' | 'flow' | 'host' | 'incident' | 'packet'; id: string; label: string };
export interface Answer { text: string[]; cites: Cite[]; table?: { cols: string[]; rows: Array<Array<string | number>> }; intent: string }

const IP_RE = /\b(?:\d{1,3}\.){3}\d{1,3}\b|\b[0-9a-f]{1,4}(?::[0-9a-f]{0,4}){2,7}\b/gi;
const DOMAIN_RE = /\b(?:[a-z0-9-]+\.)+[a-z]{2,24}\b/gi;
const FID_RE = /\bNSX-\d{4}\b/gi;
const FLOW_RE = /\bF\d+\b/g;
const INC_RE = /\bINC-\d{3}\b/gi;

const CAT_WORDS: Array<[RegExp, string[]]> = [
  [/scan|recon|probe|sweep|discover/i, ['reconnaissance']],
  [/beacon|c2|command|heartbeat|callback/i, ['c2_beaconing']],
  [/exfil|upload|egress|leak|transfer/i, ['exfiltration']],
  [/dns|tunnel|nxdomain|dga/i, ['dns_anomaly', 'exfiltration']],
  [/flood|dos|ddos|burst/i, ['dos_flood']],
  [/lateral|smb|rdp|pivot/i, ['lateral_movement']],
  [/arp|spoof|mitm|man.in/i, ['mitm']],
  [/cred|password|cleartext|plaintext|telnet|ftp/i, ['credential_exposure']],
  [/anomal|outlier|unusual|isolation|ml|model/i, ['anomaly']],
  [/port mismatch|non.standard|policy/i, ['policy']],
];

export const SUGGESTIONS = [
  'What happened in this capture?',
  'Show the highest-priority findings',
  'Which hosts are involved in incidents?',
  'Is there any beaconing or C2 activity?',
  'Was data exfiltrated?',
  'What DNS domains were queried most?',
  'Which TLS servers (SNI) were contacted?',
  'Who are the top talkers?',
];

const fCite = (f: Finding): Cite => ({ kind: 'finding', id: f.id, label: `${f.id} · ${f.severity}` });

export function ask(q: string, run: AnalysisResult): Answer {
  const s = run.summary;
  const findings = run.findings.filter((f) => !f.suppressed);
  const lower = q.toLowerCase();
  const ips = [...new Set((q.match(IP_RE) || []).filter((x) => x.includes('.') || x.split(':').length > 2))];
  const domains = [...new Set((q.match(DOMAIN_RE) || []).filter((d) => !/^\d+\./.test(d)))];
  const fids = [...new Set((q.match(FID_RE) || []).map((x) => x.toUpperCase()))];
  const flowIds = [...new Set(q.match(FLOW_RE) || [])];
  const incIds = [...new Set((q.match(INC_RE) || []).map((x) => x.toUpperCase()))];

  // why was NSX-xxxx flagged
  if (fids.length) {
    const f = findings.find((x) => x.id === fids[0]) || run.findings.find((x) => x.id === fids[0]);
    if (!f) return { intent: 'finding', text: [`No finding ${fids[0]} exists in this analysis run.`], cites: [] };
    return {
      intent: 'finding',
      text: [
        `**${f.title}** — ${f.severity} severity, priority ${f.risk?.score}/100, evidence confidence ${f.confidence}.`,
        `Why it was flagged: ${[...f.explanation.ruleEvidence, f.explanation.modelSignal].filter(Boolean).join(' ')}`,
        `Observed facts: ${f.explanation.observedFacts.join(' ')}`,
        `Interpretation (hypothesis): ${f.explanation.interpretation}`,
        `Alternatives to rule out: ${f.explanation.alternatives.join('; ')}.`,
      ],
      cites: [fCite(f), ...f.evidence.flowIds.slice(0, 5).map((id) => ({ kind: 'flow' as const, id, label: id })), ...f.evidence.packetIdx.slice(0, 5).map((p) => ({ kind: 'packet' as const, id: String(p), label: `#${p}` }))],
    };
  }

  if (incIds.length) {
    const inc = run.incidents.find((i) => i.id === incIds[0]);
    if (!inc) return { intent: 'incident', text: [`No incident ${incIds[0]} in this run.`], cites: [] };
    return { intent: 'incident', text: [`**${inc.title}** (${inc.severity}, max priority ${inc.riskMax}).`, inc.narrative, `Grouped because: ${inc.reasons.slice(0, 4).join('; ')}.`], cites: [{ kind: 'incident', id: inc.id, label: inc.id }, ...inc.findingIds.slice(0, 8).map((id) => ({ kind: 'finding' as const, id, label: id }))] };
  }

  if (flowIds.length) {
    const fl = run.flows.find((f) => f.id === flowIds[0]);
    if (fl) {
      const related = findings.filter((f) => f.evidence.flowIds.includes(fl.id));
      return { intent: 'flow', text: [`Flow **${fl.id}**: ${fl.src}:${fl.sport} → ${fl.dst}:${fl.dport} (${fl.transport}/${fl.app}), ${fl.totalPkts} packets, ${fmtBytes(fl.totalBytes)}, ${fmtDur(fl.duration)}, state ${fl.state}${fl.anomalyScore != null ? `, Isolation Forest score ${fl.anomalyScore}` : ''}.`, related.length ? `Referenced by ${related.length} finding(s).` : 'Not referenced by any finding.'], cites: [{ kind: 'flow', id: fl.id, label: fl.id }, ...related.map(fCite)] };
    }
  }

  // host / domain questions
  if (ips.length || (domains.length && !/most|top/.test(lower))) {
    const target = ips[0] || domains[0];
    const host = run.hosts.find((h) => h.ip === target);
    const byName = !host ? run.hosts.filter((h) => h.hostnames.some((n) => n.toLowerCase().includes(target.toLowerCase()))) : [];
    const hostIps = host ? [host.ip] : byName.map((h) => h.ip);
    const rel = findings.filter((f) => f.evidence.entities.some((e) => e === target || hostIps.includes(e)));
    const flows = run.flows.filter((f) => hostIps.includes(f.src) || hostIps.includes(f.dst));
    const dnsHits = run.packets.filter((p) => p.meta.dns?.query?.toLowerCase().includes(target.toLowerCase())).slice(0, 200);
    if (!host && !byName.length && !rel.length && !dnsHits.length) return { intent: 'entity', text: [`${target} does not appear in this capture's hosts, DNS queries, SNI or findings.`], cites: [] };
    const text: string[] = [];
    if (host) {
      text.push(`**${host.ip}** (${host.internal ? 'internal' : 'external'}${host.hostnames.length ? ', seen as ' + host.hostnames.join(', ') : ''}) — role: ${host.role}.`);
      text.push(`Sent ${fmtBytes(host.bytesOut)} / received ${fmtBytes(host.bytesIn)} across ${host.flowsOut} outbound and ${host.flowsIn} inbound flows; contacted ${host.fanOut} hosts on ${host.distinctDstPorts} ports; ${host.failedConns} failed connection attempts. Active ${fmtTs(host.firstSeen)} → ${fmtTs(host.lastSeen)}.`);
    } else if (byName.length) text.push(`${target} resolved to / was served by: ${byName.map((h) => h.ip).join(', ')}.`);
    if (dnsHits.length) text.push(`${dnsHits.length} DNS packet(s) mention ${target}.`);
    text.push(rel.length ? `Involved in ${rel.length} finding(s): ${rel.slice(0, 5).map((f) => f.title).join('; ')}${rel.length > 5 ? '…' : ''}` : 'Not involved in any finding.');
    const peers = new Map<string, number>();
    for (const f of flows) { const p = hostIps.includes(f.src) ? f.dst : f.src; peers.set(p, (peers.get(p) || 0) + f.totalBytes); }
    return {
      intent: 'entity', text,
      cites: [...hostIps.slice(0, 3).map((ip) => ({ kind: 'host' as const, id: ip, label: ip })), ...rel.slice(0, 8).map(fCite)],
      table: peers.size ? { cols: ['Peer', 'Bytes'], rows: [...peers.entries()].sort((a, b) => b[1] - a[1]).slice(0, 8).map(([p, b]) => [p, fmtBytes(b)]) } : undefined,
    };
  }

  // category questions
  for (const [re, cats] of CAT_WORDS) {
    if (re.test(lower) && !/what happened|summar|overview/.test(lower)) {
      const rel = findings.filter((f) => cats.includes(f.category) || (cats.includes('dns_anomaly') && f.detectorId === 'rule_dns_anomaly'));
      if (!rel.length) return { intent: 'category', text: [`No ${cats.map(humanize).join(' / ')} findings were raised in this capture with the current thresholds.`, 'Absence of a finding does not prove absence of activity — the capture window and vantage point may be limited.'], cites: [] };
      return {
        intent: 'category',
        text: [`${rel.length} related finding(s):`, ...rel.slice(0, 6).map((f) => `• ${f.title} — priority ${f.risk?.score}, ${f.confidence} confidence. ${f.explanation.summary}`)],
        cites: rel.slice(0, 10).map(fCite),
      };
    }
  }

  if (/dns|domain|quer/.test(lower)) {
    return { intent: 'dns', text: [`${s.topDomains.length ? 'Most-queried names:' : 'No DNS queries were observed.'}`], cites: [], table: s.topDomains.length ? { cols: ['Name', 'Queries'], rows: s.topDomains.map((d) => [d.name, d.count]) } : undefined };
  }
  if (/tls|sni|https|ja3|certificate/.test(lower)) {
    const ja3 = new Map<string, number>();
    for (const f of run.flows) if (f.ja3Hash) ja3.set(f.ja3Hash, (ja3.get(f.ja3Hash) || 0) + 1);
    return { intent: 'tls', text: [s.topSni.length ? `TLS server names seen in ClientHello messages (${ja3.size} distinct JA3 client fingerprints):` : 'No TLS ClientHello SNI values were observed.'], cites: [], table: s.topSni.length ? { cols: ['SNI', 'ClientHellos'], rows: s.topSni.map((d) => [d.name, d.count]) } : undefined };
  }
  if (/talker|bandwidth|volume|largest|biggest|top host|most traffic/.test(lower)) {
    return { intent: 'talkers', text: ['Top sources by bytes sent:'], cites: s.topSrc.slice(0, 5).map((t) => ({ kind: 'host' as const, id: t.ip, label: t.ip })), table: { cols: ['Host', 'Packets', 'Bytes'], rows: s.topSrc.map((t) => [t.ip, t.packets, fmtBytes(t.bytes)]) } };
  }
  if (/port|service/.test(lower)) {
    return { intent: 'ports', text: ['Most-used destination ports (by flow count):'], cites: [], table: { cols: ['Port', 'Service', 'Flows'], rows: s.topPorts.map((p) => [p.port, WELL_KNOWN[p.port] || '—', p.flows]) } };
  }
  if (/protocol/.test(lower)) {
    return { intent: 'protocols', text: ['Protocol distribution (highest decoded layer):'], cites: [], table: { cols: ['Protocol', 'Packets'], rows: Object.entries(s.protocols).sort((a, b) => b[1] - a[1]).map(([k, v]) => [k, v]) } };
  }
  if (/incident|correlat|campaign|related/.test(lower)) {
    if (!run.incidents.length) return { intent: 'incidents', text: ['No findings were correlated into incidents (no shared entities within the correlation window).'], cites: [] };
    return { intent: 'incidents', text: run.incidents.map((i) => `• **${i.id}** ${i.title} — ${i.findingIds.length} findings, tactics: ${i.tactics.join(' → ') || 'n/a'}. Entities: ${i.entities.slice(0, 6).join(', ')}.`), cites: run.incidents.map((i) => ({ kind: 'incident' as const, id: i.id, label: i.id })) };
  }
  if (/critical|high|priority|top finding|worst|riskiest|important|urgent/.test(lower)) {
    const top = findings.slice(0, 6);
    return { intent: 'priority', text: top.length ? ['Highest-priority findings (priority is a transparent ranking, not a probability):', ...top.map((f) => `• [${f.risk?.score}] ${f.title}`)] : ['No findings.'], cites: top.map(fCite) };
  }
  if (/how many|count|number of|stats|size/.test(lower)) {
    return { intent: 'stats', text: [`${s.parsedPackets.toLocaleString()} packets (${fmtBytes(s.totalBytes)}) over ${fmtDur(s.duration)}, ${s.totalFlows.toLocaleString()} flows, ${s.hostsInternal} internal and ${s.hostsExternal} external hosts, ${findings.length} findings and ${run.incidents.length} incidents.`], cites: [] };
  }
  if (/first|start|begin|earliest|when/.test(lower)) {
    const ord = [...findings].sort((a, b) => a.evidence.tsRange[0] - b.evidence.tsRange[0]);
    return { intent: 'timeline', text: [`Capture runs ${fmtTs(s.start)} → ${fmtTs(s.end)}.`, ...ord.slice(0, 6).map((f) => `• ${fmtTs(f.evidence.tsRange[0], false)} — ${f.title}`)], cites: ord.slice(0, 6).map(fCite) };
  }
  if (/help|what can you|how do/.test(lower)) {
    return { intent: 'help', text: ['I answer from this case\'s structured evidence only, with citations. Try:', ...SUGGESTIONS.map((x) => `• ${x}`), '• Ask about a specific IP, domain, finding ID (NSX-0001), flow ID (F12) or incident (INC-001).'], cites: [] };
  }

  // default: summary
  const top = findings.slice(0, 4);
  return {
    intent: 'summary',
    text: [
      `The capture spans ${fmtDur(s.duration)} (${fmtTs(s.start)} → ${fmtTs(s.end)}) with ${s.parsedPackets.toLocaleString()} packets, ${s.totalFlows.toLocaleString()} flows and ${s.hostsInternal + s.hostsExternal} hosts.`,
      findings.length ? `${findings.length} findings were raised (${Object.entries(s.bySeverity).map(([k, v]) => `${v} ${k}`).join(', ')}), grouped into ${run.incidents.length} candidate incident(s).` : 'No findings were raised with the current thresholds.',
      ...(run.incidents[0] ? [`Most significant incident: ${run.incidents[0].title}. Tactic progression (hypothesis): ${run.incidents[0].tactics.join(' → ') || 'n/a'}.`] : []),
      ...top.map((f) => `• [${f.risk?.score}] ${f.title}`),
      'All statements above are derived from the parsed evidence; interpretations are hypotheses for analyst review.',
    ],
    cites: [...run.incidents.slice(0, 2).map((i) => ({ kind: 'incident' as const, id: i.id, label: i.id })), ...top.map(fCite)],
  };
}
