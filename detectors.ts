// ───────────────────────────────────────────────────────────────────────────
// Layered detection: transparent rules → statistical baselines → unsupervised
// model. Every finding separates (1) observed facts, (2) detection rationale
// and (3) interpretation, and links back to packets, flows and timestamps.
// ───────────────────────────────────────────────────────────────────────────
import type { AnalysisConfig, Finding, Flow, HostSummary, PacketRecord, Severity, SignalSource, Explanation, MitreRef, FeatureContribution } from './types';
import { timingStats, round, isInternalIp, isBroadcastOrMulticast, median, mad, std, mean, SUSPICIOUS_PORTS, TLS_PORTS, HTTP_PORTS, ADMIN_PORTS, WELL_KNOWN } from './util';
import { isolationForest } from './iforest';

export interface DetectorMeta {
  id: string;
  version: string;
  name: string;
  source: SignalSource;
  category: string;
  defaultSeverity: Severity;
  description: string;
  caveat: string;
  mitre: MitreRef[];
}

const M = {
  scan: { id: 'T1046', name: 'Network Service Discovery', tactic: 'Discovery' },
  remoteDisc: { id: 'T1018', name: 'Remote System Discovery', tactic: 'Discovery' },
  dns: { id: 'T1071.004', name: 'Application Layer Protocol: DNS', tactic: 'Command and Control' },
  dga: { id: 'T1568.002', name: 'Dynamic Resolution: Domain Generation Algorithms', tactic: 'Command and Control' },
  exfilAlt: { id: 'T1048', name: 'Exfiltration Over Alternative Protocol', tactic: 'Exfiltration' },
  exfilC2: { id: 'T1041', name: 'Exfiltration Over C2 Channel', tactic: 'Exfiltration' },
  web: { id: 'T1071.001', name: 'Application Layer Protocol: Web Protocols', tactic: 'Command and Control' },
  dosNet: { id: 'T1498', name: 'Network Denial of Service', tactic: 'Impact' },
  dosEnd: { id: 'T1499', name: 'Endpoint Denial of Service', tactic: 'Impact' },
  arp: { id: 'T1557.002', name: 'Adversary-in-the-Middle: ARP Cache Poisoning', tactic: 'Credential Access' },
  sniff: { id: 'T1040', name: 'Network Sniffing', tactic: 'Credential Access' },
  remoteSvc: { id: 'T1021', name: 'Remote Services', tactic: 'Lateral Movement' },
  nonStdPort: { id: 'T1571', name: 'Non-Standard Port', tactic: 'Command and Control' },
  protoTun: { id: 'T1572', name: 'Protocol Tunneling', tactic: 'Command and Control' },
  bruteforce: { id: 'T1110', name: 'Brute Force', tactic: 'Credential Access' },
};

export const DETECTORS: DetectorMeta[] = [
  { id: 'rule_port_scan', version: '2.0.0', name: 'Port / host scan', source: 'rule', category: 'reconnaissance', defaultSeverity: 'high', mitre: [M.scan],
    description: 'Vertical (many ports on one host) and horizontal (one port across many hosts) sweeps inside a sliding time window.',
    caveat: 'Legitimate asset discovery, vulnerability scanners and monitoring can resemble scanning activity.' },
  { id: 'rule_failed_connections', version: '1.0.0', name: 'Repeated failed connections', source: 'rule', category: 'reconnaissance', defaultSeverity: 'medium', mitre: [M.scan, M.bruteforce],
    description: 'A source with many TCP attempts that never complete a handshake (Zeek-style S0/REJ states).',
    caveat: 'Misconfigured services, firewall drops, or asymmetric capture visibility also produce unanswered SYNs.' },
  { id: 'rule_icmp_sweep', version: '1.0.0', name: 'ICMP ping sweep', source: 'rule', category: 'reconnaissance', defaultSeverity: 'medium', mitre: [M.remoteDisc],
    description: 'One source sends ICMP echo requests to many distinct hosts.',
    caveat: 'Network monitoring and inventory tools routinely ping-sweep subnets.' },
  { id: 'rule_dns_anomaly', version: '2.0.0', name: 'DNS anomalies', source: 'rule', category: 'dns_anomaly', defaultSeverity: 'high', mitre: [M.dns, M.dga],
    description: 'Elevated NXDOMAIN ratios, long/high-entropy query labels (tunnelling) and excessive unique subdomains per base domain.',
    caveat: 'Encrypted DNS (DoH/DoT), split-horizon DNS and CDN/telemetry naming schemes can produce high entropy or NXDOMAINs.' },
  { id: 'rule_beacon_periodicity', version: '2.0.0', name: 'Beacon-like periodicity', source: 'rule', category: 'c2_beaconing', defaultSeverity: 'high', mitre: [M.web, M.exfilC2],
    description: 'Repeated connections to the same destination at regular intervals (low coefficient of variation) with consistent sizes.',
    caveat: 'NTP, telemetry agents, health checks and update pollers are periodic by design.' },
  { id: 'rule_traffic_burst', version: '2.0.0', name: 'Traffic burst / SYN flood', source: 'rule', category: 'dos_flood', defaultSeverity: 'high', mitre: [M.dosNet, M.dosEnd],
    description: 'Per-second packet rate above threshold, merged into burst windows; SYN-dominated bursts are labelled as possible floods.',
    caveat: 'Backups, streaming and load tests can surge; capture slices and packet loss distort rate estimates.' },
  { id: 'rule_outbound_transfer', version: '2.0.0', name: 'Large outbound transfer', source: 'rule', category: 'exfiltration', defaultSeverity: 'high', mitre: [M.exfilAlt, M.exfilC2],
    description: 'Internal→external flows (or aggregates to one destination) whose outbound bytes exceed a threshold.',
    caveat: 'Cloud backup, uploads, software distribution and video calls legitimately move large volumes.' },
  { id: 'rule_tcp_flag_anomaly', version: '2.0.0', name: 'Invalid TCP flag combinations', source: 'rule', category: 'reconnaissance', defaultSeverity: 'high', mitre: [M.scan],
    description: 'SYN+FIN, Xmas (FIN+PSH+URG) and NULL-flag packets that violate RFC 793 state transitions.',
    caveat: 'Custom test harnesses, fuzzers and some legacy devices emit non-standard flags.' },
  { id: 'rule_protocol_port_mismatch', version: '1.0.0', name: 'Protocol / port mismatch', source: 'rule', category: 'policy', defaultSeverity: 'low', mitre: [M.nonStdPort, M.protoTun],
    description: 'Application protocols observed on unexpected ports (TLS/HTTP/SSH off their usual ports, plaintext HTTP on 443).',
    caveat: 'Developer services, proxies and appliances often run on custom ports. Merits review, not proof of compromise.' },
  { id: 'rule_cleartext_credentials', version: '1.0.0', name: 'Cleartext authentication', source: 'rule', category: 'credential_exposure', defaultSeverity: 'medium', mitre: [M.sniff],
    description: 'Presence of credentials in cleartext protocols (HTTP Basic, FTP, POP3, IMAP, SMTP AUTH, Telnet). Values are never stored.',
    caveat: 'Lab environments and legacy internal systems may intentionally use cleartext protocols.' },
  { id: 'rule_arp_spoofing', version: '1.0.0', name: 'ARP spoofing indicators', source: 'rule', category: 'mitm', defaultSeverity: 'high', mitre: [M.arp],
    description: 'An IP address claimed by multiple MAC addresses in ARP replies, or bursts of unsolicited (gratuitous) ARP replies.',
    caveat: 'Failover pairs (VRRP/HSRP), virtualisation and NIC teaming can legitimately move IPs between MACs.' },
  { id: 'rule_lateral_movement', version: '1.0.0', name: 'Internal admin-protocol fan-out', source: 'rule', category: 'lateral_movement', defaultSeverity: 'high', mitre: [M.remoteSvc],
    description: 'An internal host contacting many internal hosts on administrative ports (SMB, RDP, SSH, WinRM, RPC).',
    caveat: 'Patch management, backup agents, domain controllers and IT jump hosts legitimately fan out on admin ports.' },
  { id: 'rule_fan_in', version: '1.0.0', name: 'High fan-in convergence', source: 'rule', category: 'dos_flood', defaultSeverity: 'medium', mitre: [M.dosNet],
    description: 'Many distinct sources converging on one destination (possible distributed flood or popular-service effect).',
    caveat: 'Public-facing services and shared infrastructure naturally receive traffic from many sources.' },
  { id: 'rule_suspicious_port', version: '1.0.0', name: 'Known-suspicious port usage', source: 'rule', category: 'c2_beaconing', defaultSeverity: 'medium', mitre: [M.nonStdPort],
    description: 'Established sessions to ports commonly associated with backdoors, RAT handlers, IRC or Tor.',
    caveat: 'Port numbers are weak evidence: any service can be configured on any port.' },
  { id: 'stat_host_volume_outlier', version: '1.0.0', name: 'Host egress volume outlier', source: 'statistical', category: 'anomaly', defaultSeverity: 'medium', mitre: [],
    description: 'Robust z-score (median/MAD) of per-host outbound bytes relative to all hosts in this capture.',
    caveat: 'Baseline is this capture only; a busy server or backup host will be an outlier without being malicious.' },
  { id: 'ml_isolation_forest_flow', version: '2.0.0', name: 'Isolation Forest flow outlier', source: 'model', category: 'anomaly', defaultSeverity: 'medium', mitre: [],
    description: 'Unsupervised Isolation Forest over log-scaled flow features; top-ranked outliers with path-based feature attribution.',
    caveat: 'Statistical unusualness is NOT an attack probability. Rare but legitimate workflows also score highly.' },
];

const META = Object.fromEntries(DETECTORS.map((d) => [d.id, d]));

export interface DetectContext {
  packets: PacketRecord[];
  flows: Flow[];
  hosts: HostSummary[];
  cfg: AnalysisConfig;
  runId: string;
  captureLimits: string[];
  claimed: Set<string>; // sources already explained by a primary detector
}

let fseq = 0;
export function resetFindingSeq() { fseq = 0; }

function make(
  ctx: DetectContext,
  id: string,
  p: {
    severity: Severity;
    title: string;
    score: number;
    scoreType?: string;
    category?: string;
    explanation: Omit<Explanation, 'limitations'> & { limitations?: string[] };
    srcIp?: string;
    dstIp?: string;
    entities: string[];
    packetIdx: number[];
    flowIds: string[];
    tsRange: [number, number];
    observed: Record<string, unknown>;
    thresholds: Record<string, unknown>;
    contributions?: FeatureContribution[];
    mitre?: MitreRef[];
  },
): Finding {
  const meta = META[id];
  fseq++;
  const pk = p.packetIdx.length;
  const confidence = ctx.captureLimits.length > 0 && pk < 10 ? 'low' : pk >= 20 || p.flowIds.length >= 5 ? 'high' : pk >= 4 ? 'medium' : 'low';
  return {
    id: `NSX-${String(fseq).padStart(4, '0')}`,
    runId: ctx.runId,
    detectorId: id,
    detectorVersion: meta.version,
    source: meta.source,
    category: p.category || meta.category,
    severity: p.severity,
    confidence,
    title: p.title,
    scoreType: p.scoreType || (meta.source === 'rule' ? 'rule_confidence' : meta.source === 'model' ? 'isolation_forest_score' : 'robust_z_score'),
    score: round(p.score, 3),
    explanation: {
      ...p.explanation,
      limitations: [...(p.explanation.limitations || []), ...ctx.captureLimits,
        'A single vantage point may miss asymmetric return paths or internal hops.',
        'Encrypted payloads are not inspected; only observable metadata is used.'],
    },
    caveats: meta.caveat,
    evidence: {
      srcIp: p.srcIp, dstIp: p.dstIp, entities: [...new Set(p.entities.filter(Boolean))],
      packetIdx: [...new Set(p.packetIdx)].slice(0, 60), flowIds: [...new Set(p.flowIds)].slice(0, 40),
      tsRange: p.tsRange, observed: p.observed, thresholds: p.thresholds, contributions: p.contributions,
    },
    mitre: p.mitre || meta.mitre,
    status: 'new',
    tags: [],
  };
}

const isFailed = (f: Flow) => f.state === 'S0' || f.state === 'REJ' || f.state === 'HALF';
const fmtBytes = (b: number) => (b >= 1048576 ? `${(b / 1048576).toFixed(2)} MB` : b >= 1024 ? `${(b / 1024).toFixed(1)} KB` : `${b} B`);

// ── 1. Port / host scan ────────────────────────────────────────────────────
function portScan(ctx: DetectContext): Finding[] {
  const { scanPorts, scanWindow, sweepHosts } = ctx.cfg.thresholds;
  const out: Finding[] = [];
  const bySrc = new Map<string, Flow[]>();
  for (const f of ctx.flows) if (f.transport === 'TCP' || f.transport === 'UDP') (bySrc.get(f.src) || bySrc.set(f.src, []).get(f.src)!).push(f);
  for (const [src, flows] of bySrc) {
    // vertical: per destination, sliding window over distinct ports
    const byDst = new Map<string, Flow[]>();
    for (const f of flows) (byDst.get(f.dst) || byDst.set(f.dst, []).get(f.dst)!).push(f);
    let best: { dst: string; ports: Set<number>; win: Flow[] } | null = null;
    for (const [dst, fl] of byDst) {
      const s = [...fl].sort((a, b) => a.start - b.start);
      let lo = 0;
      const cnt = new Map<number, number>();
      for (let hi = 0; hi < s.length; hi++) {
        const p = s[hi].dport ?? -1;
        cnt.set(p, (cnt.get(p) || 0) + 1);
        while (s[hi].start - s[lo].start > scanWindow) {
          const q = s[lo].dport ?? -1;
          const c = cnt.get(q)! - 1;
          c ? cnt.set(q, c) : cnt.delete(q);
          lo++;
        }
        if (cnt.size >= scanPorts && (!best || cnt.size > best.ports.size)) best = { dst, ports: new Set(cnt.keys()), win: s.slice(lo, hi + 1) };
      }
    }
    if (best) {
      const w = best.win;
      const failed = w.filter((f) => isFailed(f)).length;
      const dur = Math.max(0.001, w[w.length - 1].start - w[0].start);
      const n = best.ports.size;
      ctx.claimed.add(src);
      out.push(make(ctx, 'rule_port_scan', {
        severity: n >= 40 ? 'critical' : 'high',
        title: `Possible vertical port scan: ${src} → ${best.dst} (${n} ports in ${round(dur, 1)}s)`,
        score: Math.min(0.98, 0.6 + n / 100 + (failed / w.length) * 0.2),
        explanation: {
          summary: `${src} contacted ${n} distinct destination ports on ${best.dst} within ${round(dur, 2)} seconds.`,
          observedFacts: [
            `${n} distinct destination ports touched on ${best.dst} (sample: ${[...best.ports].sort((a, b) => a - b).slice(0, 12).join(', ')}).`,
            `${w.length} connection attempts between ${new Date(w[0].start * 1000).toISOString()} and ${new Date(w[w.length - 1].start * 1000).toISOString()}.`,
            `${failed} of ${w.length} attempts (${Math.round((failed / w.length) * 100)}%) never completed a handshake (S0/REJ).`,
          ],
          ruleEvidence: [`Distinct destination ports in a ${scanWindow}s sliding window (${n}) ≥ threshold (${scanPorts}).`],
          interpretation: 'Broad port enumeration against a single host is consistent with reconnaissance (service discovery) prior to exploitation, or with an authorised vulnerability scan.',
          alternatives: ['Authorised vulnerability assessment or inventory scan', 'Monitoring system probing service health', 'Misconfigured client cycling through ports'],
          nextChecks: [`Confirm whether ${src} is a sanctioned scanner or IT asset`, `Check which ports on ${best.dst} answered (SYN-ACK) — those services are now known to the source`, 'Look for follow-on connections from the same source to open ports in later time windows'],
        },
        srcIp: src, dstIp: best.dst, entities: [src, best.dst],
        packetIdx: w.flatMap((f) => f.packetIdx.slice(0, 3)), flowIds: w.map((f) => f.id),
        tsRange: [w[0].start, w[w.length - 1].end],
        observed: { distinct_ports: n, attempts: w.length, failed_attempts: failed, window_seconds: round(dur, 2), sample_ports: [...best.ports].slice(0, 15) },
        thresholds: { scan_port_threshold: scanPorts, window_seconds: scanWindow },
      }));
    }
    // horizontal: one port, many hosts
    const byPort = new Map<number, Flow[]>();
    for (const f of flows) if (f.dport != null && f.dport < 49152) (byPort.get(f.dport) || byPort.set(f.dport, []).get(f.dport)!).push(f);
    for (const [port, fl] of byPort) {
      const hostsSet = new Set(fl.filter((f) => !isBroadcastOrMulticast(f.dst)).map((f) => f.dst));
      if (hostsSet.size < sweepHosts) continue;
      const s = [...fl].sort((a, b) => a.start - b.start);
      const dur = s[s.length - 1].start - s[0].start;
      if (dur > scanWindow * 20) continue;
      const failed = s.filter((f) => isFailed(f)).length;
      if (port === 53 || port === 443 || port === 80) { if (failed / s.length < 0.5) continue; }
      ctx.claimed.add(src);
      out.push(make(ctx, 'rule_port_scan', {
        severity: hostsSet.size >= 50 ? 'critical' : 'high',
        title: `Possible horizontal sweep: ${src} probing port ${port}${WELL_KNOWN[port] ? ' (' + WELL_KNOWN[port] + ')' : ''} on ${hostsSet.size} hosts`,
        score: Math.min(0.97, 0.6 + hostsSet.size / 120),
        explanation: {
          summary: `${src} connected to port ${port} on ${hostsSet.size} distinct hosts within ${round(dur, 1)}s.`,
          observedFacts: [`${hostsSet.size} distinct destination hosts on port ${port}.`, `${failed} of ${s.length} attempts failed to complete a handshake.`],
          ruleEvidence: [`Distinct destination hosts for a single port (${hostsSet.size}) ≥ threshold (${sweepHosts}).`],
          interpretation: 'Sweeping a single service across a subnet is consistent with searching for exposed services (e.g. SMB, RDP, SSH) or worm-like propagation.',
          alternatives: ['Inventory or patch-management discovery', 'Load balancer health checks', 'Client service discovery'],
          nextChecks: ['Identify the owner/role of the source', `List hosts that accepted connections on port ${port}`, 'Check for authentication attempts that followed'],
        },
        srcIp: src, entities: [src, ...[...hostsSet].slice(0, 10)],
        packetIdx: s.flatMap((f) => f.packetIdx.slice(0, 2)), flowIds: s.map((f) => f.id),
        tsRange: [s[0].start, s[s.length - 1].end],
        observed: { port, distinct_hosts: hostsSet.size, attempts: s.length, failed_attempts: failed, duration_seconds: round(dur, 2) },
        thresholds: { sweep_host_threshold: sweepHosts },
      }));
    }
  }
  return out;
}

// ── 2. Failed connections ─────────────────────────────────────────────────
function failedConnections(ctx: DetectContext): Finding[] {
  const { failedConns, failedRatio } = ctx.cfg.thresholds;
  const out: Finding[] = [];
  const bySrc = new Map<string, Flow[]>();
  for (const f of ctx.flows) if (f.transport === 'TCP') (bySrc.get(f.src) || bySrc.set(f.src, []).get(f.src)!).push(f);
  for (const [src, fl] of bySrc) {
    if (ctx.claimed.has(src)) continue;
    const failed = fl.filter((f) => isFailed(f));
    const ratio = failed.length / fl.length;
    if (failed.length < failedConns || ratio < failedRatio) continue;
    const targets = new Set(failed.map((f) => `${f.dst}:${f.dport}`));
    const rej = failed.filter((f) => f.state === 'REJ').length;
    const half = failed.filter((f) => f.state === 'HALF').length;
    out.push(make(ctx, 'rule_failed_connections', {
      severity: failed.length >= failedConns * 4 ? 'high' : 'medium',
      title: `Repeated failed TCP connections from ${src} (${failed.length} unanswered/rejected)`,
      score: Math.min(0.9, 0.5 + ratio * 0.4),
      explanation: {
        summary: `${failed.length} of ${fl.length} TCP connection attempts from ${src} never completed a handshake.`,
        observedFacts: [`${failed.length - rej - half} attempts had no response (S0), ${rej} were rejected with RST (REJ) and ${half} were left half-open.`, `Failures target ${targets.size} distinct destination:port pairs.`],
        ruleEvidence: [`Failed attempts (${failed.length}) ≥ ${failedConns} and failure ratio (${round(ratio, 2)}) ≥ ${failedRatio}.`],
        interpretation: 'Many failed handshakes can indicate probing, brute-force attempts against a filtered service, or a flood; it can equally indicate an unreachable or misconfigured service.',
        alternatives: ['Service down or firewall silently dropping', 'Client retry storm after an outage', 'Capture missing the return path (asymmetric routing)'],
        nextChecks: ['Check whether the targeted service was available at the time', 'Inspect retransmission timing (regular → automated)', 'Verify the capture sees both directions of traffic'],
      },
      srcIp: src, entities: [src, ...[...targets].slice(0, 5).map((t) => t.split(':')[0])],
      packetIdx: failed.flatMap((f) => f.packetIdx.slice(0, 2)), flowIds: failed.map((f) => f.id),
      tsRange: [failed[0].start, failed[failed.length - 1].end],
      observed: { failed_attempts: failed.length, total_attempts: fl.length, failure_ratio: round(ratio, 3), rejected: rej, unanswered: failed.length - rej, distinct_targets: targets.size },
      thresholds: { min_failed: failedConns, min_ratio: failedRatio },
    }));
  }
  return out;
}

// ── 3. ICMP sweep ──────────────────────────────────────────────────────────
function icmpSweep(ctx: DetectContext): Finding[] {
  const out: Finding[] = [];
  const bySrc = new Map<string, PacketRecord[]>();
  for (const p of ctx.packets) if (p.meta.icmp && (p.meta.icmp.type === 8 || p.meta.icmp.type === 128) && p.src) (bySrc.get(p.src) || bySrc.set(p.src, []).get(p.src)!).push(p);
  for (const [src, ps] of bySrc) {
    const dsts = new Set(ps.map((p) => p.dst));
    if (dsts.size < ctx.cfg.thresholds.icmpSweepHosts) continue;
    const replies = ctx.packets.filter((p) => p.dst === src && p.meta.icmp && (p.meta.icmp.type === 0 || p.meta.icmp.type === 129));
    out.push(make(ctx, 'rule_icmp_sweep', {
      severity: 'medium', title: `ICMP ping sweep from ${src} (${dsts.size} hosts probed)`, score: Math.min(0.9, 0.55 + dsts.size / 200),
      explanation: {
        summary: `${src} sent ICMP echo requests to ${dsts.size} distinct hosts.`,
        observedFacts: [`${ps.length} echo requests to ${dsts.size} hosts.`, `${new Set(replies.map((r) => r.src)).size} hosts replied (alive).`],
        ruleEvidence: [`Distinct ICMP echo targets (${dsts.size}) ≥ threshold (${ctx.cfg.thresholds.icmpSweepHosts}).`],
        interpretation: 'Host discovery via ping sweep often precedes port scanning.',
        alternatives: ['Network monitoring (e.g. uptime checks)', 'Inventory tooling'],
        nextChecks: ['Check whether the source is a monitoring server', 'Correlate with subsequent TCP scanning from the same source'],
      },
      srcIp: src, entities: [src], packetIdx: ps.map((p) => p.i), flowIds: [], tsRange: [ps[0].ts, ps[ps.length - 1].ts],
      observed: { echo_requests: ps.length, distinct_targets: dsts.size, live_hosts_replied: new Set(replies.map((r) => r.src)).size },
      thresholds: { icmp_sweep_hosts: ctx.cfg.thresholds.icmpSweepHosts },
    }));
  }
  return out;
}

// ── 4. DNS anomalies ───────────────────────────────────────────────────────
function dnsAnomaly(ctx: DetectContext): Finding[] {
  const t = ctx.cfg.thresholds;
  const out: Finding[] = [];
  const dns = ctx.packets.filter((p) => p.meta.dns && p.proto === 'DNS');
  if (!dns.length) return out;
  const responses = dns.filter((p) => p.meta.dns!.qr === 'response');
  const queries = dns.filter((p) => p.meta.dns!.qr === 'query');
  // NXDOMAIN per client
  const byClient = new Map<string, PacketRecord[]>();
  for (const r of responses) if (r.dst) (byClient.get(r.dst) || byClient.set(r.dst, []).get(r.dst)!).push(r);
  for (const [client, rs] of byClient) {
    if (rs.length < 5) continue;
    const nx = rs.filter((r) => r.meta.dns!.rcode === 3);
    const ratio = nx.length / rs.length;
    if (ratio < t.dnsNxRatio) continue;
    const samples = [...new Set(nx.map((r) => r.meta.dns!.query).filter(Boolean))].slice(0, 6) as string[];
    out.push(make(ctx, 'rule_dns_anomaly', {
      severity: ratio >= 0.5 ? 'high' : 'medium',
      title: `Elevated NXDOMAIN ratio for ${client} (${Math.round(ratio * 100)}% of ${rs.length} responses)`,
      score: Math.min(1, ratio * 1.5),
      explanation: {
        summary: `${nx.length} of ${rs.length} DNS responses to ${client} were NXDOMAIN (non-existent domain).`,
        observedFacts: [`NXDOMAIN responses: ${nx.length}; total responses: ${rs.length}.`, `Sample failed names: ${samples.join(', ') || 'n/a'}.`],
        ruleEvidence: [`NXDOMAIN ratio (${round(ratio, 3)}) ≥ threshold (${t.dnsNxRatio}) with ≥ 5 responses.`],
        interpretation: 'A high proportion of failed lookups is consistent with domain-generation-algorithm (DGA) malware searching for its C2, but also with typos or stale configuration.',
        alternatives: ['Misconfigured search suffix / stale DNS entries', 'Browser DNS prefetch of dead links', 'Split-horizon DNS resolving internally only'],
        nextChecks: ['Inspect the failed names for algorithmic patterns', 'Check whether any lookup eventually succeeded and what it connected to', 'Identify the process on the client making the lookups (endpoint telemetry)'],
      },
      srcIp: client, entities: [client], packetIdx: nx.map((r) => r.i), flowIds: [], tsRange: [nx[0].ts, nx[nx.length - 1].ts],
      observed: { responses: rs.length, nxdomain: nx.length, nxdomain_ratio: round(ratio, 3), sample_failed_queries: samples },
      thresholds: { nxdomain_ratio: t.dnsNxRatio },
      mitre: [META.rule_dns_anomaly.mitre[1]],
    }));
  }
  // Tunnelling: long + high-entropy labels, per client & base domain
  const groups = new Map<string, PacketRecord[]>();
  for (const q of queries) {
    const d = q.meta.dns!;
    if (!d.query || !q.src) continue;
    const long = (d.queryLen || 0) >= t.dnsLongLabel;
    const ent = (d.subdomainEntropy || 0) >= t.dnsEntropy && (d.queryLen || 0) >= 20;
    if (long || ent) {
      const k = `${q.src}|${d.baseDomain}`;
      (groups.get(k) || groups.set(k, []).get(k)!).push(q);
    }
  }
  for (const [k, qs] of groups) {
    if (qs.length < 3) continue;
    const [client, base] = k.split('|');
    const avgLen = mean(qs.map((q) => q.meta.dns!.queryLen || 0));
    const avgEnt = mean(qs.map((q) => q.meta.dns!.subdomainEntropy || 0));
    const txt = qs.filter((q) => q.meta.dns!.qtype === 'TXT' || q.meta.dns!.qtype === 'NULL').length;
    out.push(make(ctx, 'rule_dns_anomaly', {
      severity: qs.length >= 10 ? 'critical' : 'high', category: 'exfiltration',
      title: `Suspected DNS tunnelling: ${client} → *.${base} (${qs.length} long/high-entropy queries)`,
      score: Math.min(0.97, 0.7 + qs.length / 60 + (avgEnt - t.dnsEntropy) / 10),
      explanation: {
        summary: `${client} issued ${qs.length} queries under ${base} with long, random-looking subdomain labels.`,
        observedFacts: [`Average query length ${round(avgLen, 1)} chars; average subdomain entropy ${round(avgEnt, 2)} bits/char.`, `${txt} of the queries requested TXT/NULL records.`, `Example: ${qs[0].meta.dns!.query}`],
        ruleEvidence: [`Query length ≥ ${t.dnsLongLabel} or subdomain Shannon entropy ≥ ${t.dnsEntropy} on ≥ 3 queries to the same base domain.`],
        interpretation: 'Encoding data into DNS labels is a known covert-channel / exfiltration technique (e.g. iodine, dnscat2). The pattern is strongly suggestive but not conclusive.',
        alternatives: ['CDN or anti-virus reputation lookups that encode hashes in DNS', 'Telemetry SDKs using hashed subdomains', 'DKIM/SPF or service-discovery records'],
        nextChecks: [`Check reputation and registration age of ${base}`, 'Measure total bytes encoded in labels over time', 'Look for matching TXT responses carrying data back'],
      },
      srcIp: client, entities: [client, base], packetIdx: qs.map((q) => q.i), flowIds: [], tsRange: [qs[0].ts, qs[qs.length - 1].ts],
      observed: { suspicious_queries: qs.length, base_domain: base, avg_query_length: round(avgLen, 1), avg_subdomain_entropy: round(avgEnt, 3), txt_queries: txt, sample_queries: qs.slice(0, 4).map((q) => q.meta.dns!.query) },
      thresholds: { long_label: t.dnsLongLabel, entropy: t.dnsEntropy },
      mitre: [META.rule_dns_anomaly.mitre[0], M.exfilAlt, M.protoTun],
    }));
  }
  // Excessive unique subdomains (without necessarily long labels)
  const uniq = new Map<string, Set<string>>();
  const uniqPk = new Map<string, number[]>();
  for (const q of queries) {
    const d = q.meta.dns!;
    if (!d.query || !d.baseDomain || !q.src) continue;
    const k = `${q.src}|${d.baseDomain}`;
    if (groups.has(k) && groups.get(k)!.length >= 3) continue;
    (uniq.get(k) || uniq.set(k, new Set()).get(k)!).add(d.query);
    (uniqPk.get(k) || uniqPk.set(k, []).get(k)!).push(q.i);
  }
  for (const [k, names] of uniq) {
    if (names.size < t.dnsUniqueSubdomains) continue;
    const [client, base] = k.split('|');
    const idx = uniqPk.get(k)!;
    out.push(make(ctx, 'rule_dns_anomaly', {
      severity: 'medium', title: `High unique-subdomain rate: ${client} → *.${base} (${names.size} names)`, score: Math.min(0.85, 0.5 + names.size / 300),
      explanation: {
        summary: `${client} looked up ${names.size} distinct names under ${base}.`,
        observedFacts: [`${names.size} unique query names; sample: ${[...names].slice(0, 3).join(', ')}.`],
        ruleEvidence: [`Unique subdomains for one base domain (${names.size}) ≥ threshold (${t.dnsUniqueSubdomains}).`],
        interpretation: 'Many unique subdomains can reflect DNS-based data encoding or beaconing with unique identifiers.',
        alternatives: ['CDN sharding or ad-tech domains', 'Reverse-DNS lookups (in-addr.arpa) by monitoring tools'],
        nextChecks: [`Review the purpose of ${base}`, 'Check timing regularity of the queries'],
      },
      srcIp: client, entities: [client, base], packetIdx: idx, flowIds: [], tsRange: [ctx.packets[idx[0] - 1]?.ts ?? 0, ctx.packets[idx[idx.length - 1] - 1]?.ts ?? 0],
      observed: { unique_names: names.size, base_domain: base },
      thresholds: { unique_subdomains: t.dnsUniqueSubdomains },
    }));
  }
  return out;
}

// ── 5. Beacon periodicity ──────────────────────────────────────────────────
function beacon(ctx: DetectContext): Finding[] {
  const t = ctx.cfg.thresholds;
  const out: Finding[] = [];
  const groups = new Map<string, Flow[]>();
  for (const f of ctx.flows) {
    if (f.transport === 'ICMP' || isBroadcastOrMulticast(f.dst)) continue;
    if (f.dport === 53 || f.dport === 123 || f.dport === 5353 || f.dport === 1900) continue;
    const k = `${f.src}->${f.dst}:${f.dport}/${f.transport}`;
    (groups.get(k) || groups.set(k, []).get(k)!).push(f);
  }
  for (const [k, all] of groups) {
    if (all.length < t.beaconMin) continue;
    // exclude bulk transfers sharing the endpoint so they don't mask the heartbeat cadence
    const medBytes = median(all.map((f) => f.bytesFwd));
    const fl = all.filter((f) => f.bytesFwd <= medBytes * 10 + 2048);
    const excluded = all.length - fl.length;
    if (fl.length < t.beaconMin) continue;
    const ts = fl.map((f) => f.start);
    const st = timingStats(ts);
    if (st.mean < t.beaconMinInterval || st.cv > t.beaconCv) continue;
    const sizes = fl.map((f) => f.bytesFwd);
    const sizeCv = mean(sizes) > 0 ? std(sizes) / mean(sizes) : 0;
    const f0 = fl[0];
    const name = f0.sni || f0.httpHost;
    const score = Math.min(0.97, Math.max(0.6, 1 - st.cv) * (sizeCv < 0.2 ? 1 : 0.9));
    out.push(make(ctx, 'rule_beacon_periodicity', {
      severity: fl.length >= 10 && st.cv < 0.1 ? 'high' : st.cv < 0.15 ? 'high' : 'medium',
      title: `Beacon-like periodicity: ${f0.src} → ${f0.dst}:${f0.dport}${name ? ' (' + name + ')' : ''} every ~${round(st.mean, 1)}s`,
      score,
      explanation: {
        summary: `${fl.length} connections from ${f0.src} to ${f0.dst}:${f0.dport} at a near-constant interval of ${round(st.mean, 2)}s (CV ${round(st.cv, 3)}).`,
        observedFacts: [
          `Mean inter-connection interval ${round(st.mean, 3)}s, standard deviation ${round(st.std, 3)}s.`,
          `Outbound bytes per connection: mean ${Math.round(mean(sizes))} B (size CV ${round(sizeCv, 2)} — ${sizeCv < 0.2 ? 'highly consistent' : 'variable'}).`,
          name ? `Destination name observed: ${name}.` : 'No destination hostname observed (no SNI/Host header).',
          ...(excluded ? [`${excluded} bulk-transfer connection(s) to the same endpoint were excluded from the timing analysis (see transfer findings).`] : []),
        ],
        ruleEvidence: [`≥ ${t.beaconMin} connections, mean interval ≥ ${t.beaconMinInterval}s and timing CV (${round(st.cv, 3)}) ≤ ${t.beaconCv}.`],
        interpretation: 'Regular, low-jitter, similarly sized check-ins are characteristic of automated implants contacting command-and-control, but are equally typical of benign agents.',
        alternatives: ['Telemetry / monitoring agents', 'Software update or licence checks', 'Keep-alive or health-check traffic'],
        nextChecks: [`Look up the reputation/ownership of ${f0.dst}${name ? ' / ' + name : ''}`, 'Compare the JA3 fingerprint with known client software', 'Check whether the interval persists across longer captures'],
      },
      srcIp: f0.src, dstIp: f0.dst, entities: [f0.src, f0.dst, ...(name ? [name] : [])],
      packetIdx: fl.flatMap((f) => f.packetIdx.slice(0, 3)), flowIds: fl.map((f) => f.id), tsRange: [ts[0], fl[fl.length - 1].end],
      observed: { connections: fl.length, excluded_bulk_connections: excluded, mean_interval_s: st.mean, std_interval_s: st.std, timing_cv: st.cv, size_cv: round(sizeCv, 3), destination_name: name || null, ja3: f0.ja3Hash || null },
      thresholds: { min_connections: t.beaconMin, cv_threshold: t.beaconCv, min_interval_s: t.beaconMinInterval },
    }));
    void k;
  }
  return out;
}

// ── 6. Traffic burst / flood ───────────────────────────────────────────────
function trafficBurst(ctx: DetectContext): Finding[] {
  const t = ctx.cfg.thresholds;
  const out: Finding[] = [];
  const bins = new Map<number, PacketRecord[]>();
  for (const p of ctx.packets) {
    const s = Math.floor(p.ts);
    (bins.get(s) || bins.set(s, []).get(s)!).push(p);
  }
  const hot = [...bins.entries()].filter(([, ps]) => ps.length >= t.floodPps).sort((a, b) => a[0] - b[0]);
  if (!hot.length) return out;
  // merge consecutive seconds into burst windows
  const windows: Array<Array<[number, PacketRecord[]]>> = [];
  for (const h of hot) {
    const last = windows[windows.length - 1];
    if (last && h[0] - last[last.length - 1][0] <= 2) last.push(h);
    else windows.push([h]);
  }
  for (const w of windows) {
    const pk = w.flatMap(([, ps]) => ps);
    const dst = new Map<string, number>();
    let syn = 0;
    const srcs = new Set<string>();
    for (const p of pk) {
      if (p.dst) dst.set(p.dst, (dst.get(p.dst) || 0) + 1);
      if (p.src) srcs.add(p.src);
      if ((p.flagBits & 0x12) === 0x02) syn++;
    }
    const [top, topN] = [...dst.entries()].sort((a, b) => b[1] - a[1])[0] || ['unknown', 0];
    const peak = Math.max(...w.map(([, ps]) => ps.length));
    const synRatio = syn / pk.length;
    const isSyn = synRatio >= t.floodSynRatio;
    for (const s of srcs) if (pk.filter((p) => p.src === s).length > pk.length * 0.3) ctx.claimed.add(s);
    out.push(make(ctx, 'rule_traffic_burst', {
      severity: isSyn ? 'critical' : peak >= t.floodPps * 5 ? 'high' : 'medium',
      title: `${isSyn ? 'Possible SYN flood' : 'High-volume traffic burst'} targeting ${top} (peak ${peak} pkts/s)`,
      score: isSyn ? 0.95 : 0.8,
      explanation: {
        summary: `Packet rate exceeded ${t.floodPps}/s for ${w.length} second(s); ${Math.round((topN / pk.length) * 100)}% of packets targeted ${top}.`,
        observedFacts: [`Peak rate ${peak} packets/second; ${pk.length} packets in the burst window.`, `${srcs.size} distinct source address(es).`, `SYN-only packets: ${Math.round(synRatio * 100)}%.`],
        ruleEvidence: [`Packets per second (${peak}) ≥ ${t.floodPps}${isSyn ? `; SYN ratio (${round(synRatio, 2)}) ≥ ${t.floodSynRatio}` : ''}.`],
        interpretation: isSyn ? 'A SYN-dominated surge concentrated on one target is consistent with a SYN flood attempting to exhaust connection state.' : 'A volumetric surge may indicate a flood, but also bulk transfers.',
        alternatives: ['Load/stress testing', 'Backup or replication burst', 'Capture artefact (timestamp compression)'],
        nextChecks: [`Check ${top}'s service availability during the window`, 'Determine whether sources are spoofed (TTL, MAC consistency)', 'Compare against expected peak throughput'],
      },
      dstIp: top, srcIp: srcs.size === 1 ? [...srcs][0] : undefined, entities: [top, ...[...srcs].slice(0, 5)],
      packetIdx: pk.map((p) => p.i), flowIds: [], tsRange: [w[0][0], w[w.length - 1][0] + 1],
      observed: { peak_pps: peak, burst_seconds: w.length, packets_in_burst: pk.length, target_ip: top, target_share: round(topN / pk.length, 3), syn_ratio: round(synRatio, 3), distinct_sources: srcs.size },
      thresholds: { pps_threshold: t.floodPps, syn_ratio_threshold: t.floodSynRatio },
    }));
  }
  return out;
}

// ── 7. Outbound transfer ───────────────────────────────────────────────────
function outboundTransfer(ctx: DetectContext): Finding[] {
  const thr = ctx.cfg.thresholds.outboundMB * 1048576;
  const out: Finding[] = [];
  const anyInternal = ctx.flows.some((f) => isInternalIp(f.src) || isInternalIp(f.dst));
  const egress = (f: Flow) => (anyInternal ? isInternalIp(f.src) && !isInternalIp(f.dst) : true);
  const agg = new Map<string, Flow[]>();
  for (const f of ctx.flows) {
    if (!egress(f)) continue;
    (agg.get(`${f.src}|${f.dst}`) || agg.set(`${f.src}|${f.dst}`, []).get(`${f.src}|${f.dst}`)!).push(f);
  }
  for (const [k, fl] of agg) {
    const bytes = fl.reduce((s, f) => s + f.bytesFwd, 0);
    if (bytes < thr) continue;
    const [src, dst] = k.split('|');
    const dur = Math.max(...fl.map((f) => f.end)) - Math.min(...fl.map((f) => f.start));
    const inBytes = fl.reduce((s, f) => s + f.bytesBwd, 0);
    const name = fl.find((f) => f.sni || f.httpHost);
    const mb = bytes / 1048576;
    out.push(make(ctx, 'rule_outbound_transfer', {
      severity: mb >= ctx.cfg.thresholds.outboundMB * 4 ? 'high' : 'medium',
      title: `Large outbound transfer: ${src} → ${dst} (${fmtBytes(bytes)}${name ? ', ' + (name.sni || name.httpHost) : ''})`,
      score: Math.min(0.95, 0.6 + mb / (ctx.cfg.thresholds.outboundMB * 20)),
      explanation: {
        summary: `${src} sent ${fmtBytes(bytes)} to ${dst} over ${fl.length} flow(s) in ${round(dur, 1)}s.`,
        observedFacts: [`Outbound ${fmtBytes(bytes)} vs inbound ${fmtBytes(inBytes)} (ratio ${round(bytes / Math.max(1, inBytes), 1)}:1).`, `Destination port(s): ${[...new Set(fl.map((f) => f.dport))].join(', ')}; app: ${[...new Set(fl.map((f) => f.app))].join(', ')}.`, anyInternal ? `${dst} is outside private address space.` : 'No private addressing observed; direction inferred from flow initiator.'],
        ruleEvidence: [`Aggregate outbound bytes to one destination (${round(mb, 2)} MB) ≥ threshold (${ctx.cfg.thresholds.outboundMB} MB).`],
        interpretation: 'A large, upload-heavy transfer to an external endpoint can indicate data staging or exfiltration; size alone does not establish intent.',
        alternatives: ['Cloud backup or file sync', 'Video conferencing / streaming upload', 'Software artefact publishing'],
        nextChecks: [`Identify the service behind ${dst}${name ? ' (' + (name.sni || name.httpHost) + ')' : ''}`, 'Check whether the transfer occurred outside business hours', 'Correlate with endpoint file-access logs on the source'],
      },
      srcIp: src, dstIp: dst, entities: [src, dst], packetIdx: fl.flatMap((f) => f.packetIdx.slice(0, 20)), flowIds: fl.map((f) => f.id),
      tsRange: [Math.min(...fl.map((f) => f.start)), Math.max(...fl.map((f) => f.end))],
      observed: { bytes_out: bytes, mb_out: round(mb, 2), bytes_in: inBytes, flows: fl.length, duration_s: round(dur, 2) },
      thresholds: { outbound_mb: ctx.cfg.thresholds.outboundMB },
    }));
  }
  return out;
}

// ── 8. TCP flag anomalies ──────────────────────────────────────────────────
function tcpFlags(ctx: DetectContext): Finding[] {
  const hits: Array<[PacketRecord, string]> = [];
  for (const p of ctx.packets) {
    if (p.transport !== 'TCP' || p.flags === '') continue;
    const b = p.flagBits;
    if ((b & 0x03) === 0x03) hits.push([p, 'SYN+FIN']);
    else if ((b & 0x29) === 0x29) hits.push([p, 'Xmas (FIN+PSH+URG)']);
    else if ((b & 0x3f) === 0) hits.push([p, 'NULL (no flags)']);
  }
  if (!hits.length) return [];
  const bySrc = new Map<string, Array<[PacketRecord, string]>>();
  for (const h of hits) (bySrc.get(h[0].src || '?') || bySrc.set(h[0].src || '?', []).get(h[0].src || '?')!).push(h);
  const out: Finding[] = [];
  for (const [src, hs] of bySrc) {
    const kinds = [...new Set(hs.map((h) => h[1]))];
    const dsts = new Set(hs.map((h) => h[0].dst));
    out.push(make(ctx, 'rule_tcp_flag_anomaly', {
      severity: hs.length >= 10 ? 'high' : 'medium',
      title: `Invalid TCP flags from ${src}: ${kinds.join(', ')} (${hs.length} packets)`,
      score: 0.88,
      explanation: {
        summary: `${hs.length} packets from ${src} carried flag combinations that are invalid under RFC 793.`,
        observedFacts: [`Flag patterns: ${kinds.join(', ')}.`, `Targets: ${dsts.size} host(s); ports touched: ${new Set(hs.map((h) => h[0].dport)).size}.`],
        ruleEvidence: ['Packet flags matched an explicit invalid-combination policy (SYN+FIN, FIN+PSH+URG, or no flags).'],
        interpretation: 'These combinations are used by stealth scans (nmap -sX/-sN/-sF) and OS fingerprinting to evade simple filters.',
        alternatives: ['Fuzzing / protocol test harnesses', 'Faulty middleboxes rewriting flags'],
        nextChecks: [`Determine whether ${src} is an authorised scanner`, 'Check the target responses (RST vs silence) to see what was learned'],
      },
      srcIp: src, entities: [src, ...[...dsts].slice(0, 5) as string[]], packetIdx: hs.map((h) => h[0].i), flowIds: [],
      tsRange: [hs[0][0].ts, hs[hs.length - 1][0].ts],
      observed: { packets: hs.length, patterns: kinds, distinct_targets: dsts.size },
      thresholds: { policy: 'RFC 793 invalid flag combinations' },
    }));
  }
  return out;
}

// ── 9. Protocol / port mismatch ────────────────────────────────────────────
function protoPort(ctx: DetectContext): Finding[] {
  const items: Array<{ f: Flow; reason: string }> = [];
  for (const f of ctx.flows) {
    const p = f.dport;
    if (p == null) continue;
    if (f.app === 'TLS' && !TLS_PORTS.has(p) && p < 49152) items.push({ f, reason: `TLS on port ${p}` });
    else if (f.app === 'HTTP' && (p === 443)) items.push({ f, reason: 'Plaintext HTTP on port 443' });
    else if (f.app === 'HTTP' && !HTTP_PORTS.has(p) && p < 49152) items.push({ f, reason: `HTTP on non-standard port ${p}` });
    else if (f.app === 'SSH' && p !== 22 && p < 49152) items.push({ f, reason: `SSH on port ${p}` });
    else if (f.app === 'DNS' && p !== 53 && f.sport !== 53) items.push({ f, reason: `DNS-formatted payload on port ${p}` });
  }
  if (!items.length) return [];
  const byReason = new Map<string, Flow[]>();
  for (const it of items) (byReason.get(it.reason) || byReason.set(it.reason, []).get(it.reason)!).push(it.f);
  const out: Finding[] = [];
  for (const [reason, fl] of byReason) {
    const ents = [...new Set(fl.flatMap((f) => [f.src, f.dst]))];
    out.push(make(ctx, 'rule_protocol_port_mismatch', {
      severity: reason.includes('443') ? 'medium' : 'low', title: `Protocol/port mismatch: ${reason} (${fl.length} flow${fl.length > 1 ? 's' : ''})`, score: 0.6,
      explanation: {
        summary: `${reason} observed between ${ents.slice(0, 4).join(', ')}.`,
        observedFacts: fl.slice(0, 4).map((f) => `${f.src}:${f.sport} → ${f.dst}:${f.dport} identified as ${f.app} from payload signatures.`),
        ruleEvidence: ['Protocol identified from payload bytes (not port) did not match the expected port set.'],
        interpretation: 'Running a protocol on an unexpected port can be used to blend in or bypass egress filtering, but is common for internal services.',
        alternatives: ['Developer/test services', 'Reverse proxies or appliances on custom ports'],
        nextChecks: ['Identify the service owner', 'Check whether egress policy permits this port'],
      },
      entities: ents, srcIp: fl[0].src, dstIp: fl[0].dst, packetIdx: fl.flatMap((f) => f.packetIdx.slice(0, 4)), flowIds: fl.map((f) => f.id),
      tsRange: [fl[0].start, fl[fl.length - 1].end], observed: { reason, flows: fl.length }, thresholds: { expected_tls_ports: [...TLS_PORTS].slice(0, 6), expected_http_ports: [...HTTP_PORTS].slice(0, 6) },
    }));
  }
  return out;
}

// ── 10. Cleartext credentials ──────────────────────────────────────────────
function cleartext(ctx: DetectContext): Finding[] {
  const hits = ctx.packets.filter((p) => p.meta.cred);
  const telnet = ctx.flows.filter((f) => f.app === 'Telnet' && f.state !== 'S0' && f.state !== 'REJ');
  const groups = new Map<string, PacketRecord[]>();
  for (const h of hits) {
    const k = `${h.meta.cred!.protocol}|${h.src}|${h.dst}`;
    (groups.get(k) || groups.set(k, []).get(k)!).push(h);
  }
  const out: Finding[] = [];
  for (const [k, ps] of groups) {
    const [proto, src, dst] = k.split('|');
    out.push(make(ctx, 'rule_cleartext_credentials', {
      severity: 'medium', title: `Cleartext ${proto} authentication: ${src} → ${dst}`, score: 0.9,
      explanation: {
        summary: `${ps.length} packet(s) carried ${proto} authentication material in cleartext. Values were detected but not stored.`,
        observedFacts: [`Credential element(s): ${[...new Set(ps.map((p) => p.meta.cred!.kind))].join(', ')}.`, `Server: ${dst}${ps[0].dport ? ':' + ps[0].dport : ''}.`],
        ruleEvidence: ['Protocol command/header signature for authentication matched in an unencrypted session.'],
        interpretation: 'Anyone on the path can read these credentials; this is an exposure regardless of intent.',
        alternatives: ['Intentional lab / test traffic', 'Legacy device with no TLS option'],
        nextChecks: ['Rotate the exposed credentials', 'Migrate the service to an encrypted protocol (SFTP/HTTPS/IMAPS)'],
      },
      srcIp: src, dstIp: dst, entities: [src, dst], packetIdx: ps.map((p) => p.i), flowIds: [], tsRange: [ps[0].ts, ps[ps.length - 1].ts],
      observed: { protocol: proto, packets: ps.length, value_stored: false }, thresholds: { policy: 'Any cleartext authentication' },
    }));
  }
  if (telnet.length) {
    out.push(make(ctx, 'rule_cleartext_credentials', {
      severity: 'medium', title: `Telnet session(s) observed (${telnet.length})`, score: 0.75,
      explanation: {
        summary: `${telnet.length} established Telnet session(s); Telnet transmits keystrokes, including passwords, in cleartext.`,
        observedFacts: telnet.slice(0, 4).map((f) => `${f.src} → ${f.dst}:23, ${f.totalPkts} packets, ${fmtBytes(f.totalBytes)}.`),
        ruleEvidence: ['Established TCP session on port 23.'],
        interpretation: 'Interactive cleartext remote administration exposes credentials to anyone on the path.',
        alternatives: ['Network device console in an isolated management VLAN'],
        nextChecks: ['Replace Telnet with SSH', 'Review who authenticated'],
      },
      entities: [...new Set(telnet.flatMap((f) => [f.src, f.dst]))], srcIp: telnet[0].src, dstIp: telnet[0].dst,
      packetIdx: telnet.flatMap((f) => f.packetIdx.slice(0, 5)), flowIds: telnet.map((f) => f.id), tsRange: [telnet[0].start, telnet[telnet.length - 1].end],
      observed: { sessions: telnet.length }, thresholds: { policy: 'Telnet discouraged' },
    }));
  }
  return out;
}

// ── 11. ARP spoofing ───────────────────────────────────────────────────────
function arpSpoof(ctx: DetectContext): Finding[] {
  const replies = ctx.packets.filter((p) => p.meta.arp?.op === 'reply');
  const ipMacs = new Map<string, Map<string, PacketRecord[]>>();
  for (const r of replies) {
    const a = r.meta.arp!;
    if (a.senderIp === '0.0.0.0') continue;
    const m = ipMacs.get(a.senderIp) || ipMacs.set(a.senderIp, new Map()).get(a.senderIp)!;
    (m.get(a.senderMac) || m.set(a.senderMac, []).get(a.senderMac)!).push(r);
  }
  const requests = new Set(ctx.packets.filter((p) => p.meta.arp?.op === 'request').map((p) => `${p.meta.arp!.senderIp}>${p.meta.arp!.targetIp}`));
  const out: Finding[] = [];
  for (const [ip, macs] of ipMacs) {
    const unsolicited = [...macs.values()].flat().filter((r) => !requests.has(`${r.meta.arp!.targetIp}>${ip}`));
    if (macs.size < 2 && unsolicited.length < 10) continue;
    const all = [...macs.values()].flat().sort((a, b) => a.ts - b.ts);
    out.push(make(ctx, 'rule_arp_spoofing', {
      severity: macs.size >= 2 ? 'high' : 'medium',
      title: macs.size >= 2 ? `IP ${ip} claimed by ${macs.size} MAC addresses (possible ARP spoofing)` : `Unsolicited ARP reply storm for ${ip}`,
      score: macs.size >= 2 ? 0.9 : 0.7,
      explanation: {
        summary: macs.size >= 2 ? `ARP replies mapped ${ip} to ${macs.size} different hardware addresses.` : `${unsolicited.length} unsolicited ARP replies announced ${ip}.`,
        observedFacts: [...macs.entries()].map(([m, rs]) => `${m} announced ${ip} in ${rs.length} reply(ies), first at ${new Date(rs[0].ts * 1000).toISOString()}.`),
        ruleEvidence: [macs.size >= 2 ? 'More than one MAC address claimed the same IP in ARP replies.' : `Unsolicited ARP replies (${unsolicited.length}) ≥ 10.`],
        interpretation: 'Conflicting ARP announcements are the core mechanism of ARP cache poisoning, which enables adversary-in-the-middle interception.',
        alternatives: ['High-availability failover (VRRP/HSRP/CARP)', 'VM migration or NIC replacement', 'Duplicate IP misconfiguration'],
        nextChecks: [`Identify which MAC is the legitimate owner of ${ip} (switch CAM table / DHCP logs)`, 'Check for traffic redirected through the rogue MAC', 'Enable Dynamic ARP Inspection on the switch'],
      },
      entities: [ip], srcIp: ip, packetIdx: all.map((r) => r.i), flowIds: [], tsRange: [all[0].ts, all[all.length - 1].ts],
      observed: { ip, macs: [...macs.keys()], replies: all.length, unsolicited: unsolicited.length }, thresholds: { max_macs_per_ip: 1, unsolicited_threshold: 10 },
    }));
  }
  return out;
}

// ── 12. Lateral movement fan-out ───────────────────────────────────────────
function lateral(ctx: DetectContext): Finding[] {
  const out: Finding[] = [];
  const bySrc = new Map<string, Flow[]>();
  for (const f of ctx.flows) {
    if (!isInternalIp(f.src) || !isInternalIp(f.dst) || f.dport == null || !ADMIN_PORTS.has(f.dport)) continue;
    (bySrc.get(f.src) || bySrc.set(f.src, []).get(f.src)!).push(f);
  }
  for (const [src, fl] of bySrc) {
    const ok = fl.filter((f) => f.state === 'SF' || f.state === 'S1' || f.state === 'RST');
    const targets = new Set(ok.map((f) => f.dst));
    if (targets.size < ctx.cfg.thresholds.lateralHosts) continue;
    const ports = [...new Set(ok.map((f) => f.dport!))];
    out.push(make(ctx, 'rule_lateral_movement', {
      severity: targets.size >= ctx.cfg.thresholds.lateralHosts * 2 ? 'critical' : 'high',
      title: `Admin-protocol fan-out from ${src} to ${targets.size} internal hosts (${ports.map((p) => WELL_KNOWN[p] || p).join(', ')})`,
      score: Math.min(0.95, 0.65 + targets.size / 40),
      explanation: {
        summary: `${src} established sessions on administrative ports with ${targets.size} internal hosts.`,
        observedFacts: [`Established sessions: ${ok.length}; ports: ${ports.join(', ')}.`, `Targets (sample): ${[...targets].slice(0, 8).join(', ')}.`],
        ruleEvidence: [`Distinct internal hosts reached on admin ports (${targets.size}) ≥ threshold (${ctx.cfg.thresholds.lateralHosts}).`],
        interpretation: 'Rapid admin-protocol fan-out is consistent with lateral movement (e.g. PsExec over SMB, RDP hopping) or worm propagation.',
        alternatives: ['IT management / patch deployment server', 'Backup or monitoring agent', 'Domain controller replication'],
        nextChecks: [`Confirm the role of ${src}`, 'Review authentication logs on target hosts for the same time window', 'Check for new services or scheduled tasks created on targets'],
      },
      srcIp: src, entities: [src, ...[...targets].slice(0, 10)], packetIdx: ok.flatMap((f) => f.packetIdx.slice(0, 3)), flowIds: ok.map((f) => f.id),
      tsRange: [ok[0].start, ok[ok.length - 1].end], observed: { internal_targets: targets.size, sessions: ok.length, ports }, thresholds: { lateral_hosts: ctx.cfg.thresholds.lateralHosts, admin_ports: [...ADMIN_PORTS] },
    }));
  }
  return out;
}

// ── 13. Fan-in ─────────────────────────────────────────────────────────────
function fanIn(ctx: DetectContext): Finding[] {
  const out: Finding[] = [];
  for (const h of ctx.hosts) {
    if (h.fanIn < ctx.cfg.thresholds.fanInSources || isBroadcastOrMulticast(h.ip)) continue;
    const fl = ctx.flows.filter((f) => f.dst === h.ip);
    const dur = Math.max(...fl.map((f) => f.end)) - Math.min(...fl.map((f) => f.start));
    if (dur > 600) continue;
    out.push(make(ctx, 'rule_fan_in', {
      severity: 'medium', title: `High fan-in: ${h.fanIn} sources converged on ${h.ip} in ${round(dur, 0)}s`, score: Math.min(0.85, 0.5 + h.fanIn / 400),
      explanation: {
        summary: `${h.fanIn} distinct sources contacted ${h.ip} within ${round(dur, 1)}s.`,
        observedFacts: [`${fl.length} inbound flows; ${fmtBytes(h.bytesIn)} received.`],
        ruleEvidence: [`Distinct sources (${h.fanIn}) ≥ threshold (${ctx.cfg.thresholds.fanInSources}) within 10 minutes.`],
        interpretation: 'Many sources converging quickly can indicate a distributed flood — or simply a popular service.',
        alternatives: ['Public web server', 'DNS resolver / proxy', 'NAT gateway'],
        nextChecks: [`Confirm whether ${h.ip} is an expected public-facing service`, 'Check per-source volume and spoofing indicators'],
      },
      dstIp: h.ip, entities: [h.ip], packetIdx: fl.flatMap((f) => f.packetIdx.slice(0, 1)), flowIds: fl.slice(0, 40).map((f) => f.id),
      tsRange: [Math.min(...fl.map((f) => f.start)), Math.max(...fl.map((f) => f.end))], observed: { distinct_sources: h.fanIn, inbound_flows: fl.length }, thresholds: { fan_in_sources: ctx.cfg.thresholds.fanInSources },
    }));
  }
  return out;
}

// ── 14. Suspicious ports ───────────────────────────────────────────────────
function suspiciousPort(ctx: DetectContext): Finding[] {
  const groups = new Map<number, Flow[]>();
  for (const f of ctx.flows) {
    if (f.dport == null || !SUSPICIOUS_PORTS[f.dport]) continue;
    if (isFailed(f) || (f.transport === 'TCP' && f.state === 'OTH')) continue;
    if (ctx.claimed.has(f.src)) continue;
    (groups.get(f.dport) || groups.set(f.dport, []).get(f.dport)!).push(f);
  }
  const out: Finding[] = [];
  for (const [port, fl] of groups) {
    out.push(make(ctx, 'rule_suspicious_port', {
      severity: [4444, 31337, 1337, 6667].includes(port) ? 'medium' : 'low',
      title: `Session(s) to port ${port} — ${SUSPICIOUS_PORTS[port]} (${fl.length})`, score: 0.55,
      explanation: {
        summary: `${fl.length} established session(s) to port ${port}, commonly associated with ${SUSPICIOUS_PORTS[port]}.`,
        observedFacts: fl.slice(0, 4).map((f) => `${f.src} → ${f.dst}:${port}, ${f.totalPkts} pkts, ${fmtBytes(f.totalBytes)}, app=${f.app}.`),
        ruleEvidence: [`Destination port ${port} is on the known-suspicious port list and the session was answered.`],
        interpretation: 'Port reputation is weak evidence on its own but is useful corroboration alongside other signals.',
        alternatives: ['Legitimate service configured on that port'],
        nextChecks: ['Identify the listening service on the destination', 'Correlate with beaconing or transfer findings'],
      },
      srcIp: fl[0].src, dstIp: fl[0].dst, entities: [...new Set(fl.flatMap((f) => [f.src, f.dst]))], packetIdx: fl.flatMap((f) => f.packetIdx.slice(0, 4)), flowIds: fl.map((f) => f.id),
      tsRange: [fl[0].start, fl[fl.length - 1].end], observed: { port, sessions: fl.length, label: SUSPICIOUS_PORTS[port] }, thresholds: { list: 'built-in suspicious port list' },
    }));
  }
  return out;
}

// ── Statistical: host egress outlier ───────────────────────────────────────
function hostVolume(ctx: DetectContext): Finding[] {
  const hs = ctx.hosts.filter((h) => !isBroadcastOrMulticast(h.ip) && h.flowsOut > 0);
  if (hs.length < 5) return [];
  const vals = hs.map((h) => Math.log10(1 + h.bytesOut));
  const med = median(vals);
  const m = mad(vals) || 0.1;
  const out: Finding[] = [];
  hs.forEach((h, i) => {
    const z = (0.6745 * (vals[i] - med)) / m;
    if (z < ctx.cfg.thresholds.statZ || h.bytesOut < 512 * 1024) return;
    const fl = ctx.flows.filter((f) => f.src === h.ip).sort((a, b) => b.bytesFwd - a.bytesFwd);
    out.push(make(ctx, 'stat_host_volume_outlier', {
      severity: z >= ctx.cfg.thresholds.statZ * 2 ? 'medium' : 'low', title: `Egress volume outlier: ${h.ip} sent ${fmtBytes(h.bytesOut)} (robust z = ${round(z, 1)})`, score: round(z, 2),
      explanation: {
        summary: `${h.ip}'s outbound volume is ${round(z, 1)} robust standard deviations above the median host in this capture.`,
        observedFacts: [`Outbound ${fmtBytes(h.bytesOut)} across ${h.flowsOut} flows; median host sends ${fmtBytes(Math.round(Math.pow(10, med) - 1))}.`, `Top destination: ${fl[0]?.dst} (${fmtBytes(fl[0]?.bytesFwd || 0)}).`],
        ruleEvidence: [],
        modelSignal: `Robust z-score ${round(z, 2)} on log10(bytes_out) using median/MAD over ${hs.length} hosts (threshold ${ctx.cfg.thresholds.statZ}).`,
        interpretation: 'Statistically unusual egress relative to peers in this capture. Not a verdict.',
        alternatives: ['Server or backup host with naturally high egress', 'Small capture with few comparable hosts'],
        nextChecks: [`Compare ${h.ip}'s egress with historical captures (PCAP Diff)`, 'Review top destinations and their purpose'],
      },
      srcIp: h.ip, entities: [h.ip], packetIdx: fl.slice(0, 5).flatMap((f) => f.packetIdx.slice(0, 5)), flowIds: fl.slice(0, 10).map((f) => f.id),
      tsRange: [h.firstSeen, h.lastSeen], observed: { bytes_out: h.bytesOut, robust_z: round(z, 3), hosts_in_baseline: hs.length }, thresholds: { robust_z: ctx.cfg.thresholds.statZ },
    }));
  });
  return out;
}

// ── Model: Isolation Forest ────────────────────────────────────────────────
export const ML_FEATURES = ['duration', 'total_packets', 'total_bytes', 'bytes_per_packet', 'packet_rate', 'byte_rate', 'fwd_bwd_ratio', 'out_in_byte_ratio', 'inter_arrival_cv', 'pkt_size_std', 'dst_port_class'] as const;
const LOG_FEATS = new Set(['duration', 'total_packets', 'total_bytes', 'bytes_per_packet', 'packet_rate', 'byte_rate', 'fwd_bwd_ratio', 'out_in_byte_ratio', 'pkt_size_std']);

function isoForest(ctx: DetectContext): Finding[] {
  const flows = ctx.flows.filter((f) => f.transport === 'TCP' || f.transport === 'UDP');
  if (flows.length < 8) return [];
  const raw = flows.map((f) => ML_FEATURES.map((k) => Number((f.features as unknown as Record<string, number>)[k]) || 0));
  const X = raw.map((r) => r.map((v, j) => (LOG_FEATS.has(ML_FEATURES[j]) ? Math.log1p(Math.max(0, v)) : v)));
  const ml = ctx.cfg.ml;
  const res = isolationForest(X, { trees: ml.trees, sampleSize: ml.sampleSize, seed: ml.seed, contamination: ml.contamination });
  const d = ML_FEATURES.length;
  const meds = Array.from({ length: d }, (_, j) => median(X.map((r) => r[j])));
  const sds = Array.from({ length: d }, (_, j) => std(X.map((r) => r[j])) + 1e-6);
  const meanCredit = Array.from({ length: d }, (_, j) => mean(res.attributions.map((a) => a[j])) + 1e-9);
  const cands: Array<{ i: number; s: number }> = [];
  flows.forEach((f, i) => {
    f.anomalyScore = round(res.scores[i], 3);
    f.isAnomaly = res.scores[i] >= res.threshold && res.scores[i] >= ml.minScore;
    if (f.isAnomaly) cands.push({ i, s: res.scores[i] });
  });
  cands.sort((a, b) => b.s - a.s);
  const out: Finding[] = [];
  for (const { i, s } of cands.slice(0, ml.maxFindings)) {
    const f = flows[i];
    const rel = res.attributions[i].map((a, j) => (a / meanCredit[j]) * (1 + Math.abs((X[i][j] - meds[j]) / sds[j])));
    const sum = rel.reduce((a, b) => a + b, 0) || 1;
    const contributions: FeatureContribution[] = ML_FEATURES.map((name, j) => ({
      feature: name, observed: round(raw[i][j], 3), baseline: round(LOG_FEATS.has(name) ? Math.expm1(meds[j]) : meds[j], 3),
      z: round((X[i][j] - meds[j]) / sds[j], 2), share: round(rel[j] / sum, 3),
    })).sort((a, b) => b.share - a.share);
    const top = contributions.slice(0, 3);
    out.push(make(ctx, 'ml_isolation_forest_flow', {
      severity: s >= 0.8 ? 'high' : s >= 0.7 ? 'medium' : 'low',
      title: `Flow outlier (IF score ${round(s, 2)}): ${f.src}:${f.sport} → ${f.dst}:${f.dport} ${f.app}`,
      score: s,
      explanation: {
        summary: `This flow was isolated unusually quickly by the Isolation Forest relative to the ${flows.length} TCP/UDP flows in this capture.`,
        observedFacts: [`${f.totalPkts} packets, ${fmtBytes(f.totalBytes)}, duration ${f.duration}s, state ${f.state}.`, ...top.map((c) => `${c.feature}: observed ${c.observed} vs capture median ${c.baseline} (z ${c.z}).`)],
        ruleEvidence: [],
        modelSignal: `Isolation Forest score ${round(s, 3)} (0.5 ≈ typical; → 1 = easily isolated). Top-${Math.round(ml.contamination * 100)}% cut-off ${round(res.threshold, 3)}, floor ${ml.minScore}. Relative score — not a probability of maliciousness.`,
        interpretation: 'The flow\'s feature combination is rare within this capture. Use it as a pointer for review, especially if it overlaps with rule-based findings.',
        alternatives: ['Rare but legitimate application behaviour', 'Capture boundary effects (flows cut at start/end)', 'Small baseline population'],
        nextChecks: ['Open the flow and inspect its packets', 'Check whether rule-based findings involve the same hosts (corroboration)', 'Compare with a known-benign capture via PCAP Diff'],
        limitations: ['Feature attribution is a path-based approximation (DIFFI-style), not SHAP. It indicates which features the trees used to isolate this flow.', `Model: Isolation Forest, ${ml.trees} trees, ψ=${Math.min(ml.sampleSize, flows.length)}, seed ${ml.seed}.`],
      },
      srcIp: f.src, dstIp: f.dst, entities: [f.src, f.dst], packetIdx: f.packetIdx.slice(0, 25), flowIds: [f.id], tsRange: [f.start, f.end],
      observed: { anomaly_score: round(s, 3), flow_state: f.state, top_features: top.map((c) => c.feature) },
      thresholds: { contamination: ml.contamination, min_score: ml.minScore, trees: ml.trees, sample_size: ml.sampleSize, seed: ml.seed },
      contributions,
    }));
  }
  return out;
}

export function runDetectors(ctx: DetectContext): { findings: Finding[]; versions: Record<string, string> } {
  const versions: Record<string, string> = {};
  const findings: Finding[] = [];
  const add = (id: string, fn: (c: DetectContext) => Finding[]) => {
    versions[id] = META[id].version;
    findings.push(...fn(ctx));
  };
  if (ctx.cfg.runRules) {
    add('rule_port_scan', portScan);
    add('rule_traffic_burst', trafficBurst);
    add('rule_failed_connections', failedConnections);
    add('rule_icmp_sweep', icmpSweep);
    add('rule_dns_anomaly', dnsAnomaly);
    add('rule_beacon_periodicity', beacon);
    add('rule_outbound_transfer', outboundTransfer);
    add('rule_tcp_flag_anomaly', tcpFlags);
    add('rule_protocol_port_mismatch', protoPort);
    add('rule_cleartext_credentials', cleartext);
    add('rule_arp_spoofing', arpSpoof);
    add('rule_lateral_movement', lateral);
    add('rule_fan_in', fanIn);
    add('rule_suspicious_port', suspiciousPort);
  }
  if (ctx.cfg.runStatistical) add('stat_host_volume_outlier', hostVolume);
  if (ctx.cfg.runML) add('ml_isolation_forest_flow', isoForest);
  return { findings, versions };
}
