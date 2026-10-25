// PCAP Diff: compare two analysed captures (e.g. baseline vs. suspect).
import type { AnalysisResult } from '../engine/types';

export interface DiffResult {
  newHosts: Array<{ ip: string; bytes: number; internal: boolean; names: string[] }>;
  goneHosts: Array<{ ip: string; bytes: number }>;
  hostVolumeChanges: Array<{ ip: string; before: number; after: number; ratio: number }>;
  protocolShift: Array<{ proto: string; before: number; after: number; delta: number }>;
  newDomains: string[];
  newSni: string[];
  newPorts: Array<{ port: number; flows: number }>;
  newJa3: string[];
  findingDelta: Array<{ category: string; before: number; after: number }>;
  totals: { packets: [number, number]; bytes: [number, number]; flows: [number, number]; hosts: [number, number]; findings: [number, number] };
}

export function diffRuns(a: AnalysisResult, b: AnalysisResult): DiffResult {
  const hostsA = new Map(a.hosts.map((h) => [h.ip, h]));
  const hostsB = new Map(b.hosts.map((h) => [h.ip, h]));
  const vol = (h: { bytesIn: number; bytesOut: number }) => h.bytesIn + h.bytesOut;
  const newHosts = b.hosts.filter((h) => !hostsA.has(h.ip)).map((h) => ({ ip: h.ip, bytes: vol(h), internal: h.internal, names: h.hostnames })).sort((x, y) => y.bytes - x.bytes);
  const goneHosts = a.hosts.filter((h) => !hostsB.has(h.ip)).map((h) => ({ ip: h.ip, bytes: vol(h) })).sort((x, y) => y.bytes - x.bytes);
  const hostVolumeChanges = b.hosts
    .filter((h) => hostsA.has(h.ip))
    .map((h) => { const before = vol(hostsA.get(h.ip)!); const after = vol(h); return { ip: h.ip, before, after, ratio: after / Math.max(1, before) }; })
    .filter((x) => x.ratio >= 2 || x.ratio <= 0.5)
    .sort((x, y) => Math.abs(Math.log(y.ratio)) - Math.abs(Math.log(x.ratio)))
    .slice(0, 15);
  const pa = a.summary.protocols, pb = b.summary.protocols;
  const ta = a.summary.parsedPackets || 1, tb = b.summary.parsedPackets || 1;
  const protos = new Set([...Object.keys(pa), ...Object.keys(pb)]);
  const protocolShift = [...protos].map((p) => {
    const before = ((pa[p] || 0) / ta) * 100; const after = ((pb[p] || 0) / tb) * 100;
    return { proto: p, before: Math.round(before * 10) / 10, after: Math.round(after * 10) / 10, delta: Math.round((after - before) * 10) / 10 };
  }).sort((x, y) => Math.abs(y.delta) - Math.abs(x.delta));
  const setOf = <T,>(arr: T[]) => new Set(arr);
  const domainsOf = (r: AnalysisResult) => setOf(r.packets.filter((p) => p.meta.dns?.qr === 'query' && p.meta.dns.query).map((p) => p.meta.dns!.query!));
  const dA = domainsOf(a);
  const newDomains = [...domainsOf(b)].filter((d) => !dA.has(d)).slice(0, 100);
  const sA = setOf(a.flows.map((f) => f.sni).filter(Boolean) as string[]);
  const newSni = [...setOf(b.flows.map((f) => f.sni).filter(Boolean) as string[])].filter((s) => !sA.has(s));
  const jA = setOf(a.flows.map((f) => f.ja3Hash).filter(Boolean) as string[]);
  const newJa3 = [...setOf(b.flows.map((f) => f.ja3Hash).filter(Boolean) as string[])].filter((s) => !jA.has(s));
  const portsA = setOf(a.flows.map((f) => f.dport));
  const pc = new Map<number, number>();
  for (const f of b.flows) if (f.dport != null && !portsA.has(f.dport) && f.dport < 49152) pc.set(f.dport, (pc.get(f.dport) || 0) + 1);
  const newPorts = [...pc.entries()].sort((x, y) => y[1] - x[1]).slice(0, 20).map(([port, flows]) => ({ port, flows }));
  const cats = new Set([...Object.keys(a.summary.byCategory), ...Object.keys(b.summary.byCategory)]);
  const findingDelta = [...cats].map((c) => ({ category: c, before: a.summary.byCategory[c] || 0, after: b.summary.byCategory[c] || 0 }));
  const nf = (r: AnalysisResult) => r.findings.filter((f) => !f.suppressed).length;
  return {
    newHosts, goneHosts, hostVolumeChanges, protocolShift, newDomains, newSni, newPorts, newJa3, findingDelta,
    totals: {
      packets: [a.summary.parsedPackets, b.summary.parsedPackets], bytes: [a.summary.totalBytes, b.summary.totalBytes],
      flows: [a.flows.length, b.flows.length], hosts: [a.hosts.length, b.hosts.length], findings: [nf(a), nf(b)],
    },
  };
}
