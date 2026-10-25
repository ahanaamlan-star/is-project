// Bidirectional flow reconstruction (canonical 5-tuple + idle timeout + TCP
// port-reuse split), Zeek-style connection state, flow & host features.
import type { PacketRecord, Flow, HostSummary, ConnState } from './types';
import { timingStats, std, round, portClass, isInternalIp, isBroadcastOrMulticast } from './util';

const MAX_IDX = 1000;
const MAX_TS = 2000;

export function canonicalKey(src: string, dst: string, sport: number | null, dport: number | null, transport: string) {
  let a = `${src}:${sport ?? 0}`;
  let b = `${dst}:${dport ?? 0}`;
  if (a > b) [a, b] = [b, a];
  return `${transport}:${a}<->${b}`;
}

interface Building extends Flow {
  _initSrc: string;
  _initPort: number | null;
  _last: number;
  _closed: boolean;
  _synFromInit: boolean;
  _synAck: boolean;
  _rstFromResp: boolean;
  _rst: boolean;
  _fin: boolean;
  _established: boolean;
  _apps: Record<string, number>;
  _dns: Set<string>;
}

const APP_RANK: Record<string, number> = { TCP: 0, UDP: 0, ICMP: 0, ICMPv6: 0 };

export function buildFlows(packets: PacketRecord[], idleTimeout: number): Flow[] {
  const active = new Map<string, Building>();
  const done: Building[] = [];
  let seq = 0;

  const open = (p: PacketRecord, key: string): Building => {
    // If the first packet we see is a SYN-ACK, the initiator is the destination
    const reverse = p.transport === 'TCP' && (p.flagBits & 0x12) === 0x12;
    const src = reverse ? p.dst! : p.src!;
    const dst = reverse ? p.src! : p.dst!;
    const sport = reverse ? p.dport : p.sport;
    const dport = reverse ? p.sport : p.dport;
    seq++;
    const f: Building = {
      id: `F${seq}`, key, src, dst, sport, dport, transport: p.transport, app: p.transport,
      start: p.ts, end: p.ts, duration: 0, pktsFwd: 0, pktsBwd: 0, bytesFwd: 0, bytesBwd: 0, totalPkts: 0, totalBytes: 0,
      flagCounts: {}, flagsSeen: '', state: 'OTH', packetIdx: [], features: null as never,
      _ts: [], _sizes: [], _initSrc: src, _initPort: sport, _last: p.ts, _closed: false,
      _synFromInit: false, _synAck: false, _rstFromResp: false, _rst: false, _fin: false, _established: false,
      _apps: {}, _dns: new Set(),
    };
    return f;
  };

  for (const p of packets) {
    if (!p.src || !p.dst) continue;
    if (p.transport === 'ARP' || p.transport === 'OTHER') continue;
    const key = canonicalKey(p.src, p.dst, p.sport, p.dport, p.transport);
    let f = active.get(key);
    const isSyn = p.transport === 'TCP' && (p.flagBits & 0x12) === 0x02;
    if (f && (p.ts - f._last > idleTimeout || (isSyn && (f._closed || f._rst) && f.totalPkts > 1))) {
      done.push(f);
      f = undefined;
    }
    if (!f) {
      f = open(p, key);
      active.set(key, f);
    }
    const fwd = p.src === f._initSrc && p.sport === f._initPort;
    f.totalPkts++;
    f.totalBytes += p.len;
    if (fwd) { f.pktsFwd++; f.bytesFwd += p.len; } else { f.pktsBwd++; f.bytesBwd += p.len; }
    f.start = Math.min(f.start, p.ts);
    f.end = Math.max(f.end, p.ts);
    f._last = p.ts;
    if (f.packetIdx.length < MAX_IDX) f.packetIdx.push(p.i);
    if (f._ts!.length < MAX_TS) { f._ts!.push(p.ts); f._sizes!.push(p.len); }
    if (p.transport === 'TCP') {
      const b = p.flagBits;
      const inc = (k: string) => (f!.flagCounts[k] = (f!.flagCounts[k] || 0) + 1);
      if ((b & 0x12) === 0x02) { inc('SYN'); if (fwd) f._synFromInit = true; }
      if ((b & 0x12) === 0x12) { inc('SYNACK'); f._synAck = true; }
      if (b & 0x01) { inc('FIN'); f._fin = true; f._closed = true; }
      if (b & 0x04) { inc('RST'); f._rst = true; if (!fwd) f._rstFromResp = true; }
      if (b & 0x08) inc('PSH');
      if (b & 0x20) inc('URG');
      if ((b & 0x10) && f._synAck && fwd && !(b & 0x04)) f._established = true;
    }
    if (APP_RANK[p.proto] === undefined && !['IPv4', 'IPv6', 'OTHER', 'MALFORMED'].includes(p.proto)) {
      f._apps[p.proto] = (f._apps[p.proto] || 0) + 1;
    }
    if (p.meta.tls?.sni && !f.sni) f.sni = p.meta.tls.sni;
    if (p.meta.tls?.ja3Hash && !f.ja3Hash) f.ja3Hash = p.meta.tls.ja3Hash;
    if (p.meta.http?.host && !f.httpHost) f.httpHost = p.meta.http.host;
    if (p.meta.dns?.query && f._dns.size < 20) f._dns.add(p.meta.dns.query);
  }
  for (const f of active.values()) done.push(f);

  return done.map((f) => finalizeFlow(f)).sort((a, b) => a.start - b.start);
}

function connState(f: Building): ConnState {
  if (f.transport === 'UDP') return 'UDP';
  if (f.transport.startsWith('ICMP')) return 'ICMP';
  if (f.transport !== 'TCP') return 'OTH';
  if (f._synFromInit && !f._synAck && f._rstFromResp) return 'REJ';
  if (f._synFromInit && !f._synAck && f.pktsBwd === 0) return 'S0';
  if (f._synFromInit && !f._synAck && f._rst) return 'REJ';
  if (f._synAck && !f._established) return 'HALF';
  if (f._established && f._rst) return 'RST';
  if (f._established && f._fin) return 'SF';
  if (f._established) return 'S1';
  return 'OTH';
}

function finalizeFlow(f: Building): Flow {
  const duration = round(f.end - f.start, 4);
  const appEntries = Object.entries(f._apps).sort((a, b) => b[1] - a[1]);
  const app = appEntries.length ? appEntries[0][0] : f.transport;
  const t = timingStats(f._ts!);
  const d = Math.max(duration, 0.0001);
  const flow: Flow = {
    id: f.id, key: f.key, src: f.src, dst: f.dst, sport: f.sport, dport: f.dport, transport: f.transport, app,
    start: f.start, end: f.end, duration, pktsFwd: f.pktsFwd, pktsBwd: f.pktsBwd, bytesFwd: f.bytesFwd, bytesBwd: f.bytesBwd,
    totalPkts: f.totalPkts, totalBytes: f.totalBytes, flagCounts: f.flagCounts,
    flagsSeen: Object.keys(f.flagCounts).join(', ') || (f.transport === 'TCP' ? 'NONE' : '—'),
    state: connState(f), packetIdx: f.packetIdx, sni: f.sni, httpHost: f.httpHost, ja3Hash: f.ja3Hash,
    dnsQueries: f._dns.size ? [...f._dns] : undefined,
    features: {
      duration: round(d, 4),
      total_packets: f.totalPkts,
      total_bytes: f.totalBytes,
      bytes_per_packet: round(f.totalBytes / Math.max(1, f.totalPkts), 2),
      packet_rate: round(f.totalPkts / d, 2),
      byte_rate: round(f.totalBytes / d, 2),
      fwd_bwd_ratio: round(f.pktsFwd / Math.max(1, f.pktsBwd), 2),
      out_in_byte_ratio: round(f.bytesFwd / Math.max(1, f.bytesBwd), 2),
      inter_arrival_mean: t.mean,
      inter_arrival_cv: t.cv,
      pkt_size_std: round(std(f._sizes!), 2),
      syn_count: f.flagCounts.SYN || 0,
      rst_count: f.flagCounts.RST || 0,
      dst_port_class: portClass(f.dport),
    },
    _ts: f._ts,
  };
  return flow;
}

export function buildHosts(flows: Flow[], packets: PacketRecord[], dnsMap: Record<string, string[]>): HostSummary[] {
  type H = HostSummary & { _t: Set<string>; _s: Set<string>; _p: Map<number, number>; _proto: Set<string>; _mac: Set<string> };
  const hosts = new Map<string, H>();
  const get = (ip: string): H => {
    let h = hosts.get(ip);
    if (!h) {
      h = {
        ip, internal: isInternalIp(ip), hostnames: dnsMap[ip] || [], macs: [], flowsOut: 0, flowsIn: 0, fanOut: 0, fanIn: 0,
        distinctDstPorts: 0, topDstPorts: [], bytesOut: 0, bytesIn: 0, pktsOut: 0, pktsIn: 0, failedConns: 0, protocols: [],
        firstSeen: Infinity, lastSeen: 0, role: 'client',
        _t: new Set(), _s: new Set(), _p: new Map(), _proto: new Set(), _mac: new Set(),
      };
      hosts.set(ip, h);
    }
    return h;
  };
  for (const f of flows) {
    const s = get(f.src);
    const d = get(f.dst);
    s.flowsOut++;
    d.flowsIn++;
    s._t.add(f.dst);
    d._s.add(f.src);
    if (f.dport != null) s._p.set(f.dport, (s._p.get(f.dport) || 0) + 1);
    s.bytesOut += f.bytesFwd; s.bytesIn += f.bytesBwd; s.pktsOut += f.pktsFwd; s.pktsIn += f.pktsBwd;
    d.bytesIn += f.bytesFwd; d.bytesOut += f.bytesBwd; d.pktsIn += f.pktsFwd; d.pktsOut += f.pktsBwd;
    if (f.state === 'S0' || f.state === 'REJ' || f.state === 'HALF') s.failedConns++;
    s._proto.add(f.app); d._proto.add(f.app);
    s.firstSeen = Math.min(s.firstSeen, f.start); d.firstSeen = Math.min(d.firstSeen, f.start);
    s.lastSeen = Math.max(s.lastSeen, f.end); d.lastSeen = Math.max(d.lastSeen, f.end);
  }
  for (const p of packets) {
    if (p.src && p.srcMac && hosts.has(p.src) && p.transport !== 'ARP') hosts.get(p.src)!._mac.add(p.srcMac);
  }
  const out: HostSummary[] = [];
  for (const h of hosts.values()) {
    h.fanOut = h._t.size;
    h.fanIn = h._s.size;
    h.distinctDstPorts = h._p.size;
    h.topDstPorts = [...h._p.entries()].sort((a, b) => b[1] - a[1]).slice(0, 12).map(([p]) => p);
    h.protocols = [...h._proto];
    h.macs = [...h._mac].slice(0, 6);
    if (h.firstSeen === Infinity) h.firstSeen = 0;
    if (isBroadcastOrMulticast(h.ip)) h.role = 'broadcast/multicast';
    else if (h.distinctDstPorts >= 12 && h.failedConns >= 8) h.role = 'scanner-like';
    else if (h.fanIn >= 3 && h.flowsIn > h.flowsOut * 2) h.role = 'server';
    else if (h.fanOut >= 10) h.role = 'high fan-out client';
    else if (h.flowsIn > 0 && h.flowsOut === 0) h.role = 'service endpoint';
    const { _t, _s, _p, _proto, _mac, ...clean } = h;
    out.push(clean);
  }
  return out.sort((a, b) => b.bytesOut + b.bytesIn - (a.bytesOut + a.bytesIn));
}

export function buildDnsMap(packets: PacketRecord[]): Record<string, string[]> {
  const map: Record<string, Set<string>> = {};
  for (const p of packets) {
    const d = p.meta.dns;
    if (d?.qr === 'response' && d.query && d.answers) {
      for (const a of d.answers) {
        if (a.startsWith('CNAME')) continue;
        (map[a] ||= new Set()).add(d.query);
      }
    }
    if (p.meta.tls?.sni && p.dst) (map[p.dst] ||= new Set()).add(p.meta.tls.sni);
    if (p.meta.http?.host && p.meta.http.kind === 'request' && p.dst) (map[p.dst] ||= new Set()).add(p.meta.http.host.split(':')[0]);
  }
  const out: Record<string, string[]> = {};
  for (const [k, v] of Object.entries(map)) out[k] = [...v].slice(0, 5);
  return out;
}
