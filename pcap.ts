// ───────────────────────────────────────────────────────────────────────────
// PCAP / PCAPNG reader + protocol dissector (Ethernet, VLAN, SLL/SLL2, Null,
// raw IP, ARP, IPv4, IPv6 + ext headers, TCP, UDP, ICMP/ICMPv6, DNS, TLS
// ClientHello/ServerHello (SNI, ALPN, JA3/JA3S), HTTP, FTP/POP3/IMAP/SMTP/
// Telnet credential *presence*, SSH banners, QUIC).
// Treats every capture as untrusted input: all reads are bounds-checked.
// ───────────────────────────────────────────────────────────────────────────
import type { PacketRecord, PacketMeta, DnsMeta, TlsMeta, HttpMeta } from './types';
import { shannonEntropy, baseDomain, md5 } from './util';

export interface ParseOutput {
  format: 'pcap' | 'pcapng';
  linktypes: Set<number>;
  packets: PacketRecord[];
  totalFrames: number;
  truncated: number;
  warnings: string[];
}

export const LINKTYPE_NAMES: Record<number, string> = {
  0: 'NULL/Loopback', 1: 'Ethernet', 12: 'Raw IP', 14: 'Raw IP', 101: 'Raw IP', 105: 'IEEE 802.11', 108: 'OpenBSD Loopback',
  113: 'Linux SLL', 127: '802.11 Radiotap', 228: 'Raw IPv4', 229: 'Raw IPv6', 276: 'Linux SLL2',
};

export class CaptureFormatError extends Error {}

export function detectFormat(buf: ArrayBuffer): 'pcap' | 'pcapng' | null {
  if (buf.byteLength < 24) return null;
  const v = new DataView(buf);
  const m = v.getUint32(0, false);
  if ([0xa1b2c3d4, 0xd4c3b2a1, 0xa1b23c4d, 0x4d3cb2a1].includes(m)) return 'pcap';
  if (m === 0x0a0d0d0a) return 'pcapng';
  return null;
}

type Frame = { ts: number; caplen: number; len: number; off: number; linktype: number };

function* readPcap(buf: ArrayBuffer, warnings: string[]): Generator<Frame> {
  const v = new DataView(buf);
  const magic = v.getUint32(0, false);
  const le = magic === 0xd4c3b2a1 || magic === 0x4d3cb2a1;
  const nano = magic === 0xa1b23c4d || magic === 0x4d3cb2a1;
  const linktype = v.getUint32(20, le) & 0x0fffffff;
  const snaplen = v.getUint32(16, le);
  let p = 24;
  while (p + 16 <= buf.byteLength) {
    const sec = v.getUint32(p, le);
    const frac = v.getUint32(p + 4, le);
    const caplen = v.getUint32(p + 8, le);
    const len = v.getUint32(p + 12, le);
    p += 16;
    if (caplen > 262144 * 4 || (snaplen > 0 && caplen > Math.max(snaplen, 262144))) {
      warnings.push(`Corrupt record header at byte offset ${p - 16} (caplen=${caplen}). Remaining data ignored.`);
      return;
    }
    if (p + caplen > buf.byteLength) {
      warnings.push(`Capture ends mid-packet at byte offset ${p - 16}; the final record is truncated and was skipped.`);
      return;
    }
    yield { ts: sec + frac / (nano ? 1e9 : 1e6), caplen, len, off: p, linktype };
    p += caplen;
  }
}

function* readPcapng(buf: ArrayBuffer, warnings: string[]): Generator<Frame> {
  const v = new DataView(buf);
  let p = 0;
  let le = true;
  let ifaces: Array<{ linktype: number; tsres: number; tsoffset: number }> = [];
  while (p + 12 <= buf.byteLength) {
    let type = v.getUint32(p, le);
    if (v.getUint32(p, false) === 0x0a0d0d0a) {
      // Section Header Block: determine byte order
      const bom = v.getUint32(p + 8, true);
      le = bom === 0x1a2b3c4d;
      if (!le && v.getUint32(p + 8, false) !== 0x1a2b3c4d) {
        warnings.push('Invalid PCAPNG byte-order magic; stopping.');
        return;
      }
      type = 0x0a0d0d0a;
      ifaces = [];
    }
    const blen = v.getUint32(p + 4, le);
    if (blen < 12 || p + blen > buf.byteLength || blen % 4 !== 0) {
      warnings.push(`Corrupt PCAPNG block at byte offset ${p} (length ${blen}). Remaining data ignored.`);
      return;
    }
    const body = p + 8;
    if (type === 0x00000001) {
      const linktype = v.getUint16(body, le);
      let tsres = 1e-6;
      let tsoffset = 0;
      let o = body + 8;
      const end = p + blen - 4;
      while (o + 4 <= end) {
        const code = v.getUint16(o, le);
        const olen = v.getUint16(o + 2, le);
        if (code === 0) break;
        if (code === 9 && olen >= 1) {
          const r = v.getUint8(o + 4);
          tsres = r & 0x80 ? Math.pow(2, -(r & 0x7f)) : Math.pow(10, -r);
        }
        if (code === 14 && olen >= 8) {
          tsoffset = Number(le ? v.getBigInt64(o + 4, true) : v.getBigInt64(o + 4, false));
        }
        o += 4 + Math.ceil(olen / 4) * 4;
      }
      ifaces.push({ linktype, tsres, tsoffset });
    } else if (type === 0x00000006 || type === 0x00000002) {
      const ifid = type === 6 ? v.getUint32(body, le) : v.getUint16(body, le);
      const hi = v.getUint32(body + 4, le);
      const lo = v.getUint32(body + 8, le);
      const caplen = v.getUint32(body + 12, le);
      const len = v.getUint32(body + 16, le);
      const off = body + 20;
      const iface = ifaces[ifid] || { linktype: 1, tsres: 1e-6, tsoffset: 0 };
      if (off + caplen <= p + blen) {
        const ts = (hi * 4294967296 + lo) * iface.tsres + iface.tsoffset;
        yield { ts, caplen, len, off, linktype: iface.linktype };
      } else warnings.push(`PCAPNG packet block at offset ${p} declares more data than it contains; skipped.`);
    } else if (type === 0x00000003) {
      const len = v.getUint32(body, le);
      const iface = ifaces[0] || { linktype: 1, tsres: 1e-6, tsoffset: 0 };
      const caplen = Math.min(len, blen - 16);
      yield { ts: 0, caplen, len, off: body + 4, linktype: iface.linktype };
    }
    p += blen;
  }
}

// ── helpers ────────────────────────────────────────────────────────────────
const hex2 = (n: number) => n.toString(16).padStart(2, '0');
function mac(b: Uint8Array, o: number) {
  if (o + 6 > b.length) return undefined;
  return [0, 1, 2, 3, 4, 5].map((i) => hex2(b[o + i])).join(':');
}
function ipv4(b: Uint8Array, o: number) {
  return `${b[o]}.${b[o + 1]}.${b[o + 2]}.${b[o + 3]}`;
}
function ipv6(b: Uint8Array, o: number) {
  const g: string[] = [];
  for (let i = 0; i < 16; i += 2) g.push(((b[o + i] << 8) | b[o + i + 1]).toString(16));
  // compress the longest run of zero groups
  let bestS = -1, bestL = 0;
  for (let i = 0; i < 8; ) {
    if (g[i] === '0') {
      let j = i;
      while (j < 8 && g[j] === '0') j++;
      if (j - i > bestL) { bestS = i; bestL = j - i; }
      i = j;
    } else i++;
  }
  if (bestL > 1) {
    const left = g.slice(0, bestS).join(':');
    const right = g.slice(bestS + bestL).join(':');
    return `${left}::${right}`;
  }
  return g.join(':');
}
const u16 = (b: Uint8Array, o: number) => (b[o] << 8) | b[o + 1];
const u32 = (b: Uint8Array, o: number) => ((b[o] << 24) >>> 0) + (b[o + 1] << 16) + (b[o + 2] << 8) + b[o + 3];
function ascii(b: Uint8Array, o: number, n: number) {
  let s = '';
  const end = Math.min(b.length, o + n);
  for (let i = o; i < end; i++) s += String.fromCharCode(b[i]);
  return s;
}

const FLAG_NAMES: Array<[number, string]> = [[2, 'SYN'], [16, 'ACK'], [1, 'FIN'], [4, 'RST'], [8, 'PSH'], [32, 'URG'], [64, 'ECE'], [128, 'CWR']];
export function flagString(bits: number) {
  const out = FLAG_NAMES.filter(([m]) => bits & m).map(([, n]) => n);
  return out.length ? out.join('+') : 'NONE';
}

const ICMP_LABELS: Record<number, string> = { 0: 'Echo reply', 3: 'Destination unreachable', 5: 'Redirect', 8: 'Echo request', 11: 'Time exceeded' };
const ICMP6_LABELS: Record<number, string> = { 1: 'Destination unreachable', 3: 'Time exceeded', 128: 'Echo request', 129: 'Echo reply', 133: 'Router solicitation', 134: 'Router advertisement', 135: 'Neighbor solicitation', 136: 'Neighbor advertisement' };
const QTYPES: Record<number, string> = { 1: 'A', 2: 'NS', 5: 'CNAME', 6: 'SOA', 12: 'PTR', 15: 'MX', 16: 'TXT', 28: 'AAAA', 33: 'SRV', 65: 'HTTPS', 255: 'ANY' };
const RCODES: Record<number, string> = { 0: 'NOERROR', 1: 'FORMERR', 2: 'SERVFAIL', 3: 'NXDOMAIN', 4: 'NOTIMP', 5: 'REFUSED' };
const TLS_VERSIONS: Record<number, string> = { 0x0300: 'SSL 3.0', 0x0301: 'TLS 1.0', 0x0302: 'TLS 1.1', 0x0303: 'TLS 1.2', 0x0304: 'TLS 1.3' };
const isGrease = (v: number) => (v & 0x0f0f) === 0x0a0a && (v >> 8) === (v & 0xff);

// ── DNS ────────────────────────────────────────────────────────────────────
function readName(b: Uint8Array, start: number, base: number): { name: string; next: number } | null {
  const labels: string[] = [];
  let o = start;
  let jumped = false;
  let next = -1;
  let guard = 0;
  while (o < b.length && guard++ < 128) {
    const l = b[o];
    if (l === 0) { o += 1; break; }
    if ((l & 0xc0) === 0xc0) {
      if (o + 1 >= b.length) return null;
      const ptr = ((l & 0x3f) << 8) | b[o + 1];
      if (!jumped) next = o + 2;
      jumped = true;
      o = base + ptr;
      continue;
    }
    if (o + 1 + l > b.length) return null;
    labels.push(ascii(b, o + 1, l));
    o += 1 + l;
  }
  return { name: labels.join('.'), next: jumped ? next : o };
}

function parseDns(b: Uint8Array, o: number): DnsMeta | null {
  if (o + 12 > b.length) return null;
  const id = u16(b, o);
  const fl = u16(b, o + 2);
  const qd = u16(b, o + 4);
  const an = u16(b, o + 6);
  if (qd > 32 || an > 256) return null;
  const rcode = fl & 0xf;
  const meta: DnsMeta = { id, qr: fl & 0x8000 ? 'response' : 'query', rcode, rcodeName: RCODES[rcode] || `RCODE_${rcode}`, ancount: an };
  let p = o + 12;
  if (qd > 0) {
    const n = readName(b, p, o);
    if (!n) return meta;
    p = n.next;
    const q = n.name.replace(/\.$/, '');
    meta.query = q;
    meta.queryLen = q.length;
    meta.entropy = shannonEntropy(q);
    meta.baseDomain = baseDomain(q);
    const sub = q.length > meta.baseDomain.length ? q.slice(0, q.length - meta.baseDomain.length - 1) : '';
    meta.subdomainEntropy = shannonEntropy(sub.replace(/\./g, ''));
    if (p + 4 <= b.length) meta.qtype = QTYPES[u16(b, p)] || `TYPE${u16(b, p)}`;
    p += 4;
    for (let i = 1; i < qd; i++) {
      const nn = readName(b, p, o);
      if (!nn) return meta;
      p = nn.next + 4;
    }
  }
  if (meta.qr === 'response' && an > 0) {
    const answers: string[] = [];
    for (let i = 0; i < an && answers.length < 8; i++) {
      const n = readName(b, p, o);
      if (!n || n.next + 10 > b.length) break;
      p = n.next;
      const t = u16(b, p);
      const rdlen = u16(b, p + 8);
      const rd = p + 10;
      if (rd + rdlen > b.length) break;
      if (t === 1 && rdlen === 4) answers.push(ipv4(b, rd));
      else if (t === 28 && rdlen === 16) answers.push(ipv6(b, rd));
      else if (t === 5) {
        const c = readName(b, rd, o);
        if (c) answers.push(`CNAME ${c.name}`);
      }
      p = rd + rdlen;
    }
    meta.answers = answers;
  }
  return meta;
}

// ── TLS ────────────────────────────────────────────────────────────────────
function parseTls(b: Uint8Array, o: number): TlsMeta | null {
  if (o + 6 > b.length) return null;
  if (b[o] !== 0x16 && b[o] !== 0x17 && b[o] !== 0x15 && b[o] !== 0x14) return null;
  if (b[o + 1] !== 0x03 || b[o + 2] > 0x04) return null;
  if (b[o] !== 0x16) return { type: 'Record', version: TLS_VERSIONS[u16(b, o + 1)] };
  const hs = o + 5;
  if (hs + 4 > b.length) return { type: 'Record' };
  const hsType = b[hs];
  let p = hs + 4;
  if (hsType === 1) {
    if (p + 34 > b.length) return { type: 'ClientHello' };
    const ver = u16(b, p);
    p += 34;
    const sidLen = b[p];
    p += 1 + sidLen;
    if (p + 2 > b.length) return { type: 'ClientHello', version: TLS_VERSIONS[ver] };
    const csLen = u16(b, p);
    p += 2;
    const ciphers: number[] = [];
    for (let i = 0; i < csLen && p + i + 1 < b.length; i += 2) {
      const c = u16(b, p + i);
      if (!isGrease(c)) ciphers.push(c);
    }
    p += csLen;
    if (p >= b.length) return { type: 'ClientHello', version: TLS_VERSIONS[ver] };
    p += 1 + b[p];
    const meta: TlsMeta = { type: 'ClientHello', version: TLS_VERSIONS[ver] };
    const exts: number[] = [];
    const curves: number[] = [];
    const pf: number[] = [];
    let realVer = ver;
    if (p + 2 <= b.length) {
      const extEnd = Math.min(b.length, p + 2 + u16(b, p));
      p += 2;
      while (p + 4 <= extEnd) {
        const et = u16(b, p);
        const el = u16(b, p + 2);
        const ed = p + 4;
        if (!isGrease(et)) exts.push(et);
        if (et === 0 && ed + 5 <= b.length) {
          const nl = u16(b, ed + 3);
          meta.sni = ascii(b, ed + 5, nl);
        } else if (et === 10 && ed + 2 <= b.length) {
          const l = u16(b, ed);
          for (let i = 0; i < l; i += 2) {
            if (ed + 2 + i + 1 >= b.length) break;
            const c = u16(b, ed + 2 + i);
            if (!isGrease(c)) curves.push(c);
          }
        } else if (et === 11 && ed < b.length) {
          const l = b[ed];
          for (let i = 0; i < l && ed + 1 + i < b.length; i++) pf.push(b[ed + 1 + i]);
        } else if (et === 16 && ed + 2 <= b.length) {
          const l = u16(b, ed);
          const alpn: string[] = [];
          let q = ed + 2;
          while (q < ed + 2 + l && q < b.length) {
            const sl = b[q];
            alpn.push(ascii(b, q + 1, sl));
            q += 1 + sl;
          }
          meta.alpn = alpn;
        } else if (et === 43 && ed < b.length) {
          const l = b[ed];
          for (let i = 0; i < l; i += 2) {
            if (ed + 1 + i + 1 >= b.length) break;
            const sv = u16(b, ed + 1 + i);
            if (!isGrease(sv) && sv > realVer) realVer = sv;
          }
        }
        p = ed + el;
      }
    }
    meta.version = TLS_VERSIONS[realVer] || meta.version;
    meta.ja3 = `${ver},${ciphers.join('-')},${exts.join('-')},${curves.join('-')},${pf.join('-')}`;
    meta.ja3Hash = md5(meta.ja3);
    return meta;
  }
  if (hsType === 2) {
    if (p + 35 > b.length) return { type: 'ServerHello' };
    const ver = u16(b, p);
    p += 34;
    p += 1 + b[p];
    if (p + 3 > b.length) return { type: 'ServerHello', version: TLS_VERSIONS[ver] };
    const cipher = u16(b, p);
    p += 3;
    const exts: number[] = [];
    let realVer = ver;
    if (p + 2 <= b.length) {
      const extEnd = Math.min(b.length, p + 2 + u16(b, p));
      p += 2;
      while (p + 4 <= extEnd) {
        const et = u16(b, p);
        const el = u16(b, p + 2);
        exts.push(et);
        if (et === 43 && el === 2 && p + 6 <= b.length) realVer = u16(b, p + 4);
        p += 4 + el;
      }
    }
    const ja3s = `${ver},${cipher},${exts.join('-')}`;
    return { type: 'ServerHello', version: TLS_VERSIONS[realVer] || TLS_VERSIONS[ver], cipher: '0x' + cipher.toString(16).padStart(4, '0'), ja3s, ja3sHash: md5(ja3s) };
  }
  return { type: 'Record', version: TLS_VERSIONS[u16(b, o + 1)] };
}

// ── HTTP + cleartext protocol heuristics ───────────────────────────────────
const HTTP_METHODS = ['GET ', 'POST ', 'PUT ', 'DELETE ', 'HEAD ', 'OPTIONS ', 'PATCH ', 'CONNECT '];
function parseHttp(b: Uint8Array, o: number): HttpMeta | null {
  const head = ascii(b, o, 8);
  const isReq = HTTP_METHODS.some((m) => head.startsWith(m));
  const isResp = head.startsWith('HTTP/1.');
  if (!isReq && !isResp) return null;
  const text = ascii(b, o, Math.min(1500, b.length - o));
  const lines = text.split('\r\n');
  const first = lines[0].slice(0, 200);
  const meta: HttpMeta = { kind: isReq ? 'request' : 'response', firstLine: first };
  if (isReq) {
    const [method, uri] = first.split(' ');
    meta.method = method;
    meta.uri = uri?.slice(0, 160);
  } else meta.status = parseInt(first.split(' ')[1], 10) || undefined;
  for (const l of lines.slice(1, 25)) {
    const ll = l.toLowerCase();
    if (ll.startsWith('host:')) meta.host = l.slice(5).trim().slice(0, 120);
    else if (ll.startsWith('user-agent:')) meta.userAgent = l.slice(11).trim().slice(0, 160);
    else if (ll.startsWith('authorization: basic')) meta.hasBasicAuth = true;
  }
  return meta;
}

function cleartextCred(b: Uint8Array, o: number, sport: number, dport: number): { protocol: string; kind: string } | null {
  const s = ascii(b, o, 16).toUpperCase();
  if (dport === 21 || sport === 21) {
    if (s.startsWith('USER ')) return { protocol: 'FTP', kind: 'username' };
    if (s.startsWith('PASS ')) return { protocol: 'FTP', kind: 'password' };
  }
  if (dport === 110 && (s.startsWith('USER ') || s.startsWith('PASS '))) return { protocol: 'POP3', kind: s.startsWith('PASS') ? 'password' : 'username' };
  if (dport === 143 && / LOGIN /.test(s)) return { protocol: 'IMAP', kind: 'login' };
  if ((dport === 25 || dport === 587) && s.startsWith('AUTH ')) return { protocol: 'SMTP', kind: 'auth' };
  return null;
}

// ── main dissector ─────────────────────────────────────────────────────────
function dissect(b: Uint8Array, linktype: number): Omit<PacketRecord, 'i' | 'ts' | 'len' | 'caplen' | 'off' | 'info'> {
  const rec: Omit<PacketRecord, 'i' | 'ts' | 'len' | 'caplen' | 'off' | 'info'> = {
    src: null, dst: null, sport: null, dport: null, transport: 'OTHER', proto: 'OTHER', flags: '', flagBits: 0, meta: {},
  };
  let o = 0;
  let etype = -1;
  if (linktype === 1) {
    if (b.length < 14) return rec;
    rec.dstMac = mac(b, 0);
    rec.srcMac = mac(b, 6);
    etype = u16(b, 12);
    o = 14;
    let guard = 0;
    while ((etype === 0x8100 || etype === 0x88a8 || etype === 0x9100) && o + 4 <= b.length && guard++ < 4) {
      etype = u16(b, o + 2);
      o += 4;
    }
  } else if (linktype === 113) {
    if (b.length < 16) return rec;
    etype = u16(b, 14);
    if (u16(b, 4) === 6) rec.srcMac = mac(b, 6);
    o = 16;
  } else if (linktype === 276) {
    if (b.length < 20) return rec;
    etype = u16(b, 0);
    rec.srcMac = mac(b, 12);
    o = 20;
  } else if (linktype === 0 || linktype === 108) {
    if (b.length < 4) return rec;
    const famLE = b[0] | (b[1] << 8);
    const famBE = u16(b, 2);
    const fam = famLE < 256 && famLE > 0 ? famLE : famBE;
    etype = fam === 2 ? 0x0800 : [24, 28, 30].includes(fam) ? 0x86dd : -1;
    o = 4;
  } else if (linktype === 101 || linktype === 12 || linktype === 14 || linktype === 228 || linktype === 229) {
    if (!b.length) return rec;
    etype = b[0] >> 4 === 6 ? 0x86dd : 0x0800;
  } else {
    rec.proto = 'UNSUPPORTED_LINK';
    return rec;
  }

  let l4 = -1;
  let l4off = 0;
  let fragmentNonFirst = false;
  if (etype === 0x0806) {
    rec.transport = 'ARP';
    rec.proto = 'ARP';
    if (o + 28 <= b.length) {
      const op = u16(b, o + 6);
      const smac = mac(b, o + 8)!;
      const sip = ipv4(b, o + 14);
      const tmac = mac(b, o + 18)!;
      const tip = ipv4(b, o + 24);
      rec.src = sip;
      rec.dst = tip;
      rec.meta.arp = { op: op === 2 ? 'reply' : 'request', senderMac: smac, senderIp: sip, targetMac: tmac, targetIp: tip };
    }
    return rec;
  } else if (etype === 0x0800) {
    if (o + 20 > b.length) return rec;
    const ihl = (b[o] & 0x0f) * 4;
    rec.transport = 'IPv4';
    rec.proto = 'IPv4';
    rec.ttl = b[o + 8];
    l4 = b[o + 9];
    rec.src = ipv4(b, o + 12);
    rec.dst = ipv4(b, o + 16);
    const fragOff = u16(b, o + 6) & 0x1fff;
    const mf = (u16(b, o + 6) & 0x2000) !== 0;
    if (fragOff > 0) fragmentNonFirst = true;
    if (fragOff > 0 || mf) rec.meta.fragment = true;
    l4off = o + Math.max(20, ihl);
  } else if (etype === 0x86dd) {
    if (o + 40 > b.length) return rec;
    rec.transport = 'IPv6';
    rec.proto = 'IPv6';
    rec.ttl = b[o + 7];
    rec.src = ipv6(b, o + 8);
    rec.dst = ipv6(b, o + 24);
    let nh = b[o + 6];
    let p = o + 40;
    let guard = 0;
    while ([0, 43, 60, 44, 51].includes(nh) && p + 8 <= b.length && guard++ < 8) {
      if (nh === 44) {
        rec.meta.fragment = true;
        if ((u16(b, p + 2) & 0xfff8) !== 0) fragmentNonFirst = true;
        nh = b[p];
        p += 8;
      } else if (nh === 51) {
        const next = b[p];
        p += (b[p + 1] + 2) * 4;
        nh = next;
      } else {
        const next = b[p];
        p += (b[p + 1] + 1) * 8;
        nh = next;
      }
    }
    l4 = nh;
    l4off = p;
  } else {
    rec.proto = etype === 0x88cc ? 'LLDP' : etype === 0x8863 || etype === 0x8864 ? 'PPPoE' : etype > 0 ? `ETH_0x${etype.toString(16)}` : 'OTHER';
    return rec;
  }

  if (fragmentNonFirst) {
    rec.proto = rec.transport + '-FRAG';
    return rec;
  }

  if (l4 === 6) {
    rec.transport = 'TCP';
    rec.proto = 'TCP';
    if (l4off + 20 > b.length) return rec;
    rec.sport = u16(b, l4off);
    rec.dport = u16(b, l4off + 2);
    const doff = (b[l4off + 12] >> 4) * 4;
    rec.flagBits = b[l4off + 13];
    rec.flags = flagString(rec.flagBits);
    const pay = l4off + Math.max(20, doff);
    const plen = Math.max(0, b.length - pay);
    rec.meta.payloadLen = plen;
    if (plen > 0) appLayerTcp(b, pay, rec);
  } else if (l4 === 17) {
    rec.transport = 'UDP';
    rec.proto = 'UDP';
    if (l4off + 8 > b.length) return rec;
    rec.sport = u16(b, l4off);
    rec.dport = u16(b, l4off + 2);
    const pay = l4off + 8;
    rec.meta.payloadLen = Math.max(0, b.length - pay);
    const ports = [rec.sport, rec.dport];
    if (ports.includes(53) || ports.includes(5353) || ports.includes(5355)) {
      const d = parseDns(b, pay);
      if (d) {
        rec.meta.dns = d;
        rec.proto = ports.includes(5353) ? 'mDNS' : ports.includes(5355) ? 'LLMNR' : 'DNS';
      }
    } else if (ports.includes(443) && pay < b.length && (b[pay] & 0x80) !== 0) {
      rec.proto = 'QUIC';
      rec.meta.quic = true;
    } else if (ports.includes(123)) rec.proto = 'NTP';
    else if (ports.includes(67) || ports.includes(68)) rec.proto = 'DHCP';
    else if (ports.includes(161) || ports.includes(162)) rec.proto = 'SNMP';
    else if (ports.includes(1900)) rec.proto = 'SSDP';
    else if (ports.includes(137) || ports.includes(138)) rec.proto = 'NetBIOS';
    else if (ports.includes(514)) rec.proto = 'Syslog';
    else if (ports.includes(69)) rec.proto = 'TFTP';
  } else if (l4 === 1 || l4 === 58) {
    rec.transport = l4 === 1 ? 'ICMP' : 'ICMPv6';
    rec.proto = rec.transport;
    if (l4off + 2 <= b.length) {
      const t = b[l4off];
      const c = b[l4off + 1];
      rec.meta.icmp = { type: t, code: c, label: (l4 === 1 ? ICMP_LABELS[t] : ICMP6_LABELS[t]) || `type ${t}` };
    }
  } else if (l4 === 2) {
    rec.proto = 'IGMP';
  } else if (l4 === 47) rec.proto = 'GRE';
  else if (l4 === 50) rec.proto = 'ESP';
  else if (l4 === 132) rec.proto = 'SCTP';
  return rec;
}

function appLayerTcp(b: Uint8Array, pay: number, rec: Omit<PacketRecord, 'i' | 'ts' | 'len' | 'caplen' | 'off' | 'info'>) {
  const sp = rec.sport!, dp = rec.dport!;
  const tls = parseTls(b, pay);
  if (tls) {
    rec.proto = 'TLS';
    rec.meta.tls = tls;
    return;
  }
  const http = parseHttp(b, pay);
  if (http) {
    rec.proto = 'HTTP';
    rec.meta.http = http;
    if (http.hasBasicAuth) rec.meta.cred = { protocol: 'HTTP', kind: 'Basic authorization header' };
    return;
  }
  if (ascii(b, pay, 4) === 'SSH-') {
    rec.proto = 'SSH';
    rec.meta.ssh = ascii(b, pay, 64).split('\r')[0].split('\n')[0];
    return;
  }
  if (sp === 53 || dp === 53) {
    const d = parseDns(b, pay + 2);
    if (d) { rec.proto = 'DNS'; rec.meta.dns = d; return; }
  }
  const cred = cleartextCred(b, pay, sp, dp);
  if (cred) {
    rec.proto = cred.protocol;
    rec.meta.cred = cred;
    return;
  }
  if (dp === 23 || sp === 23) { rec.proto = 'Telnet'; return; }
  if (dp === 21 || sp === 21) { rec.proto = 'FTP'; return; }
  if (dp === 445 || sp === 445) { rec.proto = 'SMB'; return; }
  if (dp === 3389 || sp === 3389) { rec.proto = 'RDP'; return; }
  if (dp === 25 || sp === 25 || dp === 587) { rec.proto = 'SMTP'; return; }
}

function summarize(r: Omit<PacketRecord, 'info'>): string {
  const ep = (ip: string | null, port: number | null) => (ip ? (port != null ? (ip.includes(':') ? `[${ip}]:${port}` : `${ip}:${port}`) : ip) : '*');
  const m = r.meta;
  if (m.arp) return m.arp.op === 'request' ? `ARP Who has ${m.arp.targetIp}? Tell ${m.arp.senderIp}` : `ARP ${m.arp.senderIp} is at ${m.arp.senderMac}`;
  let s = `${ep(r.src, r.sport)} → ${ep(r.dst, r.dport)}`;
  if (r.flags) s += ` [${r.flags}]`;
  if (m.dns) {
    s += m.dns.qr === 'query' ? ` Query ${m.dns.qtype || ''} ${m.dns.query || ''}` : ` Response ${m.dns.rcodeName} ${m.dns.query || ''}${m.dns.answers?.length ? ' → ' + m.dns.answers.slice(0, 2).join(', ') : ''}`;
  } else if (m.tls) {
    s += ` ${m.tls.type}${m.tls.sni ? ' SNI=' + m.tls.sni : ''}${m.tls.version ? ' (' + m.tls.version + ')' : ''}`;
  } else if (m.http) s += ` ${m.http.firstLine}`;
  else if (m.icmp) s += ` ${m.icmp.label}`;
  else if (m.ssh) s += ` ${m.ssh}`;
  else if (m.cred) s += ` ${m.cred.protocol} ${m.cred.kind} (value redacted)`;
  else if (m.payloadLen) s += ` len=${m.payloadLen}`;
  return s;
}

export function parseCapture(
  buf: ArrayBuffer,
  opts: { maxPackets: number; onProgress?: (pct: number, n: number) => void },
): ParseOutput {
  const fmt = detectFormat(buf);
  if (!fmt) throw new CaptureFormatError('Unsupported or corrupt file: magic bytes do not match PCAP (a1b2c3d4 / a1b23c4d) or PCAPNG (0a0d0d0a).');
  const warnings: string[] = [];
  const packets: PacketRecord[] = [];
  const linktypes = new Set<number>();
  const bytes = new Uint8Array(buf);
  let total = 0;
  let truncated = 0;
  let parseErrors = 0;
  let unsupported = 0;
  const reader = fmt === 'pcap' ? readPcap(buf, warnings) : readPcapng(buf, warnings);
  let lastReport = 0;
  for (const fr of reader) {
    total++;
    if (packets.length >= opts.maxPackets) continue;
    linktypes.add(fr.linktype);
    if (fr.caplen < fr.len) truncated++;
    const view = bytes.subarray(fr.off, fr.off + fr.caplen);
    try {
      const d = dissect(view, fr.linktype);
      if (d.proto === 'UNSUPPORTED_LINK') unsupported++;
      const base = { ...d, i: total, ts: fr.ts, len: fr.len, caplen: fr.caplen, off: fr.off };
      packets.push({ ...base, info: summarize(base) });
    } catch (e) {
      parseErrors++;
      packets.push({ i: total, ts: fr.ts, len: fr.len, caplen: fr.caplen, off: fr.off, src: null, dst: null, sport: null, dport: null, transport: 'OTHER', proto: 'MALFORMED', flags: '', flagBits: 0, info: 'Malformed packet (dissector error)', meta: {} });
    }
    if (opts.onProgress && fr.off - lastReport > 2_000_000) {
      lastReport = fr.off;
      opts.onProgress(fr.off / buf.byteLength, packets.length);
    }
  }
  if (total > opts.maxPackets) warnings.push(`Packet limit reached: analysed the first ${opts.maxPackets.toLocaleString()} of ${total.toLocaleString()} packets for resource safety. Raise the limit in Settings to analyse more.`);
  if (truncated > 0) warnings.push(`${truncated.toLocaleString()} packets were truncated by the capture snaplen; byte counts use original wire length, but payload-level metadata may be incomplete.`);
  if (parseErrors > 0) warnings.push(`${parseErrors} packets could not be fully dissected and are marked MALFORMED (recorded, not dropped).`);
  if (unsupported > 0) warnings.push(`${unsupported} packets use an unsupported link-layer type (${[...linktypes].map((l) => LINKTYPE_NAMES[l] || l).join(', ')}); they are counted but not decoded.`);
  if (total === 0) warnings.push('The capture contains no packet records.');
  return { format: fmt, linktypes, packets, totalFrames: total, truncated, warnings };
}
