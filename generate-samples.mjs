#!/usr/bin/env node
// Generates synthetic, clearly-labelled demo captures for NetSentry XAI.
// All traffic is fabricated in-process (no real network data). Usage:
//   node scripts/generate-samples.mjs   → writes into public/samples/
import { writeFileSync, mkdirSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const OUT = join(dirname(fileURLToPath(import.meta.url)), '..', 'public', 'samples');
mkdirSync(OUT, { recursive: true });

// ── deterministic RNG ──────────────────────────────────────────────────────
let seed = 1337;
const rnd = () => { seed = (seed * 1664525 + 1013904223) >>> 0; return seed / 4294967296; };
const ri = (a, b) => a + Math.floor(rnd() * (b - a + 1));
const pick = (a) => a[Math.floor(rnd() * a.length)];

// ── byte builders ──────────────────────────────────────────────────────────
const macB = (m) => Buffer.from(m.split(':').map((h) => parseInt(h, 16)));
const ip4B = (ip) => Buffer.from(ip.split('.').map(Number));
function ip6B(ip) {
  const [l, r] = ip.split('::');
  const L = l ? l.split(':') : [];
  const R = r !== undefined && r ? r.split(':') : [];
  const groups = r !== undefined ? [...L, ...Array(8 - L.length - R.length).fill('0'), ...R] : L;
  const b = Buffer.alloc(16);
  groups.forEach((g, i) => b.writeUInt16BE(parseInt(g || '0', 16), i * 2));
  return b;
}
const u16 = (n) => { const b = Buffer.alloc(2); b.writeUInt16BE(n & 0xffff); return b; };
const u32 = (n) => { const b = Buffer.alloc(4); b.writeUInt32BE(n >>> 0); return b; };

const MACS = {};
const macOf = (ip) => (MACS[ip] ||= `02:00:${ip.split('.').slice(-4).map((x) => (+x || 0).toString(16).padStart(2, '0')).join(':')}`.slice(0, 17));
const GW_MAC = '00:1b:21:aa:00:01';
const ATTACKER_MAC = '00:0c:29:66:66:66';

function eth(src, dst, type, payload, srcMac, dstMac) {
  return Buffer.concat([macB(dstMac || (dst.startsWith('10.') ? macOf(dst) : GW_MAC)), macB(srcMac || (src.startsWith('10.') ? macOf(src) : GW_MAC)), u16(type), payload]);
}
function ipv4(src, dst, proto, l4, ttl = 64) {
  const h = Buffer.concat([Buffer.from([0x45, 0]), u16(20 + l4.length), u16(ri(0, 65535)), u16(0x4000), Buffer.from([ttl, proto]), u16(0), ip4B(src), ip4B(dst)]);
  return Buffer.concat([h, l4]);
}
function ipv6(src, dst, nh, l4) {
  return Buffer.concat([Buffer.from([0x60, 0, 0, 0]), u16(l4.length), Buffer.from([nh, 64]), ip6B(src), ip6B(dst), l4]);
}
const F = { FIN: 1, SYN: 2, RST: 4, PSH: 8, ACK: 16, URG: 32 };
function tcp(sp, dp, flags, seq = 0, ack = 0, payload = Buffer.alloc(0)) {
  return Buffer.concat([u16(sp), u16(dp), u32(seq), u32(ack), Buffer.from([0x50, flags]), u16(64240), u16(0), u16(0), payload]);
}
const udp = (sp, dp, payload) => Buffer.concat([u16(sp), u16(dp), u16(8 + payload.length), u16(0), payload]);
const icmp = (type, id, sq) => Buffer.concat([Buffer.from([type, 0]), u16(0), u16(id), u16(sq), Buffer.alloc(32, 0x61)]);
function arp(op, smac, sip, tmac, tip) {
  return Buffer.concat([u16(1), u16(0x0800), Buffer.from([6, 4]), u16(op), macB(smac), ip4B(sip), macB(tmac), ip4B(tip)]);
}
function dnsName(n) {
  return Buffer.concat([...n.split('.').map((l) => Buffer.concat([Buffer.from([l.length]), Buffer.from(l)])), Buffer.from([0])]);
}
const QT = { A: 1, TXT: 16, AAAA: 28 };
function dnsMsg(id, q, qtype, resp = false, rcode = 0, answers = []) {
  const flags = resp ? 0x8180 | rcode : 0x0100;
  const parts = [u16(id), u16(flags), u16(1), u16(answers.length), u16(0), u16(0), dnsName(q), u16(QT[qtype]), u16(1)];
  for (const a of answers) parts.push(Buffer.from([0xc0, 0x0c]), u16(1), u16(1), u32(300), u16(4), ip4B(a));
  return Buffer.concat(parts);
}
function clientHello(sni) {
  const ciphers = [0x1301, 0x1302, 0x1303, 0xc02b, 0xc02f, 0xc02c, 0xc030, 0xcca9, 0xcca8, 0xc013, 0xc014, 0x009c, 0x009d, 0x002f, 0x0035];
  const sniExt = Buffer.concat([u16(0), u16(sni.length + 5), u16(sni.length + 3), Buffer.from([0]), u16(sni.length), Buffer.from(sni)]);
  const groups = Buffer.concat([u16(10), u16(8), u16(6), u16(0x001d), u16(0x0017), u16(0x0018)]);
  const pf = Buffer.concat([u16(11), u16(2), Buffer.from([1, 0])]);
  const alpnList = Buffer.concat([Buffer.from([2]), Buffer.from('h2'), Buffer.from([8]), Buffer.from('http/1.1')]);
  const alpn = Buffer.concat([u16(16), u16(alpnList.length + 2), u16(alpnList.length), alpnList]);
  const sv = Buffer.concat([u16(43), u16(5), Buffer.from([4]), u16(0x0304), u16(0x0303)]);
  const exts = Buffer.concat([sniExt, groups, pf, alpn, sv]);
  const body = Buffer.concat([u16(0x0303), Buffer.alloc(32, 7), Buffer.from([0]), u16(ciphers.length * 2), ...ciphers.map(u16), Buffer.from([1, 0]), u16(exts.length), exts]);
  const hs = Buffer.concat([Buffer.from([1]), Buffer.from([0, body.length >> 8, body.length & 0xff]), body]);
  return Buffer.concat([Buffer.from([0x16, 0x03, 0x01]), u16(hs.length), hs]);
}
function serverHello() {
  const exts = Buffer.concat([u16(43), u16(2), u16(0x0304), u16(51), u16(4), u16(0x001d), u16(0)]);
  const body = Buffer.concat([u16(0x0303), Buffer.alloc(32, 9), Buffer.from([0]), u16(0x1301), Buffer.from([0]), u16(exts.length), exts]);
  const hs = Buffer.concat([Buffer.from([2]), Buffer.from([0, body.length >> 8, body.length & 0xff]), body]);
  return Buffer.concat([Buffer.from([0x16, 0x03, 0x03]), u16(hs.length), hs]);
}
const appData = (n) => { n = Math.max(1, n); return Buffer.concat([Buffer.from([0x17, 0x03, 0x03]), u16(n), Buffer.alloc(n, 0x5a)]); };

// ── capture assembly ───────────────────────────────────────────────────────
class Cap {
  constructor(snap = 65535) { this.pk = []; this.snap = snap; }
  add(t, frame, origLen, capLimit) { this.pk.push({ t, frame, len: origLen || frame.length, capLimit }); }
  sorted() { return this.pk.sort((a, b) => a.t - b.t); }
  pcap() {
    const parts = [Buffer.from([0xd4, 0xc3, 0xb2, 0xa1, 2, 0, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0]), Buffer.alloc(4), Buffer.alloc(4)];
    parts[1].writeUInt32LE(this.snap);
    parts[2].writeUInt32LE(1);
    for (const p of this.sorted()) {
      const cap = p.frame.subarray(0, Math.min(p.capLimit ?? this.snap, this.snap, p.frame.length));
      const h = Buffer.alloc(16);
      h.writeUInt32LE(Math.floor(p.t), 0);
      h.writeUInt32LE(Math.round((p.t % 1) * 1e6) % 1000000, 4);
      h.writeUInt32LE(cap.length, 8);
      h.writeUInt32LE(Math.max(p.len, cap.length), 12);
      parts.push(h, cap);
    }
    return Buffer.concat(parts);
  }
  pcapng() {
    const pad4 = (b) => Buffer.concat([b, Buffer.alloc((4 - (b.length % 4)) % 4)]);
    const block = (type, body) => {
      const len = 12 + body.length;
      const h = Buffer.alloc(8); h.writeUInt32LE(type, 0); h.writeUInt32LE(len, 4);
      const t = Buffer.alloc(4); t.writeUInt32LE(len, 0);
      return Buffer.concat([h, body, t]);
    };
    const shbBody = Buffer.alloc(16); shbBody.writeUInt32LE(0x1a2b3c4d, 0); shbBody.writeUInt16LE(1, 4); shbBody.writeUInt16LE(0, 6); shbBody.writeInt32LE(-1, 8); shbBody.writeInt32LE(-1, 12);
    const opt = (code, val) => { const h = Buffer.alloc(4); h.writeUInt16LE(code, 0); h.writeUInt16LE(val.length, 2); return Buffer.concat([h, pad4(val)]); };
    const idbBody = Buffer.concat([Buffer.from([1, 0, 0, 0]), (() => { const b = Buffer.alloc(4); b.writeUInt32LE(this.snap); return b; })(), opt(2, Buffer.from('eth0-demo')), opt(9, Buffer.from([6])), Buffer.alloc(4)]);
    const parts = [block(0x0a0d0d0a, shbBody), block(1, idbBody)];
    for (const p of this.sorted()) {
      const us = BigInt(Math.round(p.t * 1e6));
      const cap = p.frame.subarray(0, Math.min(p.capLimit ?? this.snap, this.snap, p.frame.length));
      const h = Buffer.alloc(20);
      h.writeUInt32LE(0, 0); h.writeUInt32LE(Number(us >> 32n), 4); h.writeUInt32LE(Number(us & 0xffffffffn), 8);
      h.writeUInt32LE(cap.length, 12); h.writeUInt32LE(Math.max(p.len, cap.length), 16);
      parts.push(block(6, Buffer.concat([h, pad4(cap)])));
    }
    return Buffer.concat(parts);
  }
}

// helpers that emit whole conversations
let ephem = 49152;
const nextPort = () => (ephem = ephem >= 65000 ? 49152 : ephem + ri(1, 7));
function tcpSession(cap, t, c, s, dport, { req = Buffer.alloc(0), resp = Buffer.alloc(0), upBytes = 0, downBytes = 0, close = true, rtt = 0.02, tls = false } = {}) {
  const body = (n) => (tls ? appData(n - 5) : Buffer.alloc(Math.max(1, n), 0x41));
  const sp = nextPort();
  let cs = ri(1000, 900000), ss = ri(1000, 900000);
  const E = (a, b, seg) => eth(a, b, 0x0800, ipv4(a, b, 6, seg, a.startsWith('10.') ? 64 : 52));
  cap.add(t, E(c, s, tcp(sp, dport, F.SYN, cs)));
  cap.add(t + rtt, E(s, c, tcp(dport, sp, F.SYN | F.ACK, ss, cs + 1)));
  cap.add(t + rtt + 0.001, E(c, s, tcp(sp, dport, F.ACK, cs + 1, ss + 1)));
  let tt = t + rtt + 0.002;
  if (req.length) { cap.add(tt, E(c, s, tcp(sp, dport, F.PSH | F.ACK, cs + 1, ss + 1, req))); tt += rtt; }
  if (resp.length) { cap.add(tt, E(s, c, tcp(dport, sp, F.PSH | F.ACK, ss + 1, cs + 1, resp))); tt += 0.002; }
  // bulk data (snaplen will truncate on disk; orig length preserved)
  const seg = 1460;
  for (let sent = 0; sent < upBytes; sent += seg) {
    const n = Math.min(seg, upBytes - sent);
    const frame = E(c, s, tcp(sp, dport, F.ACK | F.PSH, cs + 1 + sent, ss + 1, body(n)));
    cap.add(tt, frame, frame.length, 96);
    tt += 0.0008;
    if ((sent / seg) % 20 === 0) cap.add(tt, E(s, c, tcp(dport, sp, F.ACK, ss + 1, cs + 1 + sent)));
  }
  for (let sent = 0; sent < downBytes; sent += seg) {
    const n = Math.min(seg, downBytes - sent);
    cap.add(tt, E(s, c, tcp(dport, sp, F.ACK | F.PSH, ss + 1 + sent, cs + 1, body(n))), undefined, 96);
    tt += 0.0006;
  }
  if (close) {
    cap.add(tt + 0.01, E(c, s, tcp(sp, dport, F.FIN | F.ACK, cs + 2, ss + 2)));
    cap.add(tt + 0.01 + rtt, E(s, c, tcp(dport, sp, F.FIN | F.ACK, ss + 2, cs + 3)));
    cap.add(tt + 0.012 + rtt, E(c, s, tcp(sp, dport, F.ACK, cs + 3, ss + 3)));
  }
  return tt + 0.02;
}
function dnsLookup(cap, t, c, server, name, answer, rcode = 0, qtype = 'A') {
  const sp = nextPort();
  const id = ri(1, 65535);
  cap.add(t, eth(c, server, 0x0800, ipv4(c, server, 17, udp(sp, 53, dnsMsg(id, name, qtype)))));
  cap.add(t + 0.012 + rnd() * 0.01, eth(server, c, 0x0800, ipv4(server, c, 17, udp(53, sp, dnsMsg(id, name, qtype, true, rcode, answer ? [answer] : [])))));
}
function tlsVisit(cap, t, c, s, sni, { up = 0, down = ri(3000, 60000), port = 443 } = {}) {
  return tcpSession(cap, t, c, s, port, { req: clientHello(sni), resp: Buffer.concat([serverHello(), appData(ri(800, 1400))]), upBytes: up, downBytes: down, tls: true });
}

const SITES = [
  ['www.google.com', '142.250.183.4'], ['outlook.office365.com', '52.97.146.162'], ['github.com', '140.82.112.3'],
  ['teams.microsoft.com', '52.113.194.132'], ['www.wikipedia.org', '208.80.154.224'], ['slack.com', '34.226.36.50'],
  ['fonts.gstatic.com', '142.250.67.67'], ['api.stripe.com', '54.187.174.169'], ['www.linkedin.com', '13.107.42.14'],
  ['update.googleapis.com', '142.250.182.99'], ['login.microsoftonline.com', '20.190.159.68'], ['cdn.jsdelivr.net', '151.101.1.229'],
];

function benignBackground(cap, t0, t1, workstations, dnsServer, sessions) {
  for (let k = 0; k < sessions; k++) {
    const t = t0 + rnd() * (t1 - t0);
    const c = pick(workstations);
    const [name, ip] = pick(SITES);
    dnsLookup(cap, t, c, dnsServer, name, ip);
    tlsVisit(cap, t + 0.05, c, ip, name, { up: ri(400, 4000), down: ri(5000, 120000) });
  }
  // a few plain-HTTP fetches and NTP
  for (let k = 0; k < Math.max(2, sessions / 12); k++) {
    const t = t0 + rnd() * (t1 - t0);
    const c = pick(workstations);
    dnsLookup(cap, t, c, dnsServer, 'www.example.com', '93.184.216.34');
    tcpSession(cap, t + 0.05, c, '93.184.216.34', 80, { req: Buffer.from('GET /index.html HTTP/1.1\r\nHost: www.example.com\r\nUser-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64)\r\n\r\n'), resp: Buffer.from('HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: 1256\r\n\r\n<html>...</html>') });
  }
}

// ═══ Scenario 1: enterprise multi-stage intrusion (PCAP, snaplen 128) ═════
{
  seed = 2026;
  const cap = new Cap(65535);
  const T = 1761400800; // 2025-10-25 14:00:00 UTC — synthetic
  const victim = '10.10.0.23', dns = '10.10.0.2', fileSrv = '10.10.0.5', gw = '10.10.0.1';
  const ws = ['10.10.0.11', '10.10.0.12', '10.10.0.14', '10.10.0.17', '10.10.0.19', '10.10.0.23', '10.10.0.27', '10.10.0.31', '10.10.0.40'];
  const c2 = '45.137.21.9', c2name = 'cdn-sync-update.com';
  benignBackground(cap, T, T + 900, ws, dns, 70);

  // Stage 1 — initial access: HTTP download from odd port
  dnsLookup(cap, T + 58, victim, dns, 'invoice-update.top', '185.243.115.84');
  tcpSession(cap, T + 58.2, victim, '185.243.115.84', 8899, {
    req: Buffer.from('GET /doc/Invoice_8821.php?dl=1 HTTP/1.1\r\nHost: invoice-update.top:8899\r\nUser-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64)\r\n\r\n'),
    resp: Buffer.from('HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\nContent-Disposition: attachment; filename="Invoice_8821.js"\r\n\r\n'), downBytes: 48000,
  });

  // Stage 2 — C2 beaconing every ~30s (low jitter), TLS with SNI
  dnsLookup(cap, T + 110, victim, dns, c2name, c2);
  for (let i = 0; i < 24; i++) tlsVisit(cap, T + 120 + i * 30 + (rnd() - 0.5) * 0.8, victim, c2, c2name, { up: 620, down: 380 });

  // Stage 3 — discovery: ICMP sweep then vertical scan of file server
  for (let h = 1; h <= 30; h++) {
    const tgt = `10.10.0.${h + 40}`;
    cap.add(T + 200 + h * 0.05, eth(victim, tgt, 0x0800, ipv4(victim, tgt, 1, icmp(8, 0x4d2, h))));
    if (h % 3 === 0) cap.add(T + 200 + h * 0.05 + 0.002, eth(tgt, victim, 0x0800, ipv4(tgt, victim, 1, icmp(0, 0x4d2, h))));
  }
  const ports = [21, 22, 23, 25, 53, 80, 88, 110, 111, 135, 139, 143, 389, 443, 445, 464, 593, 636, 1433, 1521, 2049, 3268, 3306, 3389, 5432, 5900, 5985, 8000, 8080, 8443, 9000, 9200];
  ports.forEach((p, k) => {
    const t = T + 230 + k * 0.06;
    const sp = 41000 + k;
    cap.add(t, eth(victim, fileSrv, 0x0800, ipv4(victim, fileSrv, 6, tcp(sp, p, F.SYN, 5000 + k))));
    if ([445, 3389, 135, 139, 5985].includes(p)) cap.add(t + 0.002, eth(fileSrv, victim, 0x0800, ipv4(fileSrv, victim, 6, tcp(p, sp, F.SYN | F.ACK, 9000, 5001 + k))));
    else cap.add(t + 0.002, eth(fileSrv, victim, 0x0800, ipv4(fileSrv, victim, 6, tcp(p, sp, F.RST | F.ACK, 0, 5001 + k))));
  });

  // Stage 4 — lateral movement over SMB to 8 internal hosts
  ['10.10.0.11', '10.10.0.12', '10.10.0.14', '10.10.0.17', '10.10.0.19', '10.10.0.27', '10.10.0.31', '10.10.0.40'].forEach((h, k) =>
    tcpSession(cap, T + 300 + k * 4.3, victim, h, 445, { req: Buffer.from([0, 0, 0, 0x45, 0xfe, 0x53, 0x4d, 0x42]), resp: Buffer.from([0, 0, 0, 0x41, 0xfe, 0x53, 0x4d, 0x42]), upBytes: ri(20000, 90000), downBytes: ri(4000, 9000) }));

  // Stage 5 — DNS tunnelling (TXT, high-entropy labels)
  for (let i = 0; i < 28; i++) {
    const label = Array.from({ length: 52 }, () => '0123456789abcdefghijklmnopqrstuv'[ri(0, 31)]).join('');
    dnsLookup(cap, T + 400 + i * 1.7 + rnd() * 0.4, victim, dns, `${label}.t.dnsx-relay.net`, null, i % 3 === 0 ? 3 : 0, 'TXT');
  }

  // Stage 6 — exfiltration: 14 MB upload to C2 over TLS
  tlsVisit(cap, T + 520, victim, c2, c2name, { up: 14 * 1024 * 1024, down: 30000 });

  // Stage 7 — ARP spoofing of the gateway by a rogue host
  for (let i = 0; i < 14; i++) cap.add(T + 560 + i * 2, eth(gw, '10.10.0.255', 0x0806, arp(2, ATTACKER_MAC, gw, 'ff:ff:ff:ff:ff:ff', '10.10.0.255'), ATTACKER_MAC, 'ff:ff:ff:ff:ff:ff'));
  for (let i = 0; i < 3; i++) {
    cap.add(T + 30 + i * 200, eth('10.10.0.11', gw, 0x0806, arp(1, macOf('10.10.0.11'), '10.10.0.11', '00:00:00:00:00:00', gw), macOf('10.10.0.11'), 'ff:ff:ff:ff:ff:ff'));
    cap.add(T + 30.001 + i * 200, eth(gw, '10.10.0.11', 0x0806, arp(2, GW_MAC, gw, macOf('10.10.0.11'), '10.10.0.11'), GW_MAC, macOf('10.10.0.11')));
  }

  // Stage 8 — stealth Xmas probes from the rogue host
  for (let i = 0; i < 12; i++) cap.add(T + 610 + i * 0.1, eth('10.10.0.66', fileSrv, 0x0800, ipv4('10.10.0.66', fileSrv, 6, tcp(52000 + i, [21, 22, 80, 443, 445, 3389][i % 6], F.FIN | F.PSH | F.URG, 77))));

  // Hygiene issues — cleartext FTP + Telnet
  tcpSession(cap, T + 650, '10.10.0.31', fileSrv, 21, { req: Buffer.from('USER backup_svc\r\n'), resp: Buffer.from('331 Password required\r\n') });
  tcpSession(cap, T + 651, '10.10.0.31', fileSrv, 21, { req: Buffer.from('PASS ********\r\n'), resp: Buffer.from('230 Login successful\r\n') });
  tcpSession(cap, T + 700, '10.10.0.40', '10.10.0.250', 23, { req: Buffer.from('\xff\xfb\x18login: admin\r\n'), resp: Buffer.from('Password: '), upBytes: 600, downBytes: 2400 });

  writeFileSync(join(OUT, 'enterprise_multistage_intrusion.pcap'), cap.pcap());
  console.log(`enterprise_multistage_intrusion.pcap: ${cap.pk.length} packets`);
}

// ═══ Scenario 2: benign office baseline (PCAPNG, with IPv6) ════════════════
{
  seed = 77;
  const cap = new Cap(65535);
  const T = 1761314400; // one day earlier — synthetic
  const ws = ['10.10.0.11', '10.10.0.12', '10.10.0.14', '10.10.0.17', '10.10.0.19', '10.10.0.23', '10.10.0.27', '10.10.0.31'];
  benignBackground(cap, T, T + 900, ws, '10.10.0.2', 90);
  // IPv6 DNS + TLS
  for (let i = 0; i < 6; i++) {
    const c6 = 'fd00:10::23', s6 = '2606:4700::6810:84e5';
    const sp = nextPort();
    const t = T + 60 + rnd() * 800;
    cap.add(t, eth('10.10.0.23', '10.10.0.1', 0x86dd, ipv6(c6, 'fd00:10::2', 17, udp(sp, 53, dnsMsg(900 + i, 'www.cloudflare.com', 'AAAA')))));
    cap.add(t + 0.01, eth('10.10.0.1', '10.10.0.23', 0x86dd, ipv6('fd00:10::2', c6, 17, udp(53, sp, dnsMsg(900 + i, 'www.cloudflare.com', 'AAAA', true, 0)))));
    cap.add(t + 0.03, eth('10.10.0.23', '10.10.0.1', 0x86dd, ipv6(c6, s6, 6, tcp(sp + 1, 443, F.SYN, 1))));
    cap.add(t + 0.05, eth('10.10.0.1', '10.10.0.23', 0x86dd, ipv6(s6, c6, 6, tcp(443, sp + 1, F.SYN | F.ACK, 1, 2))));
    cap.add(t + 0.051, eth('10.10.0.23', '10.10.0.1', 0x86dd, ipv6(c6, s6, 6, tcp(sp + 1, 443, F.PSH | F.ACK, 2, 2, clientHello('www.cloudflare.com')))));
  }
  writeFileSync(join(OUT, 'office_baseline_benign.pcapng'), cap.pcapng());
  console.log(`office_baseline_benign.pcapng: ${cap.pk.length} packets`);
}
