// Small, dependency-free helpers used by the engine.

export function shannonEntropy(s: string): number {
  if (!s) return 0;
  const counts = new Map<string, number>();
  for (const ch of s) counts.set(ch, (counts.get(ch) || 0) + 1);
  let h = 0;
  for (const c of counts.values()) {
    const p = c / s.length;
    h -= p * Math.log2(p);
  }
  return Math.round(h * 1000) / 1000;
}

export function round(n: number, d = 3): number {
  const f = Math.pow(10, d);
  return Math.round(n * f) / f;
}

export function mean(a: number[]): number {
  if (!a.length) return 0;
  let s = 0;
  for (const v of a) s += v;
  return s / a.length;
}

export function std(a: number[]): number {
  if (a.length < 2) return 0;
  const m = mean(a);
  let s = 0;
  for (const v of a) s += (v - m) * (v - m);
  return Math.sqrt(s / a.length);
}

export function median(a: number[]): number {
  if (!a.length) return 0;
  const s = [...a].sort((x, y) => x - y);
  const m = s.length >> 1;
  return s.length % 2 ? s[m] : (s[m - 1] + s[m]) / 2;
}

export function mad(a: number[]): number {
  const m = median(a);
  return median(a.map((v) => Math.abs(v - m)));
}

export function timingStats(ts: number[]) {
  if (ts.length < 2) return { mean: 0, std: 0, cv: 0 };
  const s = [...ts].sort((a, b) => a - b);
  const d: number[] = [];
  for (let i = 1; i < s.length; i++) d.push(s[i] - s[i - 1]);
  const m = mean(d);
  const sd = std(d);
  return { mean: round(m, 4), std: round(sd, 4), cv: m > 1e-6 ? round(sd / m, 4) : 0 };
}

// ── IP classification ──────────────────────────────────────────────────────
export function isInternalIp(ip: string | null | undefined): boolean {
  if (!ip) return false;
  if (ip.includes(':')) {
    const l = ip.toLowerCase();
    return l === '::1' || l.startsWith('fe80') || l.startsWith('fc') || l.startsWith('fd') || l.startsWith('ff');
  }
  const p = ip.split('.').map(Number);
  if (p.length !== 4) return false;
  return (
    p[0] === 10 ||
    p[0] === 127 ||
    (p[0] === 172 && p[1] >= 16 && p[1] <= 31) ||
    (p[0] === 192 && p[1] === 168) ||
    (p[0] === 169 && p[1] === 254) ||
    (p[0] === 100 && p[1] >= 64 && p[1] <= 127) ||
    p[0] >= 224 ||
    ip === '0.0.0.0'
  );
}

export function isBroadcastOrMulticast(ip: string | null | undefined): boolean {
  if (!ip) return false;
  if (ip.includes(':')) return ip.toLowerCase().startsWith('ff');
  const p = ip.split('.').map(Number);
  return p[0] >= 224 || ip.endsWith('.255') || ip === '0.0.0.0';
}

export function baseDomain(name: string): string {
  const parts = name.toLowerCase().replace(/\.$/, '').split('.');
  if (parts.length <= 2) return parts.join('.');
  const sld = parts[parts.length - 2];
  // crude handling of 2-level public suffixes (co.uk, com.au, co.in, ...)
  if (['co', 'com', 'net', 'org', 'gov', 'ac', 'edu'].includes(sld) && parts[parts.length - 1].length === 2) {
    return parts.slice(-3).join('.');
  }
  return parts.slice(-2).join('.');
}

export function portClass(p: number | null): number {
  if (p == null) return 2;
  if (p < 1024) return 0;
  if (p < 49152) return 1;
  return 2;
}

export const WELL_KNOWN: Record<number, string> = {
  20: 'FTP-DATA', 21: 'FTP', 22: 'SSH', 23: 'Telnet', 25: 'SMTP', 53: 'DNS', 67: 'DHCP', 68: 'DHCP', 69: 'TFTP',
  80: 'HTTP', 110: 'POP3', 123: 'NTP', 135: 'MSRPC', 137: 'NetBIOS', 138: 'NetBIOS', 139: 'NetBIOS', 143: 'IMAP',
  161: 'SNMP', 389: 'LDAP', 443: 'HTTPS', 445: 'SMB', 465: 'SMTPS', 514: 'Syslog', 587: 'SMTP', 636: 'LDAPS',
  853: 'DoT', 993: 'IMAPS', 995: 'POP3S', 1433: 'MSSQL', 1521: 'Oracle', 1900: 'SSDP', 3306: 'MySQL', 3389: 'RDP',
  5353: 'mDNS', 5355: 'LLMNR', 5432: 'PostgreSQL', 5900: 'VNC', 5985: 'WinRM', 5986: 'WinRM', 6379: 'Redis',
  8080: 'HTTP-alt', 8443: 'HTTPS-alt', 9200: 'Elasticsearch', 27017: 'MongoDB',
};

export const TLS_PORTS = new Set([443, 8443, 993, 995, 465, 636, 853, 5986, 9443, 4443, 6443, 10443, 2083, 2087, 8883]);
export const HTTP_PORTS = new Set([80, 8080, 8000, 8008, 8081, 8888, 3128, 591, 5000, 3000, 9000, 7001]);
export const SUSPICIOUS_PORTS: Record<number, string> = {
  4444: 'Metasploit default handler', 1337: 'Common backdoor/leet port', 31337: 'Back Orifice / elite port',
  6667: 'IRC (legacy botnet C2)', 6666: 'IRC alt', 9001: 'Tor ORPort', 9050: 'Tor SOCKS', 5555: 'Android ADB / RATs',
  12345: 'NetBus', 2323: 'Telnet alt (IoT botnets)', 7777: 'Common RAT port', 8888: 'Common RAT/alt-HTTP',
};
export const ADMIN_PORTS = new Set([22, 135, 139, 445, 3389, 5985, 5986, 5900, 23]);

// ── MD5 (for JA3 fingerprints only) ────────────────────────────────────────
export function md5(str: string): string {
  const k: number[] = [];
  for (let i = 0; i < 64; i++) k[i] = Math.floor(Math.abs(Math.sin(i + 1)) * 2 ** 32) >>> 0;
  const r = [7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20,
    4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21];
  const bytes = new TextEncoder().encode(str);
  const len = bytes.length;
  const nBlocks = ((len + 8) >> 6) + 1;
  const words = new Uint32Array(nBlocks * 16);
  for (let i = 0; i < len; i++) words[i >> 2] |= bytes[i] << ((i % 4) * 8);
  words[len >> 2] |= 0x80 << ((len % 4) * 8);
  words[nBlocks * 16 - 2] = (len * 8) >>> 0;
  words[nBlocks * 16 - 1] = Math.floor((len * 8) / 2 ** 32);
  let a0 = 0x67452301, b0 = 0xefcdab89, c0 = 0x98badcfe, d0 = 0x10325476;
  for (let b = 0; b < nBlocks; b++) {
    let a = a0, bb = b0, c = c0, d = d0;
    for (let i = 0; i < 64; i++) {
      let f: number, g: number;
      if (i < 16) { f = (bb & c) | (~bb & d); g = i; }
      else if (i < 32) { f = (d & bb) | (~d & c); g = (5 * i + 1) % 16; }
      else if (i < 48) { f = bb ^ c ^ d; g = (3 * i + 5) % 16; }
      else { f = c ^ (bb | ~d); g = (7 * i) % 16; }
      const tmp = d;
      d = c;
      c = bb;
      const x = (a + f + k[i] + words[b * 16 + g]) >>> 0;
      bb = (bb + ((x << r[i]) | (x >>> (32 - r[i])))) >>> 0;
      a = tmp;
    }
    a0 = (a0 + a) >>> 0; b0 = (b0 + bb) >>> 0; c0 = (c0 + c) >>> 0; d0 = (d0 + d) >>> 0;
  }
  const hex = (n: number) => Array.from({ length: 4 }, (_, i) => ((n >>> (i * 8)) & 0xff).toString(16).padStart(2, '0')).join('');
  return hex(a0) + hex(b0) + hex(c0) + hex(d0);
}

// Deterministic PRNG (mulberry32) — reproducible Isolation Forest runs.
export function mulberry32(seed: number) {
  let t = seed >>> 0;
  return () => {
    t = (t + 0x6d2b79f5) >>> 0;
    let r = Math.imul(t ^ (t >>> 15), 1 | t);
    r = (r + Math.imul(r ^ (r >>> 7), 61 | r)) ^ r;
    return ((r ^ (r >>> 14)) >>> 0) / 4294967296;
  };
}

export function stableHash(obj: unknown): string {
  const full = JSON.stringify(obj);
  let h = 2166136261;
  let h2 = 5381;
  for (let i = 0; i < full.length; i++) {
    const c = full.charCodeAt(i);
    h ^= c;
    h = Math.imul(h, 16777619);
    h2 = (Math.imul(h2, 33) + c) | 0;
  }
  return (h >>> 0).toString(16).padStart(8, '0') + (h2 >>> 0).toString(16).padStart(8, '0');
}

export function uid(prefix = ''): string {
  const r = Math.random().toString(36).slice(2, 10);
  return `${prefix}${Date.now().toString(36)}${r}`;
}
