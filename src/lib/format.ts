import type { Severity } from '../engine/types';

export const fmtBytes = (b: number) => {
  if (!isFinite(b)) return '—';
  if (b >= 1073741824) return `${(b / 1073741824).toFixed(2)} GB`;
  if (b >= 1048576) return `${(b / 1048576).toFixed(2)} MB`;
  if (b >= 1024) return `${(b / 1024).toFixed(1)} KB`;
  return `${b} B`;
};
export const fmtNum = (n: number) => (n ?? 0).toLocaleString();
export const fmtTs = (t: number | null | undefined, withDate = true) => {
  if (!t) return '—';
  const d = new Date(t * 1000);
  const iso = d.toISOString();
  return withDate ? `${iso.slice(0, 10)} ${iso.slice(11, 23)}Z` : `${iso.slice(11, 23)}Z`;
};
export const fmtDur = (s: number) => {
  if (!isFinite(s) || s <= 0) return '0s';
  if (s < 1) return `${(s * 1000).toFixed(0)} ms`;
  if (s < 60) return `${s.toFixed(1)} s`;
  if (s < 3600) return `${Math.floor(s / 60)}m ${Math.round(s % 60)}s`;
  return `${Math.floor(s / 3600)}h ${Math.floor((s % 3600) / 60)}m`;
};

export const SEV_ORDER: Severity[] = ['critical', 'high', 'medium', 'low', 'informational'];

export const SEV_STYLE: Record<Severity, string> = {
  critical: 'bg-rose-500/15 text-rose-300 border-rose-500/40',
  high: 'bg-amber-500/15 text-amber-300 border-amber-500/40',
  medium: 'bg-yellow-500/15 text-yellow-300 border-yellow-500/40',
  low: 'bg-sky-500/15 text-sky-300 border-sky-500/40',
  informational: 'bg-slate-500/15 text-slate-300 border-slate-500/40',
};
export const SEV_HEX: Record<Severity, string> = {
  critical: '#fb7185', high: '#fbbf24', medium: '#facc15', low: '#38bdf8', informational: '#94a3b8',
};

export const PROTO_COLORS = ['#0284c7', '#d97706', '#c026d3', '#059669', '#6366f1', '#e11d48', '#0d9488', '#a16207']; // validated for dark surface (CVD + lightness band)
export const OTHER_COLOR = '#64748b';

export function download(name: string, content: string | Blob, mime = 'application/octet-stream') {
  const blob = typeof content === 'string' ? new Blob([content], { type: mime }) : content;
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = name;
  document.body.appendChild(a);
  a.click();
  a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 2000);
}

export function hexDump(bytes: Uint8Array, maxRows = 256) {
  const rows: Array<{ off: string; hex: string; ascii: string }> = [];
  for (let i = 0; i < bytes.length && rows.length < maxRows; i += 16) {
    const chunk = bytes.subarray(i, i + 16);
    const hex = [...chunk].map((b) => b.toString(16).padStart(2, '0')).join(' ');
    const ascii = [...chunk].map((b) => (b >= 32 && b < 127 ? String.fromCharCode(b) : '.')).join('');
    rows.push({ off: i.toString(16).padStart(4, '0'), hex, ascii });
  }
  return rows;
}

export const humanize = (s: string) => s.replace(/_/g, ' ');
