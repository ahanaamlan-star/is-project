import React from 'react';
import { X } from 'lucide-react';
import type { Severity, FindingStatus, Confidence } from '../engine/types';
import { SEV_STYLE } from '../lib/format';
import { STATUS_LABEL } from '../store/useStore';

export const cx = (...c: Array<string | false | null | undefined>) => c.filter(Boolean).join(' ');

export function Card({ className, children, ...rest }: React.HTMLAttributes<HTMLDivElement>) {
  return <div className={cx('bg-slate-900/60 border border-slate-800 rounded-xl', className)} {...rest}>{children}</div>;
}

export function SectionTitle({ icon, children, right }: { icon?: React.ReactNode; children: React.ReactNode; right?: React.ReactNode }) {
  return (
    <div className="flex items-center justify-between gap-3 mb-3">
      <h2 className="text-[11px] font-bold uppercase tracking-wider text-slate-300 flex items-center gap-1.5">{icon}{children}</h2>
      {right}
    </div>
  );
}

export function PageHeader({ title, subtitle, right }: { title: string; subtitle?: string; right?: React.ReactNode }) {
  return (
    <div className="flex flex-col md:flex-row md:items-end md:justify-between gap-3 mb-6">
      <div>
        <h1 className="text-xl font-bold text-white tracking-tight">{title}</h1>
        {subtitle && <p className="text-xs text-slate-400 mt-1 max-w-3xl leading-relaxed">{subtitle}</p>}
      </div>
      {right && <div className="flex flex-wrap items-center gap-2">{right}</div>}
    </div>
  );
}

export function SeverityBadge({ s, className }: { s: Severity; className?: string }) {
  return <span className={cx('text-[10px] px-2 py-0.5 rounded font-bold uppercase tracking-wider border whitespace-nowrap', SEV_STYLE[s], className)}>{s}</span>;
}

const STATUS_STYLE: Record<FindingStatus, string> = {
  new: 'bg-slate-800 text-slate-300 border-slate-700',
  under_review: 'bg-yellow-500/10 text-yellow-300 border-yellow-500/30',
  benign_false_positive: 'bg-emerald-500/10 text-emerald-300 border-emerald-500/30',
  suspicious: 'bg-amber-500/10 text-amber-300 border-amber-500/30',
  escalated: 'bg-rose-500/10 text-rose-300 border-rose-500/30',
};
export function StatusBadge({ s }: { s: FindingStatus }) {
  return <span className={cx('text-[10px] px-2 py-0.5 rounded border font-semibold whitespace-nowrap', STATUS_STYLE[s])}>{STATUS_LABEL[s]}</span>;
}

export function ConfidenceBadge({ c }: { c: Confidence }) {
  const st = c === 'high' ? 'text-emerald-300 border-emerald-500/30' : c === 'medium' ? 'text-sky-300 border-sky-500/30' : 'text-slate-400 border-slate-600';
  return <span className={cx('text-[10px] px-1.5 py-0.5 rounded border whitespace-nowrap', st)} title="Evidence confidence — completeness and directness of observations (separate from severity)">evidence: {c}</span>;
}

export function Pill({ children, className, title }: { children: React.ReactNode; className?: string; title?: string }) {
  return <span title={title} className={cx('text-[10px] px-2 py-0.5 rounded bg-slate-800 text-slate-300 border border-slate-700 whitespace-nowrap', className)}>{children}</span>;
}

export function Stat({ label, value, sub, icon, accent = 'text-sky-400', onClick }: { label: string; value: React.ReactNode; sub?: string; icon?: React.ReactNode; accent?: string; onClick?: () => void }) {
  return (
    <Card className={cx('p-4', onClick && 'cursor-pointer hover:border-sky-500/40 transition-colors')} onClick={onClick}>
      <div className="flex items-center justify-between text-slate-400 text-[11px]">
        <span>{label}</span>
        <span className={accent}>{icon}</span>
      </div>
      <div className="text-2xl font-bold text-white mt-1.5 tabular-nums">{value}</div>
      {sub && <div className="text-[11px] text-slate-500 mt-0.5">{sub}</div>}
    </Card>
  );
}

export function Btn({ variant = 'primary', size = 'md', className, children, ...rest }: React.ButtonHTMLAttributes<HTMLButtonElement> & { variant?: 'primary' | 'secondary' | 'ghost' | 'danger' | 'success'; size?: 'sm' | 'md' }) {
  const v = {
    primary: 'bg-sky-600 hover:bg-sky-500 text-white border-sky-500/50',
    secondary: 'bg-slate-900 hover:bg-slate-800 text-slate-200 border-slate-700',
    ghost: 'bg-transparent hover:bg-slate-800/70 text-slate-300 border-transparent',
    danger: 'bg-rose-500/10 hover:bg-rose-500/20 text-rose-300 border-rose-500/30',
    success: 'bg-emerald-600 hover:bg-emerald-500 text-white border-emerald-500/50',
  }[variant];
  const s = size === 'sm' ? 'px-2.5 py-1 text-[11px]' : 'px-3.5 py-1.5 text-xs';
  return (
    <button className={cx('inline-flex items-center justify-center gap-1.5 rounded-lg border font-semibold transition-colors disabled:opacity-50 disabled:cursor-not-allowed', v, s, className)} {...rest}>
      {children}
    </button>
  );
}

export function EmptyState({ icon, title, body, action }: { icon?: React.ReactNode; title: string; body?: string; action?: React.ReactNode }) {
  return (
    <div className="p-10 text-center border border-dashed border-slate-800 rounded-xl bg-slate-900/30">
      <div className="mx-auto w-12 h-12 rounded-xl bg-slate-900 border border-slate-800 flex items-center justify-center text-slate-500 mb-3">{icon}</div>
      <h3 className="text-sm font-semibold text-slate-200">{title}</h3>
      {body && <p className="text-xs text-slate-500 mt-1 max-w-md mx-auto leading-relaxed">{body}</p>}
      {action && <div className="mt-4 flex justify-center gap-2">{action}</div>}
    </div>
  );
}

export function Modal({ open, onClose, title, children, wide, header }: { open: boolean; onClose: () => void; title?: React.ReactNode; children: React.ReactNode; wide?: boolean; header?: React.ReactNode }) {
  React.useEffect(() => {
    if (!open) return;
    const h = (e: KeyboardEvent) => e.key === 'Escape' && onClose();
    window.addEventListener('keydown', h);
    return () => window.removeEventListener('keydown', h);
  }, [open, onClose]);
  if (!open) return null;
  return (
    <div className="fixed inset-0 z-50 flex items-start md:items-center justify-center bg-black/75 backdrop-blur-sm p-3 md:p-6 animate-fadein" onMouseDown={(e) => e.target === e.currentTarget && onClose()}>
      <div className={cx('bg-ink-800 border border-slate-800 rounded-xl w-full max-h-[92vh] overflow-y-auto shadow-2xl', wide ? 'max-w-5xl' : 'max-w-lg')} role="dialog" aria-modal="true">
        <div className="px-5 py-4 border-b border-slate-800 flex items-start justify-between gap-4 bg-slate-900/80 sticky top-0 z-10 backdrop-blur">
          <div className="min-w-0 flex-1">{header || <h2 className="text-sm font-bold text-white uppercase tracking-wider">{title}</h2>}</div>
          <button onClick={onClose} className="p-1.5 text-slate-400 hover:text-white rounded-lg hover:bg-slate-800" aria-label="Close"><X className="w-4 h-4" /></button>
        </div>
        <div className="p-5">{children}</div>
      </div>
    </div>
  );
}

export function KV({ k, v, mono }: { k: string; v: React.ReactNode; mono?: boolean }) {
  return (
    <div className="flex justify-between gap-3 border-b border-slate-800/60 py-1.5 text-xs">
      <span className="text-slate-500 shrink-0">{k}</span>
      <span className={cx('text-slate-200 text-right break-all', mono && 'font-mono text-[11px]')}>{v}</span>
    </div>
  );
}

export function Input(props: React.InputHTMLAttributes<HTMLInputElement>) {
  return <input {...props} className={cx('bg-slate-950 border border-slate-800 rounded-lg px-2.5 py-1.5 text-xs text-slate-200 outline-none focus:border-sky-500 placeholder:text-slate-600', props.className)} />;
}
export function Select(props: React.SelectHTMLAttributes<HTMLSelectElement>) {
  return <select {...props} className={cx('bg-slate-950 border border-slate-800 rounded-lg px-2 py-1.5 text-xs text-slate-200 outline-none focus:border-sky-500', props.className)} />;
}
export function Textarea(props: React.TextareaHTMLAttributes<HTMLTextAreaElement>) {
  return <textarea {...props} className={cx('w-full bg-slate-950 border border-slate-800 rounded-lg p-2.5 text-xs text-slate-200 outline-none focus:border-sky-500 placeholder:text-slate-600', props.className)} />;
}

export function Bar({ value, max = 1, color = '#38bdf8' }: { value: number; max?: number; color?: string }) {
  return (
    <div className="h-1.5 bg-slate-800 rounded-full overflow-hidden">
      <div className="h-full rounded-full" style={{ width: `${Math.max(2, Math.min(100, (value / (max || 1)) * 100))}%`, background: color }} />
    </div>
  );
}
