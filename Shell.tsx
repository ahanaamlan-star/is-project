import React, { useEffect, useState } from 'react';
import { NavLink, Outlet, Link, useNavigate } from 'react-router-dom';
import {
  Shield, Activity, Plus, Folder, LayoutDashboard, UploadCloud, BarChart3, AlertTriangle, Network, Share2, Clock, FileText,
  FileCheck2, Settings2, Layers, MessageSquareText, GitCompareArrows, FlaskConical, Menu, X, Search, Cpu, CheckCircle2, AlertCircle, Info, SlidersHorizontal,
} from 'lucide-react';
import { useStore } from '../store/useStore';
import { Btn, Input, Modal, Textarea, cx } from './ui';
import { FindingModal } from './FindingModal';
import { PacketModal, FlowModal, HostModal } from './EvidenceModals';
import { CommandPalette } from './CommandPalette';

const NAV: Array<{ group: string; items: Array<{ to: string; label: string; icon: React.ReactNode; badge?: 'findings' | 'incidents' }> }> = [
  { group: 'Investigation', items: [
    { to: 'dashboard', label: 'Case Dashboard', icon: <LayoutDashboard className="w-4 h-4" /> },
    { to: 'ingest', label: 'PCAP Ingestion', icon: <UploadCloud className="w-4 h-4" /> },
    { to: 'overview', label: 'Analysis Overview', icon: <BarChart3 className="w-4 h-4" /> },
    { to: 'findings', label: 'Findings Explorer', icon: <AlertTriangle className="w-4 h-4" />, badge: 'findings' },
    { to: 'incidents', label: 'Incidents', icon: <Layers className="w-4 h-4" />, badge: 'incidents' },
  ] },
  { group: 'Evidence', items: [
    { to: 'flows', label: 'Packets & Flows', icon: <Network className="w-4 h-4" /> },
    { to: 'graph', label: 'Host Network Graph', icon: <Share2 className="w-4 h-4" /> },
    { to: 'timeline', label: 'Incident Timeline', icon: <Clock className="w-4 h-4" /> },
    { to: 'assistant', label: 'Evidence Assistant', icon: <MessageSquareText className="w-4 h-4" /> },
    { to: 'diff', label: 'PCAP Diff', icon: <GitCompareArrows className="w-4 h-4" /> },
  ] },
  { group: 'Case & Lab', items: [
    { to: 'notes', label: 'Analyst Notes & Audit', icon: <FileText className="w-4 h-4" /> },
    { to: 'reports', label: 'Investigation Reports', icon: <FileCheck2 className="w-4 h-4" /> },
    { to: 'lab', label: 'Evaluation Lab', icon: <FlaskConical className="w-4 h-4" /> },
    { to: 'settings', label: 'Detection Settings', icon: <SlidersHorizontal className="w-4 h-4" /> },
    { to: 'diagnostics', label: 'System Diagnostics', icon: <Settings2 className="w-4 h-4" /> },
  ] },
];

export function Shell() {
  const s = useStore();
  const nav = useNavigate();
  const [mobileNav, setMobileNav] = useState(false);
  const [createOpen, setCreateOpen] = useState(false);
  const [name, setName] = useState('');
  const [desc, setDesc] = useState('');

  useEffect(() => { if (!s.ready) s.init(); }, []); // eslint-disable-line

  useEffect(() => {
    const h = (e: KeyboardEvent) => {
      if ((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === 'k') { e.preventDefault(); s.setPalette(!useStore.getState().paletteOpen); }
    };
    window.addEventListener('keydown', h);
    return () => window.removeEventListener('keydown', h);
  }, []); // eslint-disable-line

  const activeFindings = s.run ? s.run.findings.filter((f) => !f.suppressed && f.status !== 'benign_false_positive').length : 0;
  const badges = { findings: activeFindings, incidents: s.run?.incidents.length || 0 };

  const submitCase = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!name.trim()) return;
    await s.createCase(name.trim(), desc.trim());
    setCreateOpen(false); setName(''); setDesc('');
    nav('/app/ingest');
  };

  const sidebar = (
    <nav className="p-3 space-y-5">
      {NAV.map((g) => (
        <div key={g.group}>
          <div className="text-[10px] font-bold text-slate-500 uppercase tracking-wider px-3 mb-1.5">{g.group}</div>
          <div className="space-y-0.5">
            {g.items.map((it) => (
              <NavLink key={it.to} to={`/app/${it.to}`} onClick={() => setMobileNav(false)}
                className={({ isActive }) => cx('w-full flex items-center justify-between px-3 py-2 rounded-lg text-xs font-medium transition-all border',
                  isActive ? 'bg-sky-500/10 text-sky-400 border-sky-500/30 font-semibold' : 'text-slate-400 hover:text-slate-200 hover:bg-slate-900 border-transparent')}>
                <span className="flex items-center gap-3">{it.icon}<span>{it.label}</span></span>
                {it.badge && badges[it.badge] > 0 && (
                  <span className={cx('px-2 py-0.5 text-[10px] rounded-full font-bold border', it.badge === 'findings' ? 'bg-rose-500/20 text-rose-300 border-rose-500/30' : 'bg-indigo-500/20 text-indigo-300 border-indigo-500/30')}>{badges[it.badge]}</span>
                )}
              </NavLink>
            ))}
          </div>
        </div>
      ))}
      <div className="p-3 rounded-lg bg-slate-900/60 border border-slate-800/80 text-[11px] text-slate-400 leading-relaxed">
        <div className="font-semibold text-slate-300 mb-1 flex items-center gap-1.5"><span className="w-2 h-2 rounded-full bg-emerald-400 inline-block" />Local-first forensics</div>
        Captures are parsed in a Web Worker inside this browser. Nothing is uploaded to any server.
      </div>
    </nav>
  );

  return (
    <div className="min-h-screen bg-ink-950 flex flex-col font-sans text-slate-100">
      <header className="h-16 bg-ink-850/95 backdrop-blur border-b border-slate-800 px-3 md:px-5 flex items-center justify-between sticky top-0 z-40 gap-2">
        <div className="flex items-center gap-2 md:gap-3 min-w-0">
          <button className="lg:hidden p-2 text-slate-400 hover:text-white" onClick={() => setMobileNav(true)} aria-label="Open navigation"><Menu className="w-5 h-5" /></button>
          <Link to="/" className="flex items-center gap-3 min-w-0">
            <div className="w-10 h-10 rounded-lg bg-sky-500/10 border border-sky-500/30 flex items-center justify-center shrink-0"><Shield className="w-6 h-6 text-sky-400" /></div>
            <div className="hidden sm:block">
              <div className="flex items-center gap-2"><span className="font-bold text-lg tracking-tight text-white">NetSentry</span><span className="text-xs font-semibold px-2 py-0.5 rounded bg-sky-500/20 text-sky-400 border border-sky-500/40">XAI</span></div>
              <div className="text-[10px] text-slate-400 tracking-wider uppercase font-medium">Explainable Network Forensics</div>
            </div>
          </Link>
        </div>
        <div className="flex items-center gap-2 md:gap-3 min-w-0">
          <button onClick={() => s.setPalette(true)} className="hidden md:flex items-center gap-2 bg-slate-900 border border-slate-800 rounded-lg px-3 py-1.5 text-xs text-slate-500 hover:text-slate-300 hover:border-slate-700">
            <Search className="w-3.5 h-3.5" /><span>Search evidence…</span><kbd className="ml-4 text-[10px] px-1.5 py-0.5 rounded bg-slate-800 border border-slate-700 font-mono">Ctrl K</kbd>
          </button>
          <div className="flex items-center gap-2 bg-slate-900 border border-slate-800 rounded-lg px-2.5 py-1.5 min-w-0">
            <Folder className="w-4 h-4 text-slate-400 shrink-0" />
            <select value={s.activeCaseId || ''} onChange={(e) => s.selectCase(e.target.value)} className="bg-transparent text-xs font-medium text-slate-200 outline-none cursor-pointer max-w-[110px] md:max-w-[200px]" aria-label="Active case">
              {s.cases.length === 0 && <option value="">No cases yet</option>}
              {s.cases.map((c) => <option key={c.id} value={c.id} className="bg-slate-900">{c.name}</option>)}
            </select>
          </div>
          <Btn onClick={() => setCreateOpen(true)} className="shrink-0"><Plus className="w-3.5 h-3.5" /><span className="hidden sm:inline">New Case</span></Btn>
          <div className={cx('hidden xl:flex items-center gap-2 text-xs px-3 py-1 rounded-full border', s.progress ? 'bg-sky-500/10 border-sky-500/30 text-sky-300' : 'bg-emerald-500/10 border-emerald-500/20 text-emerald-400')}>
            {s.progress ? <Cpu className="w-3.5 h-3.5 animate-pulse" /> : <Activity className="w-3.5 h-3.5 animate-pulse" />}
            <span>{s.progress ? `${s.progress.stage} ${Math.round(s.progress.pct * 100)}%` : 'Engine ready'}</span>
          </div>
        </div>
      </header>

      <div className="flex-1 flex">
        <aside className="hidden lg:block w-64 bg-ink-900 border-r border-slate-800 shrink-0 sticky top-16 h-[calc(100vh-4rem)] overflow-y-auto">{sidebar}</aside>
        {mobileNav && (
          <div className="lg:hidden fixed inset-0 z-50 flex" onClick={() => setMobileNav(false)}>
            <div className="w-72 max-w-[85%] bg-ink-900 border-r border-slate-800 h-full overflow-y-auto" onClick={(e) => e.stopPropagation()}>
              <div className="flex justify-end p-2"><button onClick={() => setMobileNav(false)} className="p-2 text-slate-400" aria-label="Close navigation"><X className="w-5 h-5" /></button></div>
              {sidebar}
            </div>
            <div className="flex-1 bg-black/60" />
          </div>
        )}
        <main className="flex-1 min-w-0 p-4 md:p-8">
          {!s.ready ? <div className="text-xs text-slate-500">Loading workspace…</div> : <Outlet />}
        </main>
      </div>

      {s.progress && <ProgressBar />}
      <FindingModal />
      <PacketModal />
      <FlowModal />
      <HostModal />
      <CommandPalette />
      <Toasts />

      <Modal open={createOpen} onClose={() => setCreateOpen(false)} title="Create investigation case">
        <form onSubmit={submitCase} className="space-y-4 text-xs">
          <div>
            <label className="block text-slate-400 mb-1 font-semibold">Case title / identifier *</label>
            <Input autoFocus required value={name} onChange={(e) => setName(e.target.value)} placeholder="e.g. Incident-2026-DMZ-Scan" className="w-full font-mono" />
          </div>
          <div>
            <label className="block text-slate-400 mb-1 font-semibold">Description & background</label>
            <Textarea rows={3} value={desc} onChange={(e) => setDesc(e.target.value)} placeholder="Reason for investigation, capture sensor origin, suspect IPs…" />
          </div>
          <div className="flex justify-end gap-2">
            <Btn type="button" variant="secondary" onClick={() => setCreateOpen(false)}>Cancel</Btn>
            <Btn type="submit"><Plus className="w-3.5 h-3.5" />Create case</Btn>
          </div>
        </form>
      </Modal>
    </div>
  );
}

function ProgressBar() {
  const p = useStore((s) => s.progress)!;
  return (
    <div className="fixed bottom-4 right-4 z-50 w-80 bg-ink-800 border border-sky-500/30 rounded-xl p-4 shadow-2xl animate-fadein">
      <div className="flex items-center justify-between text-xs mb-2">
        <span className="font-semibold text-sky-300 flex items-center gap-2"><Cpu className="w-4 h-4 animate-pulse" />{p.stage}</span>
        <span className="text-slate-400 tabular-nums">{Math.round(p.pct * 100)}%</span>
      </div>
      <div className="h-1.5 bg-slate-800 rounded-full overflow-hidden"><div className="h-full bg-sky-500 transition-all" style={{ width: `${Math.max(3, p.pct * 100)}%` }} /></div>
      {p.detail && <div className="text-[11px] text-slate-500 mt-1.5">{p.detail}</div>}
    </div>
  );
}

function Toasts() {
  const { toasts, dismissToast } = useStore();
  return (
    <div className="fixed top-20 right-4 z-[60] space-y-2 w-80 max-w-[calc(100vw-2rem)]">
      {toasts.map((t) => (
        <div key={t.id} onClick={() => dismissToast(t.id)} className={cx('p-3 rounded-lg border text-xs flex gap-2 items-start shadow-xl cursor-pointer animate-fadein backdrop-blur',
          t.kind === 'success' ? 'bg-emerald-950/90 border-emerald-500/40 text-emerald-200' : t.kind === 'error' ? 'bg-rose-950/90 border-rose-500/40 text-rose-200' : 'bg-slate-900/95 border-slate-700 text-slate-200')}>
          {t.kind === 'success' ? <CheckCircle2 className="w-4 h-4 shrink-0" /> : t.kind === 'error' ? <AlertCircle className="w-4 h-4 shrink-0" /> : <Info className="w-4 h-4 shrink-0" />}
          <span className="leading-relaxed">{t.text}</span>
        </div>
      ))}
    </div>
  );
}
