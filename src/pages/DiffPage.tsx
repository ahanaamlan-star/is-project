import { useEffect, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { GitCompareArrows, Plus, Minus, ArrowUpRight, ArrowDownRight, Globe2, Lock, Server, Fingerprint, Sparkles } from 'lucide-react';
import { useStore } from '../store/useStore';
import { Card, PageHeader, SectionTitle, Select, Btn, EmptyState, Pill } from '../components/ui';
import { diffRuns, type DiffResult } from '../lib/diff';
import { fmtBytes, humanize } from '../lib/format';
import { WELL_KNOWN } from '../engine/util';

export default function DiffPage() {
  const s = useStore();
  const nav = useNavigate();
  const analysed = s.captures.filter((c) => c.lastRunId);
  const caseName = (id: string) => s.cases.find((c) => c.id === id)?.name || '?';
  const [a, setA] = useState('');
  const [b, setB] = useState('');
  const [res, setRes] = useState<DiffResult | null>(null);
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    if (!a && analysed.length >= 2) {
      const baseline = analysed.find((c) => /baseline|benign/i.test(c.filename)) || analysed[0];
      setA(baseline.id);
      setB((analysed.find((c) => c.id === s.activeCaptureId && c.id !== baseline.id) || analysed.find((c) => c.id !== baseline.id))!.id);
    }
  }, [analysed.length]); // eslint-disable-line

  const run = async () => {
    setBusy(true);
    const [ra, rb] = await Promise.all([s.loadRunFor(a), s.loadRunFor(b)]);
    if (ra && rb) setRes(diffRuns(ra, rb));
    setBusy(false);
  };
  useEffect(() => { if (a && b && a !== b) run(); }, [a, b]); // eslint-disable-line

  if (analysed.length < 2) {
    return (<><PageHeader title="PCAP Diff" subtitle="Compare two captures or time windows to highlight new endpoints, protocol shifts and changed traffic volume." />
      <EmptyState icon={<GitCompareArrows className="w-6 h-6" />} title="Analyse at least two captures to compare" body="Tip: load the “Office baseline (benign)” demo and the “Enterprise multi-stage intrusion” demo, then return here." action={<Btn onClick={() => nav('/app/ingest')}><Sparkles className="w-3.5 h-3.5" />Load demo captures</Btn>} /></>);
  }
  const t = res?.totals;
  const delta = (x: [number, number], f: (n: number) => string = (n) => n.toLocaleString()) => (
    <div><div className="text-lg font-bold text-white tabular-nums">{f(x[1])}</div><div className={`text-[11px] ${x[1] >= x[0] ? 'text-amber-300' : 'text-emerald-300'}`}>{x[1] >= x[0] ? '▲' : '▼'} vs {f(x[0])}</div></div>
  );

  return (
    <div className="space-y-5">
      <PageHeader title="PCAP Diff" subtitle="Baseline vs. comparison: what is new, what disappeared and what changed. Useful for spotting new endpoints, protocols or egress after an event." />
      <Card className="p-4 grid md:grid-cols-2 gap-3">
        <label className="text-[11px] text-slate-400">Baseline (A)<Select value={a} onChange={(e) => setA(e.target.value)} className="w-full mt-1">{analysed.map((c) => <option key={c.id} value={c.id}>{c.filename} — {caseName(c.caseId)}</option>)}</Select></label>
        <label className="text-[11px] text-slate-400">Comparison (B)<Select value={b} onChange={(e) => setB(e.target.value)} className="w-full mt-1">{analysed.map((c) => <option key={c.id} value={c.id}>{c.filename} — {caseName(c.caseId)}</option>)}</Select></label>
      </Card>
      {a === b && <p className="text-xs text-amber-300">Pick two different captures.</p>}
      {busy && <p className="text-xs text-slate-500">Comparing…</p>}
      {res && t && a !== b && (
        <>
          <div className="grid grid-cols-2 md:grid-cols-5 gap-3">
            {[['Packets', t.packets], ['Flows', t.flows], ['Hosts', t.hosts], ['Findings', t.findings]].map(([l, v]) => <Card key={l as string} className="p-3"><div className="text-[11px] text-slate-400">{l as string}</div>{delta(v as [number, number])}</Card>)}
            <Card className="p-3"><div className="text-[11px] text-slate-400">Bytes</div>{delta(t.bytes, fmtBytes)}</Card>
          </div>
          <div className="grid lg:grid-cols-2 gap-5">
            <Card className="p-5">
              <SectionTitle icon={<Plus className="w-4 h-4 text-amber-400" />}>New hosts in B ({res.newHosts.length})</SectionTitle>
              <div className="space-y-1 max-h-72 overflow-y-auto">{res.newHosts.slice(0, 40).map((h) => (
                <div key={h.ip} className="flex justify-between gap-2 text-[11px] py-1 border-b border-slate-800/50"><span className="font-mono text-slate-200 truncate">{h.ip}{h.names[0] && <span className="text-slate-500"> · {h.names[0]}</span>}</span><span className="flex gap-2 items-center shrink-0"><Pill className={h.internal ? 'text-emerald-300' : 'text-amber-300'}>{h.internal ? 'int' : 'ext'}</Pill><span className="text-slate-400 tabular-nums">{fmtBytes(h.bytes)}</span></span></div>
              ))}{!res.newHosts.length && <p className="text-xs text-slate-500">None.</p>}</div>
            </Card>
            <Card className="p-5">
              <SectionTitle icon={<Server className="w-4 h-4 text-sky-400" />}>Hosts with ≥2× volume change</SectionTitle>
              <div className="space-y-1 max-h-72 overflow-y-auto">{res.hostVolumeChanges.map((h) => (
                <div key={h.ip} className="flex justify-between gap-2 text-[11px] py-1 border-b border-slate-800/50"><span className="font-mono text-slate-200">{h.ip}</span><span className={`flex items-center gap-1 tabular-nums ${h.ratio > 1 ? 'text-amber-300' : 'text-emerald-300'}`}>{h.ratio > 1 ? <ArrowUpRight className="w-3 h-3" /> : <ArrowDownRight className="w-3 h-3" />}{fmtBytes(h.before)} → {fmtBytes(h.after)} ({h.ratio.toFixed(1)}×)</span></div>
              ))}{!res.hostVolumeChanges.length && <p className="text-xs text-slate-500">No shared host changed volume by 2× or more.</p>}</div>
              {res.goneHosts.length > 0 && <div className="mt-3 text-[11px] text-slate-500 flex gap-1.5"><Minus className="w-3.5 h-3.5" />{res.goneHosts.length} hosts present in A are absent in B.</div>}
            </Card>
          </div>
          <div className="grid lg:grid-cols-3 gap-5">
            <Card className="p-5">
              <SectionTitle>Protocol share shift (percentage points)</SectionTitle>
              {res.protocolShift.slice(0, 10).map((p) => (
                <div key={p.proto} className="grid grid-cols-12 gap-2 items-center text-[11px] py-1">
                  <span className="col-span-3 text-slate-300">{p.proto}</span>
                  <div className="col-span-6 relative h-2 bg-slate-800 rounded"><div className="absolute top-0 h-2 rounded" style={{ left: p.delta < 0 ? `${50 + Math.max(-50, p.delta / 2)}%` : '50%', width: `${Math.min(50, Math.abs(p.delta) / 2)}%`, background: p.delta >= 0 ? '#d97706' : '#0d9488' }} /><div className="absolute left-1/2 top-[-2px] w-px h-3 bg-slate-500" /></div>
                  <span className={`col-span-3 text-right tabular-nums ${p.delta >= 0 ? 'text-amber-300' : 'text-teal-300'}`}>{p.delta > 0 ? '+' : ''}{p.delta}</span>
                </div>
              ))}
            </Card>
            <Card className="p-5">
              <SectionTitle icon={<Globe2 className="w-4 h-4 text-emerald-400" />}>New DNS names ({res.newDomains.length})</SectionTitle>
              <div className="max-h-64 overflow-y-auto space-y-0.5">{res.newDomains.slice(0, 60).map((d) => <div key={d} className="text-[11px] font-mono text-slate-300 truncate">{d}</div>)}{!res.newDomains.length && <p className="text-xs text-slate-500">None.</p>}</div>
            </Card>
            <Card className="p-5 space-y-4">
              <div><SectionTitle icon={<Lock className="w-4 h-4 text-fuchsia-400" />}>New TLS SNI ({res.newSni.length})</SectionTitle>{res.newSni.slice(0, 15).map((d) => <div key={d} className="text-[11px] font-mono text-slate-300 truncate">{d}</div>)}{!res.newSni.length && <p className="text-xs text-slate-500">None.</p>}</div>
              <div><SectionTitle icon={<Fingerprint className="w-4 h-4 text-sky-400" />}>New JA3 fingerprints ({res.newJa3.length})</SectionTitle>{res.newJa3.slice(0, 8).map((d) => <div key={d} className="text-[11px] font-mono text-slate-300 truncate">{d}</div>)}</div>
              <div><SectionTitle>New destination ports</SectionTitle><div className="flex flex-wrap gap-1">{res.newPorts.map((p) => <Pill key={p.port} className="font-mono">{p.port}{WELL_KNOWN[p.port] ? ` ${WELL_KNOWN[p.port]}` : ''} ×{p.flows}</Pill>)}{!res.newPorts.length && <span className="text-xs text-slate-500">None.</span>}</div></div>
            </Card>
          </div>
          <Card className="p-5">
            <SectionTitle>Findings by category</SectionTitle>
            <div className="grid sm:grid-cols-2 md:grid-cols-4 gap-2">{res.findingDelta.map((d) => <div key={d.category} className="p-2.5 rounded-lg border border-slate-800 bg-slate-950/50 text-[11px]"><div className="text-slate-400">{humanize(d.category)}</div><div className="text-white font-bold tabular-nums">{d.before} → {d.after}</div></div>)}{!res.findingDelta.length && <p className="text-xs text-slate-500">No findings in either capture.</p>}</div>
          </Card>
        </>
      )}
    </div>
  );
}
