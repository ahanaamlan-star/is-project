import { useEffect, useState } from 'react';
import { useSearchParams } from 'react-router-dom';
import { Layers, Link2, Unlink, Merge, ChevronRight, Users, BookOpen } from 'lucide-react';
import { useStore } from '../store/useStore';
import { NeedsRun } from '../components/Guards';
import { Card, PageHeader, SeverityBadge, StatusBadge, SectionTitle, Btn, Select, EmptyState, Pill, cx } from '../components/ui';
import { fmtTs, fmtDur } from '../lib/format';
import { SEV_RANK } from '../engine/correlate';
import type { Severity } from '../engine/types';

const TACTICS = ['Discovery', 'Credential Access', 'Lateral Movement', 'Command and Control', 'Exfiltration', 'Impact'];

export function IncidentsPage() {
  return <NeedsRun><Incidents /></NeedsRun>;
}

function Incidents() {
  const s = useStore();
  const run = s.run!;
  const [params, setParams] = useSearchParams();
  const [sel, setSel] = useState<string | null>(params.get('id') || run.incidents[0]?.id || null);
  const [mergeTarget, setMergeTarget] = useState('');
  useEffect(() => { const id = params.get('id'); if (id) setSel(id); }, [params]);
  const inc = run.incidents.find((i) => i.id === sel) || run.incidents[0];

  if (!run.incidents.length) {
    return (<><PageHeader title="Incidents" subtitle="Candidate incidents group findings that share hosts/entities within the correlation window." />
      <EmptyState icon={<Layers className="w-6 h-6" />} title="No correlated incidents" body="Findings in this run do not share entities within the correlation window (configurable in Settings). Individual findings are still available in the Findings Explorer." /></>);
  }
  const fmap = new Map(run.findings.map((f) => [f.id, f]));
  const fs = inc.findingIds.map((id) => fmap.get(id)!).filter(Boolean);

  const split = (fid: string) => s.updateRun((r) => {
    const i = r.incidents.find((x) => x.id === inc.id)!;
    i.findingIds = i.findingIds.filter((x) => x !== fid);
    const f = r.findings.find((x) => x.id === fid)!;
    delete f.incidentId;
    if (i.findingIds.length < 2) {
      for (const id of i.findingIds) delete r.findings.find((x) => x.id === id)!.incidentId;
      r.incidents = r.incidents.filter((x) => x.id !== inc.id);
    }
    return r;
  }, 'incident_split', `Analyst removed ${fid} from ${inc.id}`);

  const merge = () => mergeTarget && s.updateRun((r) => {
    const a = r.incidents.find((x) => x.id === inc.id)!;
    const b = r.incidents.find((x) => x.id === mergeTarget)!;
    a.findingIds = [...new Set([...a.findingIds, ...b.findingIds])];
    a.entities = [...new Set([...a.entities, ...b.entities])];
    a.tactics = [...new Set([...a.tactics, ...b.tactics])].sort((x, y) => TACTICS.indexOf(x) - TACTICS.indexOf(y));
    a.reasons = [...a.reasons, `Merged manually with ${b.id} by analyst`];
    a.start = Math.min(a.start, b.start); a.end = Math.max(a.end, b.end);
    a.riskMax = Math.max(a.riskMax, b.riskMax);
    a.severity = SEV_RANK[b.severity] > SEV_RANK[a.severity] ? b.severity : a.severity;
    for (const id of b.findingIds) r.findings.find((x) => x.id === id)!.incidentId = a.id;
    r.incidents = r.incidents.filter((x) => x.id !== b.id);
    return r;
  }, 'incident_merge', `Analyst merged ${mergeTarget} into ${inc.id}`).then(() => setMergeTarget(''));

  return (
    <div className="space-y-5">
      <PageHeader title="Incidents" subtitle="Findings correlated by shared entities and time proximity. The grouping rationale is shown for every incident; analysts can split or merge groupings and every change is audited." />
      <div className="grid lg:grid-cols-3 gap-5">
        <div className="space-y-2">
          {run.incidents.map((i) => (
            <button key={i.id} onClick={() => { setSel(i.id); setParams({ id: i.id }); }} className={cx('w-full text-left p-4 rounded-xl border transition-colors', i.id === inc.id ? 'border-indigo-500/50 bg-indigo-500/5' : 'border-slate-800 bg-slate-900/60 hover:border-slate-700')}>
              <div className="flex items-center justify-between gap-2"><div className="flex items-center gap-1.5"><SeverityBadge s={i.severity} /><span className="text-[10px] font-mono text-slate-500">{i.id}</span></div><span className="text-xs font-bold text-white tabular-nums">{i.riskMax}</span></div>
              <div className="text-xs font-semibold text-slate-200 mt-2 leading-snug">{i.title}</div>
              <div className="text-[10px] text-slate-500 mt-1">{i.findingIds.length} findings · {i.entities.length} entities · {fmtDur(i.end - i.start)}</div>
            </button>
          ))}
        </div>

        <div className="lg:col-span-2 space-y-5">
          <Card className="p-5">
            <div className="flex flex-wrap items-center gap-2 mb-2"><SeverityBadge s={inc.severity} /><Pill className="font-mono">{inc.id}</Pill><Pill>max priority {inc.riskMax}</Pill><Pill>{fmtTs(inc.start)} → {fmtTs(inc.end, false)}</Pill></div>
            <h2 className="text-lg font-bold text-white">{inc.title}</h2>
            <p className="text-xs text-slate-400 mt-2 leading-relaxed flex gap-2"><BookOpen className="w-4 h-4 shrink-0 text-sky-400" />{inc.narrative}</p>
          </Card>

          <Card className="p-5">
            <SectionTitle>ATT&CK tactic progression (hypothesis)</SectionTitle>
            <div className="flex flex-wrap items-stretch gap-1">
              {TACTICS.map((t, i) => {
                const hit = inc.tactics.includes(t);
                const n = fs.filter((f) => f.mitre.some((m) => m.tactic === t)).length;
                return (
                  <div key={t} className="flex items-center gap-1">
                    <div className={cx('px-3 py-2 rounded-lg border text-[11px] min-w-[110px]', hit ? 'border-rose-500/40 bg-rose-500/10 text-rose-200' : 'border-slate-800 text-slate-600')}>
                      <div className="font-semibold">{t}</div><div className="text-[10px] opacity-80">{hit ? `${n} finding${n > 1 ? 's' : ''}` : 'not observed'}</div>
                    </div>
                    {i < TACTICS.length - 1 && <ChevronRight className="w-3.5 h-3.5 text-slate-700" />}
                  </div>
                );
              })}
            </div>
          </Card>

          <div className="grid md:grid-cols-2 gap-5">
            <Card className="p-5">
              <SectionTitle icon={<Link2 className="w-4 h-4 text-indigo-400" />}>Why these were grouped</SectionTitle>
              <ul className="text-[11px] text-slate-400 space-y-1 list-disc pl-4">{inc.reasons.map((r, i) => <li key={i}>{r}</li>)}</ul>
            </Card>
            <Card className="p-5">
              <SectionTitle icon={<Users className="w-4 h-4 text-sky-400" />}>Entities</SectionTitle>
              <div className="flex flex-wrap gap-1">{inc.entities.map((e) => <button key={e} onClick={() => s.setInspect({ inspectHost: e })} className={cx('text-[11px] font-mono px-1.5 py-0.5 rounded border hover:border-sky-500/50', e === inc.pivot ? 'border-amber-500/40 text-amber-300 bg-amber-500/10' : 'border-slate-800 text-sky-300 bg-slate-950')}>{e}</button>)}</div>
              <p className="text-[10px] text-slate-500 mt-2">Highlighted: pivot entity shared by the most findings.</p>
            </Card>
          </div>

          <Card className="p-5">
            <SectionTitle right={run.incidents.length > 1 && (
              <div className="flex items-center gap-1.5">
                <Select value={mergeTarget} onChange={(e) => setMergeTarget(e.target.value)}><option value="">Merge with…</option>{run.incidents.filter((i) => i.id !== inc.id).map((i) => <option key={i.id} value={i.id}>{i.id}</option>)}</Select>
                <Btn size="sm" variant="secondary" disabled={!mergeTarget} onClick={merge}><Merge className="w-3.5 h-3.5" />Merge</Btn>
              </div>
            )}>Findings in sequence</SectionTitle>
            <div className="relative pl-5 space-y-3 before:absolute before:left-1.5 before:top-1 before:bottom-1 before:w-px before:bg-slate-800">
              {fs.sort((a, b) => a.evidence.tsRange[0] - b.evidence.tsRange[0]).map((f) => (
                <div key={f.id} className="relative">
                  <span className="absolute -left-[18px] top-3 w-2.5 h-2.5 rounded-full border-2 border-ink-800" style={{ background: { critical: '#fb7185', high: '#fbbf24', medium: '#facc15', low: '#38bdf8', informational: '#94a3b8' }[f.severity as Severity] }} />
                  <div className="p-3 rounded-lg border border-slate-800 bg-slate-950/50 flex gap-3 items-start">
                    <button className="flex-1 text-left min-w-0" onClick={() => s.setInspect({ inspectFindingId: f.id })}>
                      <div className="flex flex-wrap items-center gap-1.5"><span className="text-[10px] font-mono text-slate-500">{fmtTs(f.evidence.tsRange[0], false)}</span><SeverityBadge s={f.severity} /><StatusBadge s={f.status} /></div>
                      <div className="text-xs text-slate-200 mt-1 hover:text-sky-300">{f.title}</div>
                    </button>
                    <Btn size="sm" variant="ghost" title="Remove from incident (split)" onClick={() => split(f.id)}><Unlink className="w-3.5 h-3.5" /></Btn>
                  </div>
                </div>
              ))}
            </div>
          </Card>
        </div>
      </div>
    </div>
  );
}
