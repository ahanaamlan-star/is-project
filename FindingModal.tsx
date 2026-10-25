import { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import { FileSearch, AlertOctagon, UserCheck, CheckCircle2, HelpCircle, ShieldAlert, Eye, Brain, ListChecks, Shuffle, Ban, Target, Tag, Layers } from 'lucide-react';
import { useStore } from '../store/useStore';
import { Modal, SeverityBadge, StatusBadge, ConfidenceBadge, Pill, Btn, Textarea, Input, cx, Bar } from './ui';
import { fmtTs, humanize } from '../lib/format';
import type { FindingStatus } from '../engine/types';

const COMP_LABEL: Record<string, string> = { severity: 'Rule severity', anomaly: 'Anomaly magnitude', evidence: 'Evidence strength', corroboration: 'Corroboration', context: 'Asset context' };

export function FindingModal() {
  const { run, inspectFindingId, setInspect, updateFinding, events, addNote, toast } = useStore();
  const nav = useNavigate();
  const f = run?.findings.find((x) => x.id === inspectFindingId) || null;
  const [note, setNote] = useState('');
  const [tag, setTag] = useState('');
  useEffect(() => { setNote(''); setTag(''); }, [inspectFindingId]);
  if (!f) return null;
  const close = () => setInspect({ inspectFindingId: null });
  const ev = f.evidence;
  const history = events.filter((e) => e.findingId === f.id);

  const dispose = async (status: FindingStatus) => {
    await updateFinding(f.id, { status }, note || undefined);
    setNote('');
    toast('success', `${f.id} marked ${humanize(status)} — recorded in audit trail.`);
  };

  const Section = ({ icon, title, children, tone }: { icon: React.ReactNode; title: string; children: React.ReactNode; tone?: string }) => (
    <div className={cx('rounded-lg border p-4', tone || 'bg-slate-900/60 border-slate-800')}>
      <h3 className="text-[11px] font-bold uppercase tracking-wider text-slate-400 mb-2 flex items-center gap-1.5">{icon}{title}</h3>
      {children}
    </div>
  );
  const List = ({ items }: { items: string[] }) => items.length ? <ul className="space-y-1 text-xs text-slate-300 list-disc pl-4 leading-relaxed">{items.map((x, i) => <li key={i}>{x}</li>)}</ul> : <p className="text-xs text-slate-500">None.</p>;

  return (
    <Modal open onClose={close} wide header={
      <div>
        <div className="flex flex-wrap items-center gap-1.5 mb-2">
          <SeverityBadge s={f.severity} />
          <StatusBadge s={f.status} />
          <ConfidenceBadge c={f.confidence} />
          <Pill>{humanize(f.category)}</Pill>
          <Pill className="font-mono text-sky-300 bg-sky-950 border-sky-800">{f.detectorId} v{f.detectorVersion}</Pill>
          <Pill className={f.source === 'rule' ? 'text-emerald-300' : f.source === 'model' ? 'text-fuchsia-300' : 'text-indigo-300'}>{f.source} layer</Pill>
          {f.suppressed && <Pill className="text-slate-400">allowlisted</Pill>}
        </div>
        <h2 className="text-base md:text-lg font-bold text-white leading-snug">{f.title}</h2>
        <div className="text-[11px] text-slate-500 font-mono mt-1">{f.id} · {fmtTs(ev.tsRange[0])} → {fmtTs(ev.tsRange[1], false)}</div>
      </div>
    }>
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
        <div className="lg:col-span-2 space-y-4">
          <Section icon={<FileSearch className="w-4 h-4 text-sky-400" />} title="Finding">
            <p className="text-sm text-slate-200 leading-relaxed">{f.explanation.summary}</p>
          </Section>
          <div className="grid md:grid-cols-2 gap-4">
            <Section icon={<Eye className="w-4 h-4 text-emerald-400" />} title="Observed facts (from capture)"><List items={f.explanation.observedFacts} /></Section>
            <Section icon={<Target className="w-4 h-4 text-amber-400" />} title={f.source === 'rule' ? 'Rule evidence' : 'Detection rationale'}>
              <List items={f.explanation.ruleEvidence} />
              {f.explanation.modelSignal && <p className="mt-2 text-xs text-fuchsia-200/90 bg-fuchsia-500/5 border border-fuchsia-500/20 rounded p-2 leading-relaxed"><b>Model signal:</b> {f.explanation.modelSignal}</p>}
            </Section>
          </div>

          <div className="grid md:grid-cols-2 gap-4">
            <div className="bg-slate-900/60 p-4 rounded-lg border border-slate-800">
              <div className="text-[11px] font-bold text-slate-400 uppercase tracking-wider mb-2">Observed telemetry values</div>
              <div className="space-y-1 font-mono text-[11px]">
                {Object.entries(ev.observed).map(([k, v]) => (
                  <div key={k} className="flex justify-between gap-2 border-b border-slate-800/50 pb-1"><span className="text-slate-500">{k}</span><span className="text-sky-300 font-semibold text-right break-all">{typeof v === 'object' ? JSON.stringify(v) : String(v)}</span></div>
                ))}
              </div>
            </div>
            <div className="bg-slate-900/60 p-4 rounded-lg border border-slate-800">
              <div className="text-[11px] font-bold text-slate-400 uppercase tracking-wider mb-2">Thresholds applied</div>
              <div className="space-y-1 font-mono text-[11px]">
                {Object.entries(ev.thresholds).map(([k, v]) => (
                  <div key={k} className="flex justify-between gap-2 border-b border-slate-800/50 pb-1"><span className="text-slate-500">{k}</span><span className="text-slate-200 text-right break-all">{typeof v === 'object' ? JSON.stringify(v) : String(v)}</span></div>
                ))}
              </div>
            </div>
          </div>

          {ev.contributions && (
            <Section icon={<Brain className="w-4 h-4 text-fuchsia-400" />} title="Feature attribution (approximate, path-based — not SHAP)">
              <div className="space-y-1.5">
                {ev.contributions.slice(0, 7).map((c) => (
                  <div key={c.feature} className="grid grid-cols-12 gap-2 items-center text-[11px]">
                    <span className="col-span-4 font-mono text-slate-300 truncate">{c.feature}</span>
                    <div className="col-span-4"><Bar value={c.share} max={ev.contributions![0].share} color="#e879f9" /></div>
                    <span className="col-span-4 text-slate-400 font-mono text-right">{c.observed} <span className="text-slate-600">vs</span> {c.baseline} <span className="text-slate-600">(z {c.z})</span></span>
                  </div>
                ))}
              </div>
            </Section>
          )}

          <Section icon={<Brain className="w-4 h-4 text-sky-400" />} title="Interpretation (hypothesis)"><p className="text-xs text-slate-300 leading-relaxed">{f.explanation.interpretation}</p></Section>
          <div className="grid md:grid-cols-2 gap-4">
            <Section icon={<Shuffle className="w-4 h-4 text-indigo-400" />} title="Alternative explanations"><List items={f.explanation.alternatives} /></Section>
            <Section icon={<ListChecks className="w-4 h-4 text-emerald-400" />} title="Next analyst checks"><List items={f.explanation.nextChecks} /></Section>
          </div>
          <Section icon={<AlertOctagon className="w-4 h-4 text-amber-400" />} title="Limitations & caveats" tone="bg-amber-950/20 border-amber-900/40">
            <List items={[f.caveats, ...f.explanation.limitations]} />
            <p className="text-[11px] text-slate-500 italic mt-2">Score type <b className="text-slate-300">{f.scoreType}</b> = {f.score}. Per NetSentry XAI design principles this is a relative indicator, not a confirmed-attack probability. Human oversight is mandatory.</p>
          </Section>
        </div>

        <div className="space-y-4">
          <div className="bg-slate-900 p-4 rounded-lg border border-slate-800">
            <div className="flex items-center justify-between mb-2">
              <span className="text-[11px] font-bold uppercase tracking-wider text-slate-400">Priority score</span>
              <span className="text-2xl font-extrabold text-white tabular-nums">{f.risk?.score}<span className="text-xs text-slate-500">/100</span></span>
            </div>
            <div className="space-y-2">
              {f.risk && Object.entries(f.risk.components).map(([k, v]) => (
                <div key={k}>
                  <div className="flex justify-between text-[11px] text-slate-400"><span>{COMP_LABEL[k]} <span className="text-slate-600">× {(f.risk!.weights as unknown as Record<string, number>)[k]}</span></span><span className="font-mono text-slate-300">{v}</span></div>
                  <Bar value={v} color="#38bdf8" />
                </div>
              ))}
            </div>
            <p className="text-[10px] text-slate-500 mt-2 leading-relaxed">Transparent weighted sum of normalised components (weights configurable in Settings). A ranking aid — not a calibrated probability.</p>
          </div>

          <div className="bg-slate-900/60 p-4 rounded-lg border border-slate-800 space-y-3">
            <div className="text-[11px] font-bold uppercase tracking-wider text-slate-400">Traceable evidence</div>
            {ev.entities.length > 0 && (
              <div><div className="text-[10px] text-slate-500 mb-1">Entities</div><div className="flex flex-wrap gap-1">
                {ev.entities.slice(0, 14).map((e) => <button key={e} onClick={() => setInspect({ inspectHost: e })} className="text-[11px] font-mono px-1.5 py-0.5 rounded bg-slate-950 border border-slate-800 text-sky-300 hover:border-sky-500/50">{e}</button>)}
              </div></div>
            )}
            {ev.flowIds.length > 0 && (
              <div><div className="text-[10px] text-slate-500 mb-1">Flows ({ev.flowIds.length})</div><div className="flex flex-wrap gap-1">
                {ev.flowIds.slice(0, 20).map((id) => <button key={id} onClick={() => setInspect({ inspectFlowId: id })} className="text-[11px] font-mono px-1.5 py-0.5 rounded bg-slate-950 border border-slate-800 text-indigo-300 hover:border-indigo-500/50">{id}</button>)}
              </div></div>
            )}
            {ev.packetIdx.length > 0 && (
              <div><div className="text-[10px] text-slate-500 mb-1">Packets ({ev.packetIdx.length})</div><div className="flex flex-wrap gap-1">
                {ev.packetIdx.slice(0, 24).map((p) => <button key={p} onClick={() => setInspect({ inspectPacket: p })} className="text-[11px] font-mono px-1.5 py-0.5 rounded bg-slate-950 border border-slate-800 text-emerald-300 hover:border-emerald-500/50">#{p}</button>)}
              </div></div>
            )}
            <Btn size="sm" variant="secondary" className="w-full" onClick={() => { close(); nav(`/app/flows?finding=${f.id}`); }}>Open evidence in Packets & Flows</Btn>
          </div>

          {f.mitre.length > 0 && (
            <div className="bg-slate-900/60 p-4 rounded-lg border border-slate-800">
              <div className="text-[11px] font-bold uppercase tracking-wider text-slate-400 mb-2">MITRE ATT&CK (hypothesis)</div>
              <div className="space-y-1.5">
                {f.mitre.map((m) => (
                  <div key={m.id} className="text-[11px]"><span className="font-mono text-rose-300">{m.id}</span> <span className="text-slate-300">{m.name}</span><div className="text-slate-500">{m.tactic}</div></div>
                ))}
              </div>
              <p className="text-[10px] text-slate-500 mt-2">Mapped from observable patterns only; not attribution.</p>
            </div>
          )}

          {f.incidentId && (
            <button onClick={() => { close(); nav(`/app/incidents?id=${f.incidentId}`); }} className="w-full text-left bg-indigo-500/10 border border-indigo-500/30 rounded-lg p-3 text-xs text-indigo-200 hover:bg-indigo-500/15">
              <div className="flex items-center gap-1.5 font-semibold"><Layers className="w-3.5 h-3.5" />Part of {f.incidentId}</div>
              <div className="text-[11px] text-indigo-300/70 mt-0.5">{run?.incidents.find((i) => i.id === f.incidentId)?.title}</div>
            </button>
          )}
        </div>
      </div>

      <div className="mt-5 bg-slate-900 p-4 md:p-5 rounded-lg border border-slate-800 space-y-3">
        <div className="flex flex-wrap items-center justify-between gap-2">
          <h3 className="text-xs font-bold uppercase tracking-wider text-slate-200 flex items-center gap-1.5"><UserCheck className="w-4 h-4 text-sky-400" />Analyst oversight & disposition</h3>
          <div className="flex items-center gap-2">
            <span className="text-[11px] text-slate-500">Assignee</span>
            <Input defaultValue={f.assignee || ''} placeholder="unassigned" className="w-32" onBlur={(e) => e.target.value !== (f.assignee || '') && updateFinding(f.id, { assignee: e.target.value })} />
          </div>
        </div>
        <Textarea rows={2} value={note} onChange={(e) => setNote(e.target.value)} placeholder="Justification for the disposition, or a triage note…" />
        <div className="flex flex-wrap gap-2">
          <Btn size="sm" variant="secondary" className="!text-emerald-300 !border-emerald-500/30" onClick={() => dispose('benign_false_positive')}><CheckCircle2 className="w-3.5 h-3.5" />Benign / false positive</Btn>
          <Btn size="sm" variant="secondary" className="!text-yellow-300 !border-yellow-500/30" onClick={() => dispose('under_review')}><HelpCircle className="w-3.5 h-3.5" />Under review</Btn>
          <Btn size="sm" variant="secondary" className="!text-amber-300 !border-amber-500/30" onClick={() => dispose('suspicious')}><AlertOctagon className="w-3.5 h-3.5" />Suspicious</Btn>
          <Btn size="sm" variant="secondary" className="!text-rose-300 !border-rose-500/30" onClick={() => dispose('escalated')}><ShieldAlert className="w-3.5 h-3.5" />Escalate</Btn>
          <Btn size="sm" variant="ghost" disabled={!note.trim()} onClick={async () => { await addNote(note.trim(), f.id); setNote(''); toast('success', 'Note added to audit trail'); }}>Add note only</Btn>
        </div>
        <div className="flex flex-wrap items-center gap-1.5 pt-1">
          <Tag className="w-3.5 h-3.5 text-slate-500" />
          {f.tags.map((t) => (
            <button key={t} onClick={() => updateFinding(f.id, { tags: f.tags.filter((x) => x !== t) })} className="text-[10px] px-2 py-0.5 rounded-full bg-sky-500/10 text-sky-300 border border-sky-500/30 hover:line-through" title="Remove tag">{t}</button>
          ))}
          <form onSubmit={(e) => { e.preventDefault(); const t = tag.trim().toLowerCase(); if (t && !f.tags.includes(t)) updateFinding(f.id, { tags: [...f.tags, t] }); setTag(''); }}>
            <Input value={tag} onChange={(e) => setTag(e.target.value)} placeholder="+ tag" className="w-24 !py-0.5" />
          </form>
        </div>
        {history.length > 0 && (
          <div className="border-t border-slate-800 pt-3 space-y-1.5">
            <div className="text-[10px] uppercase tracking-wider text-slate-500 font-bold">History</div>
            {history.slice(0, 8).map((h) => (
              <div key={h.id} className="text-[11px] text-slate-400"><span className="font-mono text-slate-600">{h.ts.slice(0, 19).replace('T', ' ')}</span> · <span className="text-slate-300">{h.actor}</span> · {h.action}{h.next ? ` → ${humanize(h.next)}` : ''} — {h.note}</div>
            ))}
          </div>
        )}
      </div>
      {f.status === 'benign_false_positive' && <div className="mt-3 text-[11px] text-slate-500 flex items-center gap-1.5"><Ban className="w-3.5 h-3.5" />Dismissed findings are retained for audit and excluded from reports by default.</div>}
    </Modal>
  );
}
