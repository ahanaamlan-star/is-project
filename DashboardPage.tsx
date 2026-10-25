import { Link, useNavigate } from 'react-router-dom';
import { ShieldAlert, Cpu, Network, FileText, ArrowUpRight, UploadCloud, Layers, HeartPulse, CheckCircle2, AlertTriangle, Sparkles, FolderPlus, Trash2, Download, Upload } from 'lucide-react';
import { useStore } from '../store/useStore';
import { Card, Stat, SectionTitle, SeverityBadge, Btn, EmptyState, Select, StatusBadge, Pill, Bar } from '../components/ui';
import { fmtBytes, fmtTs, fmtDur, download, SEV_ORDER, SEV_HEX } from '../lib/format';
import { useRef } from 'react';

export function DashboardPage() {
  const s = useStore();
  const nav = useNavigate();
  const importRef = useRef<HTMLInputElement>(null);
  const c = s.cases.find((x) => x.id === s.activeCaseId);
  const cap = s.captures.find((x) => x.id === s.activeCaptureId);
  const run = s.run;
  const events = s.events.filter((e) => e.caseId === s.activeCaseId);

  const importBundle = async (f: File) => {
    try { await s.importBundle(await f.text()); s.toast('success', 'Case bundle imported.'); }
    catch (e) { s.toast('error', e instanceof Error ? e.message : String(e)); }
  };

  if (!c) {
    return (
      <div className="max-w-3xl mx-auto mt-6 space-y-5">
        <EmptyState icon={<FolderPlus className="w-6 h-6" />} title="Start your first investigation"
          body="Create a case and ingest a PCAP/PCAPNG capture, or jump straight in with a synthetic multi-stage intrusion demo."
          action={<>
            <Btn onClick={() => nav('/app/ingest')}><Sparkles className="w-3.5 h-3.5" />Try a demo capture</Btn>
            <Btn variant="secondary" onClick={() => importRef.current?.click()}><Upload className="w-3.5 h-3.5" />Import case bundle</Btn>
          </>} />
        <input ref={importRef} type="file" accept=".json" className="hidden" onChange={(e) => e.target.files?.[0] && importBundle(e.target.files[0])} />
      </div>
    );
  }

  const active = run?.findings.filter((f) => !f.suppressed) || [];
  const triaged = active.filter((f) => f.status !== 'new').length;
  const top = active.filter((f) => f.status !== 'benign_false_positive').slice(0, 6);
  const sum = run?.summary;
  const coverage = sum ? sum.parsedPackets / Math.max(1, sum.totalPackets) : 0;
  const malformed = run ? (sum!.protocols.MALFORMED || 0) : 0;

  return (
    <div className="space-y-6">
      <div className="bg-gradient-to-r from-sky-950/40 via-slate-900 to-slate-900 border border-sky-900/30 p-5 md:p-6 rounded-xl relative overflow-hidden">
        <div className="absolute inset-0 grid-bg opacity-60 pointer-events-none" />
        <div className="relative flex flex-col md:flex-row md:items-start md:justify-between gap-4">
          <div>
            <div className="text-[11px] font-semibold uppercase tracking-wider text-sky-400 mb-1">Active forensics case</div>
            <h1 className="text-2xl font-extrabold text-white">{c.name}</h1>
            <p className="text-xs text-slate-400 mt-1 max-w-2xl leading-relaxed">{c.description || 'Investigation into suspicious traffic anomalies and protocol activity.'}</p>
            <div className="text-[11px] text-slate-500 mt-2">Owner <span className="text-slate-300">{c.owner}</span> · opened {fmtTs(Date.parse(c.createdAt) / 1000)}</div>
          </div>
          <div className="flex flex-wrap gap-2 items-center">
            <Select value={c.status} onChange={(e) => s.updateCase(c.id, { status: e.target.value as typeof c.status })} aria-label="Case status">
              <option value="open">Status: Open</option><option value="in_progress">Status: In progress</option><option value="closed">Status: Closed</option>
            </Select>
            <Btn size="sm" variant="secondary" onClick={async () => download(`${c.name.replace(/\W+/g, '_')}_bundle.json`, await s.exportBundle(), 'application/json')}><Download className="w-3.5 h-3.5" />Export case</Btn>
            <Btn size="sm" variant="secondary" onClick={() => importRef.current?.click()}><Upload className="w-3.5 h-3.5" />Import</Btn>
            <Btn size="sm" variant="danger" onClick={() => { if (confirm(`Delete case "${c.name}" with all captures, analyses and audit events from this browser?`)) s.deleteCase(c.id); }}><Trash2 className="w-3.5 h-3.5" /></Btn>
            <input ref={importRef} type="file" accept=".json" className="hidden" onChange={(e) => e.target.files?.[0] && importBundle(e.target.files[0])} />
          </div>
        </div>
      </div>

      <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
        <Stat label="Security findings" value={active.length} sub={`${run?.incidents.length || 0} correlated incidents`} icon={<ShieldAlert className="w-4 h-4" />} accent="text-rose-400" onClick={() => nav('/app/findings')} />
        <Stat label="Packets dissected" value={(sum?.parsedPackets ?? 0).toLocaleString()} sub={sum ? `${fmtBytes(sum.totalBytes)} over ${fmtDur(sum.duration)}` : 'Layer-by-layer decoding'} icon={<Cpu className="w-4 h-4" />} onClick={() => nav('/app/overview')} />
        <Stat label="Reconstructed flows" value={(sum?.totalFlows ?? 0).toLocaleString()} sub={sum ? `${sum.hostsInternal} internal · ${sum.hostsExternal} external hosts` : 'Bidirectional 5-tuples'} icon={<Network className="w-4 h-4" />} accent="text-amber-400" onClick={() => nav('/app/flows')} />
        <Stat label="Analyst audit events" value={events.length} sub={`${triaged}/${active.length} findings triaged`} icon={<FileText className="w-4 h-4" />} accent="text-emerald-400" onClick={() => nav('/app/notes')} />
      </div>

      {!run ? (
        <EmptyState icon={<UploadCloud className="w-6 h-6" />} title="No analysed capture yet" body="Upload a PCAP/PCAPNG capture to this case, or load one of the demo captures." action={<Btn onClick={() => nav('/app/ingest')}>Upload PCAP / PCAPNG</Btn>} />
      ) : (
        <div className="grid lg:grid-cols-3 gap-5">
          <Card className="p-5 lg:col-span-2">
            <SectionTitle icon={<ShieldAlert className="w-4 h-4 text-rose-400" />} right={<Link to="/app/findings" className="text-xs text-sky-400 hover:text-sky-300 flex items-center gap-1">All findings<ArrowUpRight className="w-3.5 h-3.5" /></Link>}>Priority queue</SectionTitle>
            {top.length === 0 ? <p className="text-xs text-slate-500">No open findings. 🎉 Absence of findings does not prove absence of activity.</p> : (
              <div className="space-y-2">
                {top.map((f) => (
                  <button key={f.id} onClick={() => s.setInspect({ inspectFindingId: f.id })} className="w-full text-left p-3 rounded-lg bg-slate-950/60 border border-slate-800 hover:border-sky-500/40 transition-colors flex items-center gap-3">
                    <div className="w-11 h-11 rounded-lg bg-slate-900 border border-slate-800 flex flex-col items-center justify-center shrink-0">
                      <span className="text-sm font-extrabold text-white tabular-nums leading-none">{f.risk?.score}</span><span className="text-[8px] text-slate-500 uppercase">priority</span>
                    </div>
                    <div className="min-w-0 flex-1">
                      <div className="flex items-center gap-1.5 flex-wrap"><SeverityBadge s={f.severity} /><StatusBadge s={f.status} />{f.incidentId && <Pill className="text-indigo-300">{f.incidentId}</Pill>}</div>
                      <div className="text-xs text-slate-200 mt-1 truncate">{f.title}</div>
                    </div>
                  </button>
                ))}
              </div>
            )}
            <div className="mt-4">
              <div className="flex justify-between text-[11px] text-slate-500 mb-1"><span>Triage progress</span><span>{triaged}/{active.length}</span></div>
              <Bar value={triaged} max={Math.max(1, active.length)} color="#34d399" />
            </div>
          </Card>

          <div className="space-y-5">
            <Card className="p-5">
              <SectionTitle icon={<Layers className="w-4 h-4 text-indigo-400" />}>Incidents</SectionTitle>
              {run.incidents.length === 0 ? <p className="text-xs text-slate-500">No correlated incidents.</p> : run.incidents.slice(0, 3).map((i) => (
                <button key={i.id} onClick={() => nav(`/app/incidents?id=${i.id}`)} className="w-full text-left p-3 rounded-lg border border-slate-800 hover:border-indigo-500/40 mb-2 bg-slate-950/50">
                  <div className="flex items-center gap-1.5"><SeverityBadge s={i.severity} /><span className="text-[10px] font-mono text-slate-500">{i.id} · {i.findingIds.length} findings</span></div>
                  <div className="text-xs text-slate-200 mt-1 leading-snug">{i.title}</div>
                  {i.tactics.length > 0 && <div className="text-[10px] text-slate-500 mt-1 truncate">{i.tactics.join(' → ')}</div>}
                </button>
              ))}
            </Card>
            <Card className="p-5">
              <SectionTitle icon={<HeartPulse className="w-4 h-4 text-emerald-400" />}>Evidence health</SectionTitle>
              <div className="space-y-2 text-xs">
                <div className="flex justify-between"><span className="text-slate-400">Packets analysed</span><span className="text-slate-200">{Math.round(coverage * 100)}%</span></div>
                <div className="flex justify-between"><span className="text-slate-400">Snaplen-truncated</span><span className="text-slate-200">{sum!.truncatedPackets.toLocaleString()}</span></div>
                <div className="flex justify-between"><span className="text-slate-400">Malformed packets</span><span className="text-slate-200">{malformed}</span></div>
                <div className="flex justify-between"><span className="text-slate-400">Parser warnings</span><span className={run.warnings.length ? 'text-amber-300' : 'text-emerald-300'}>{run.warnings.length}</span></div>
                <div className="flex gap-1 h-2 rounded overflow-hidden mt-2">{SEV_ORDER.map((sv) => (sum!.bySeverity[sv] ? <div key={sv} style={{ flex: sum!.bySeverity[sv], background: SEV_HEX[sv] }} title={`${sv}: ${sum!.bySeverity[sv]}`} /> : null))}</div>
                {run.warnings.slice(0, 2).map((w, i) => <div key={i} className="text-[10px] text-amber-300/80 flex gap-1.5 leading-relaxed"><AlertTriangle className="w-3 h-3 shrink-0 mt-0.5" />{w}</div>)}
                {!run.warnings.length && <div className="text-[10px] text-emerald-300/80 flex gap-1.5"><CheckCircle2 className="w-3 h-3" />No parse warnings.</div>}
              </div>
            </Card>
          </div>
        </div>
      )}

      <Card className="p-5">
        <SectionTitle right={<button onClick={() => nav('/app/ingest')} className="text-xs text-sky-400 hover:text-sky-300 flex items-center gap-1">Upload new capture<ArrowUpRight className="w-3.5 h-3.5" /></button>}>Current capture provenance & cryptographic record</SectionTitle>
        {cap ? (
          <div className="grid md:grid-cols-2 gap-3 text-xs font-mono bg-slate-950 p-4 rounded-lg border border-slate-800/80">
            <div><span className="text-slate-500">Original filename: </span><span className="text-slate-200 font-semibold break-all">{cap.filename}</span></div>
            <div><span className="text-slate-500">File size: </span><span className="text-slate-200">{fmtBytes(cap.size)} ({cap.format.toUpperCase()})</span></div>
            <div className="md:col-span-2"><span className="text-slate-500">SHA-256 digest: </span><span className="text-emerald-400 break-all select-all">{cap.sha256}</span></div>
            <div><span className="text-slate-500">Parser engine: </span><span className="text-sky-400">{run?.versions.parser || '—'}</span></div>
            <div><span className="text-slate-500">Ingested at: </span><span className="text-slate-300">{new Date(cap.uploadedAt).toLocaleString()}</span></div>
            <div><span className="text-slate-500">Provenance: </span><span className="text-slate-300">{cap.provenance.replace(/_/g, ' ')}</span></div>
            <div><span className="text-slate-500">Config hash: </span><span className="text-slate-300">{run?.configHash || '—'}</span></div>
          </div>
        ) : <p className="text-xs text-slate-500">No capture uploaded to this case yet.</p>}
      </Card>

      <div className="grid md:grid-cols-3 gap-4">
        {[
          ['findings', 'Explore detected findings', 'Transparent rule triggers, model signals and evidence-linked explanations.'],
          ['graph', 'Inspect host network graph', 'Force-directed topology of internal and external endpoints with alert overlays.'],
          ['reports', 'Export investigation report', 'HTML/PDF, JSON, CSV and STIX 2.1 with provenance and analyst sign-off.'],
        ].map(([to, t, d]) => (
          <button key={to} onClick={() => nav(`/app/${to}`)} className="p-4 rounded-xl bg-slate-900/60 border border-slate-800 hover:border-sky-500/40 text-left transition-all group">
            <div className="text-xs font-semibold text-slate-300 group-hover:text-sky-400 flex items-center justify-between"><span>{t}</span><ArrowUpRight className="w-4 h-4 text-slate-500 group-hover:text-sky-400" /></div>
            <p className="text-[11px] text-slate-500 mt-1">{d}</p>
          </button>
        ))}
      </div>
    </div>
  );
}
