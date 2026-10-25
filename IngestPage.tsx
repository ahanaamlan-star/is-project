import { useEffect, useRef, useState } from 'react';
import { useNavigate, useSearchParams } from 'react-router-dom';
import { UploadCloud, CheckCircle2, AlertTriangle, Play, Shield, FileCheck, Trash2, RefreshCw, Database, Sparkles, Lock, Hash, FileWarning } from 'lucide-react';
import { useStore, type Provenance, type CaptureRec } from '../store/useStore';
import { Card, PageHeader, Btn, Select, SectionTitle, Pill, cx } from '../components/ui';
import { fmtBytes, fmtTs } from '../lib/format';
import { SAMPLES, fetchSample } from '../lib/samples';

const PROV: Array<[Provenance, string]> = [
  ['synthetic', 'Synthetic / generated'], ['public_dataset', 'Public benchmark dataset'], ['authorized_lab', 'Authorised isolated lab'],
  ['production_authorized', 'Production (authorised capture)'], ['unknown', 'Unknown / not stated'],
];

export function IngestPage() {
  const s = useStore();
  const nav = useNavigate();
  const [drag, setDrag] = useState(false);
  const [prov, setProv] = useState<Provenance>('authorized_lab');
  const [runMl, setRunMl] = useState(s.config.runML);
  const [busy, setBusy] = useState<string | null>(null);
  const [err, setErr] = useState<string | null>(null);
  const fileRef = useRef<HTMLInputElement>(null);
  const [params, setParams] = useSearchParams();
  const demoStarted = useRef(false);
  const caps = s.captures.filter((c) => c.caseId === s.activeCaseId).sort((a, b) => b.uploadedAt.localeCompare(a.uploadedAt));
  const current = caps.find((c) => c.id === s.activeCaptureId);

  const ensureCase = async (hint: string) => {
    if (!useStore.getState().activeCaseId) await s.createCase(hint, 'Created automatically from the ingestion page.');
  };

  const analyse = async (cap: CaptureRec) => {
    setErr(null);
    try {
      const r = await s.analyzeCapture(cap.id, { ...useStore.getState().config, runML: runMl });
      const n = r.findings.filter((f) => !f.suppressed).length;
      s.toast('success', `Analysis complete: ${r.summary.parsedPackets.toLocaleString()} packets, ${r.flows.length} flows, ${n} findings, ${r.incidents.length} incident${r.incidents.length === 1 ? '' : 's'}.`);
      nav('/app/overview');
    } catch (e) {
      setErr(e instanceof Error ? e.message : String(e));
    }
  };

  const handleFiles = async (files: FileList | File[]) => {
    setErr(null);
    const list = [...files];
    if (!list.length) return;
    await ensureCase(`Investigation ${new Date().toISOString().slice(0, 10)}`);
    let last: CaptureRec | null = null;
    for (const f of list) {
      setBusy(`Validating & hashing ${f.name}…`);
      try { last = await s.ingestFile(f, prov); }
      catch (e) { setErr(`${f.name}: ${e instanceof Error ? e.message : String(e)}`); }
    }
    setBusy(null);
    if (last && list.length === 1) await analyse(last);
    else if (last) s.toast('success', `${list.length} captures ingested. Analyse each from the list below.`);
  };

  const loadSample = async (file: string, title: string) => {
    setErr(null);
    setBusy(`Loading ${file}…`);
    try {
      await ensureCase(`Demo — ${title}`);
      const buffer = await fetchSample(file);
      const cap = await s.ingestFile({ name: file, buffer }, 'synthetic');
      setBusy(null);
      await analyse(cap);
    } catch (e) {
      setErr(e instanceof Error ? e.message : String(e));
    } finally { setBusy(null); }
  };

  useEffect(() => {
    if (params.get('demo') && s.ready && !demoStarted.current) {
      demoStarted.current = true;
      setParams({});
      const sm = SAMPLES.find((x) => x.file.startsWith(params.get('demo')!)) || SAMPLES[0];
      loadSample(sm.file, sm.title);
    }
  }, [s.ready]); // eslint-disable-line

  return (
    <div className="max-w-6xl mx-auto">
      <PageHeader title="PCAP / PCAPNG Ingestion" subtitle="Captures are validated by magic bytes, hashed with SHA-256 and parsed in an isolated Web Worker inside this browser. Nothing is uploaded — the original bytes are stored only in this browser's IndexedDB so you can re-analyse with new settings." />

      {err && (
        <div className="mb-4 p-3.5 rounded-lg bg-rose-500/10 border border-rose-500/30 text-rose-300 text-xs flex items-start gap-2"><AlertTriangle className="w-4 h-4 shrink-0 mt-0.5" /><span className="leading-relaxed">{err}</span></div>
      )}

      <div className="grid lg:grid-cols-5 gap-5">
        <div className="lg:col-span-3 space-y-5">
          <div
            onDragOver={(e) => { e.preventDefault(); setDrag(true); }} onDragLeave={() => setDrag(false)}
            onDrop={(e) => { e.preventDefault(); setDrag(false); handleFiles(e.dataTransfer.files); }}
            className={cx('relative overflow-hidden p-8 md:p-10 rounded-xl border-2 border-dashed text-center transition-colors', drag ? 'border-sky-400 bg-sky-500/10' : 'border-slate-700 bg-slate-900/60 hover:border-sky-500/50')}>
            {(busy || s.progress) && <div className="absolute inset-x-0 top-0 h-16 bg-gradient-to-b from-sky-400/20 to-transparent animate-scan pointer-events-none" />}
            <UploadCloud className="w-12 h-12 text-sky-400 mx-auto mb-3" />
            <h3 className="text-sm font-semibold text-slate-200">Drop PCAP / PCAPNG files here</h3>
            <p className="text-xs text-slate-400 mt-1 max-w-md mx-auto">Wireshark, tcpdump, dumpcap, tshark exports. Ethernet, Linux SLL/SLL2, loopback and raw-IP link types. Up to {s.config.maxFileMB} MB per file (configurable).</p>
            <div className="mt-5 flex flex-wrap justify-center items-center gap-3">
              <Btn onClick={() => fileRef.current?.click()} disabled={!!busy || !!s.progress}><FileCheck className="w-4 h-4" />Browse capture files</Btn>
              <input ref={fileRef} type="file" multiple accept=".pcap,.pcapng,.cap,.dmp,application/vnd.tcpdump.pcap" className="hidden" onChange={(e) => { if (e.target.files) handleFiles(e.target.files); e.target.value = ''; }} />
            </div>
            <div className="mt-5 grid sm:grid-cols-2 gap-3 text-left max-w-lg mx-auto">
              <label className="text-[11px] text-slate-400">Data provenance
                <Select value={prov} onChange={(e) => setProv(e.target.value as Provenance)} className="w-full mt-1">{PROV.map(([v, l]) => <option key={v} value={v}>{l}</option>)}</Select>
              </label>
              <label className="text-[11px] text-slate-400 flex items-center justify-between gap-2 bg-slate-950 border border-slate-800 rounded-lg px-3 mt-[18px]">
                <span>Isolation Forest anomaly layer</span>
                <input type="checkbox" checked={runMl} onChange={(e) => setRunMl(e.target.checked)} className="w-4 h-4" />
              </label>
            </div>
            {(busy || s.progress) && (
              <div className="mt-5 max-w-md mx-auto text-left">
                <div className="flex justify-between text-[11px] text-sky-300 mb-1"><span>{busy || s.progress?.stage}</span>{s.progress && <span>{Math.round(s.progress.pct * 100)}%</span>}</div>
                <div className="h-1.5 bg-slate-800 rounded-full overflow-hidden"><div className="h-full bg-sky-500 transition-all" style={{ width: `${s.progress ? Math.max(4, s.progress.pct * 100) : 15}%` }} /></div>
                {s.progress?.detail && <div className="text-[10px] text-slate-500 mt-1">{s.progress.detail}</div>}
              </div>
            )}
          </div>

          {current && (
            <Card className="p-5 border-emerald-500/30 space-y-4">
              <div className="flex items-center justify-between flex-wrap gap-2">
                <div className="flex items-center gap-2 text-emerald-400 text-xs font-bold uppercase tracking-wider"><CheckCircle2 className="w-4 h-4" />Active capture — verified</div>
                <Pill>{current.provenance.replace(/_/g, ' ')}</Pill>
              </div>
              <div className="grid sm:grid-cols-2 gap-3 text-xs font-mono bg-slate-950 p-4 rounded-lg border border-slate-800">
                <div><span className="text-slate-500">Filename: </span><span className="text-slate-200 break-all">{current.filename}</span></div>
                <div><span className="text-slate-500">Size: </span><span className="text-slate-200">{fmtBytes(current.size)} · {current.format.toUpperCase()}</span></div>
                <div className="sm:col-span-2"><span className="text-slate-500">SHA-256: </span><span className="text-emerald-400 break-all select-all">{current.sha256}</span></div>
                {current.packetCount != null && <div><span className="text-slate-500">Packets: </span><span className="text-slate-200">{current.packetCount.toLocaleString()}</span></div>}
                {current.start && <div><span className="text-slate-500">Window: </span><span className="text-slate-200">{fmtTs(current.start)}</span></div>}
              </div>
              <Btn variant="success" className="w-full !py-3 uppercase tracking-wider" disabled={!!s.progress} onClick={() => analyse(current)}>
                {s.progress ? <><RefreshCw className="w-4 h-4 animate-spin" />Running dissection & detection engine…</> : <><Play className="w-4 h-4 fill-white" />{current.lastRunId ? 'Re-run forensic analysis' : 'Execute forensic analysis'}</>}
              </Btn>
            </Card>
          )}

          <Card className="p-5">
            <SectionTitle icon={<Database className="w-4 h-4 text-sky-400" />}>Captures in this case ({caps.length})</SectionTitle>
            {caps.length === 0 ? <p className="text-xs text-slate-500">No captures yet.</p> : (
              <div className="space-y-2">
                {caps.map((c) => (
                  <div key={c.id} className={cx('p-3 rounded-lg border flex flex-col md:flex-row md:items-center gap-3 justify-between', c.id === s.activeCaptureId ? 'border-sky-500/40 bg-sky-500/5' : 'border-slate-800 bg-slate-950/50')}>
                    <div className="min-w-0">
                      <div className="text-xs font-semibold text-slate-200 truncate">{c.filename}</div>
                      <div className="text-[10px] text-slate-500 font-mono truncate">{fmtBytes(c.size)} · {c.format} · sha256 {c.sha256.slice(0, 16)}… · {c.lastRunId ? `${c.findingsCount ?? 0} findings` : 'not analysed'}</div>
                    </div>
                    <div className="flex gap-1.5 shrink-0">
                      {c.id !== s.activeCaptureId && <Btn size="sm" variant="secondary" onClick={() => s.selectCapture(c.id)}>Set active</Btn>}
                      <Btn size="sm" variant="secondary" disabled={!!s.progress} onClick={() => analyse(c)}><Play className="w-3 h-3" />{c.lastRunId ? 'Re-run' : 'Analyse'}</Btn>
                      <Btn size="sm" variant="danger" onClick={() => { if (confirm(`Permanently delete ${c.filename} and its analysis from this browser?`)) s.deleteCapture(c.id); }} aria-label="Delete capture"><Trash2 className="w-3 h-3" /></Btn>
                    </div>
                  </div>
                ))}
              </div>
            )}
          </Card>
        </div>

        <div className="lg:col-span-2 space-y-5">
          <Card className="p-5">
            <SectionTitle icon={<Sparkles className="w-4 h-4 text-amber-400" />}>Demo captures (synthetic)</SectionTitle>
            <p className="text-[11px] text-slate-500 mb-3 leading-relaxed">Clearly-labelled synthetic traffic generated for demonstration. One click loads, hashes and analyses the file.</p>
            <div className="space-y-2">
              {SAMPLES.map((x) => (
                <button key={x.file} disabled={!!busy || !!s.progress} onClick={() => loadSample(x.file, x.title)} className="w-full text-left p-3 rounded-lg border border-slate-800 bg-slate-950/50 hover:border-sky-500/40 transition-colors disabled:opacity-50 group">
                  <div className="flex items-center justify-between gap-2">
                    <span className="text-xs font-semibold text-slate-200 group-hover:text-sky-300">{x.title}</span>
                    <span className={cx('text-[9px] px-1.5 py-0.5 rounded border font-bold uppercase', x.benign ? 'text-emerald-300 border-emerald-500/30' : 'text-rose-300 border-rose-500/30')}>{x.benign ? 'benign' : 'suspicious'}</span>
                  </div>
                  <div className="text-[10px] text-slate-500 mt-1 leading-relaxed line-clamp-2">{x.description}</div>
                  <div className="text-[10px] font-mono text-slate-600 mt-1">{x.file}</div>
                </button>
              ))}
            </div>
          </Card>
          <Card className="p-5 text-[11px] text-slate-400 leading-relaxed space-y-2.5">
            <SectionTitle icon={<Shield className="w-4 h-4 text-sky-400" />}>Safe handling</SectionTitle>
            <div className="flex gap-2"><Lock className="w-3.5 h-3.5 text-emerald-400 shrink-0 mt-0.5" /><span>Processing is local: no capture bytes, metadata or findings leave the browser. There is no backend.</span></div>
            <div className="flex gap-2"><Hash className="w-3.5 h-3.5 text-emerald-400 shrink-0 mt-0.5" /><span>SHA-256 is computed on ingest and recorded in every report and audit event for chain-of-custody.</span></div>
            <div className="flex gap-2"><FileWarning className="w-3.5 h-3.5 text-emerald-400 shrink-0 mt-0.5" /><span>Captures are treated as untrusted input: bounds-checked parsing, size and packet limits, malformed packets recorded rather than dropped.</span></div>
            <div className="flex gap-2"><Shield className="w-3.5 h-3.5 text-emerald-400 shrink-0 mt-0.5" /><span>Only analyse traffic you are authorised to inspect. Credentials are detected but never stored.</span></div>
          </Card>
        </div>
      </div>
    </div>
  );
}
