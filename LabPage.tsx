import { useRef, useState } from 'react';
import { FlaskConical, Play, CheckCircle2, XCircle, Upload, Download, Info } from 'lucide-react';
import { useStore } from '../store/useStore';
import { Card, PageHeader, SectionTitle, Btn, Pill, cx, Select } from '../components/ui';
import { SAMPLES, fetchSample, type SampleCapture } from '../lib/samples';
import { runAnalysis } from '../store/engineClient';
import { DETECTORS } from '../engine/detectors';
import { download } from '../lib/format';
import type { AnalysisConfig } from '../engine/types';

type Mode = 'rules' | 'anomaly' | 'hybrid';
interface Row { scenario: string; benign: boolean; packets: number; flows: number; fired: string[]; expected: string[]; tp: number; fp: number; fn: number; alarm: boolean; findings: number; ms: number }
interface ModeResult { rows: Row[]; precision: number; recall: number; f1: number; scenarioDetect: number; benignAlarmRate: number; fpPerCapture: number; ms: number }

const MODE_LABEL: Record<Mode, string> = { rules: 'Rules only', anomaly: 'Anomaly only (statistical + IF)', hybrid: 'Hybrid (all layers)' };

function cfgFor(base: AnalysisConfig, m: Mode): AnalysisConfig {
  return { ...base, runRules: m !== 'anomaly', runStatistical: m !== 'rules', runML: m !== 'rules' };
}

export default function LabPage() {
  const s = useStore();
  const [custom, setCustom] = useState<Array<SampleCapture & { buffer: ArrayBuffer }>>([]);
  const [results, setResults] = useState<Partial<Record<Mode, ModeResult>>>({});
  const [busy, setBusy] = useState<string | null>(null);
  const [view, setView] = useState<Mode>('hybrid');
  const fileRef = useRef<HTMLInputElement>(null);
  const [pendingExpected, setPendingExpected] = useState<string>('');

  const runAll = async () => {
    const out: Partial<Record<Mode, ModeResult>> = {};
    const bufs = new Map<string, ArrayBuffer>();
    for (const sc of SAMPLES) { setBusy(`Fetching ${sc.file}…`); bufs.set(sc.file, await fetchSample(sc.file)); }
    for (const c of custom) bufs.set(c.file, c.buffer);
    const scenarios: SampleCapture[] = [...SAMPLES, ...custom];
    for (const m of ['rules', 'anomaly', 'hybrid'] as Mode[]) {
      const rows: Row[] = [];
      for (const sc of scenarios) {
        setBusy(`${MODE_LABEL[m]} · ${sc.file}`);
        const t = performance.now();
        const { result } = await runAnalysis(bufs.get(sc.file)!.slice(0), { runId: 'lab', captureId: 'lab', caseId: 'lab' }, cfgFor(s.config, m));
        const ms = performance.now() - t;
        const fired = [...new Set(result.findings.map((f) => f.detectorId))];
        const expected = m === 'anomaly' ? [] : sc.expected;
        const tp = expected.filter((d) => fired.includes(d)).length;
        const fn = expected.length - tp;
        const fp = fired.filter((d) => !sc.expected.includes(d) && !sc.allowed.includes(d)).length;
        const alarm = m === 'anomaly' ? result.findings.length > 0 : result.findings.some((f) => !sc.allowed.includes(f.detectorId) || sc.expected.includes(f.detectorId));
        rows.push({ scenario: sc.file, benign: sc.benign, packets: result.summary.parsedPackets, flows: result.flows.length, fired, expected, tp, fp, fn, alarm, findings: result.findings.length, ms: Math.round(ms) });
      }
      const TP = rows.reduce((a, r) => a + r.tp, 0), FP = rows.reduce((a, r) => a + r.fp, 0), FN = rows.reduce((a, r) => a + r.fn, 0);
      const susp = rows.filter((r) => !r.benign), ben = rows.filter((r) => r.benign);
      const precision = m === 'anomaly' ? (rows.filter((r) => r.alarm && !r.benign).length / Math.max(1, rows.filter((r) => r.alarm).length)) : TP / Math.max(1, TP + FP);
      const recall = m === 'anomaly' ? susp.filter((r) => r.alarm).length / Math.max(1, susp.length) : TP / Math.max(1, TP + FN);
      out[m] = {
        rows, precision, recall, f1: (2 * precision * recall) / Math.max(1e-9, precision + recall),
        scenarioDetect: susp.filter((r) => r.alarm).length / Math.max(1, susp.length),
        benignAlarmRate: ben.filter((r) => r.alarm).length / Math.max(1, ben.length),
        fpPerCapture: (m === 'anomaly' ? ben.reduce((a, r) => a + r.findings, 0) : FP) / Math.max(1, m === 'anomaly' ? ben.length : rows.length),
        ms: rows.reduce((a, r) => a + r.ms, 0),
      };
      setResults({ ...out });
    }
    setBusy(null);
    await s.log('evaluation', `Evaluation lab run over ${scenarios.length} scenarios (config ${JSON.stringify(cfgFor(s.config, 'hybrid').thresholds).length} chars)`);
  };

  const addCustom = async (f: File) => {
    const buffer = await f.arrayBuffer();
    const expected = pendingExpected ? [pendingExpected] : [];
    setCustom([...custom, { file: f.name, title: f.name, description: 'User-labelled capture', expected, allowed: ['ml_isolation_forest_flow', 'stat_host_volume_outlier'], benign: expected.length === 0, buffer }]);
  };

  const r = results[view];
  const pct = (x: number) => `${(x * 100).toFixed(1)}%`;

  return (
    <div className="space-y-5">
      <PageHeader title="Evaluation Lab" subtitle="Replay labelled captures through the engine and compare rules-only, anomaly-only and hybrid detection. Metrics are measured live in your browser against the scenarios' documented ground truth — no claimed numbers."
        right={<>
          {Object.keys(results).length > 0 && <Btn variant="secondary" size="sm" onClick={() => download('netsentry_evaluation.json', JSON.stringify({ generatedAt: new Date().toISOString(), config: s.config, results }, null, 2), 'application/json')}><Download className="w-3.5 h-3.5" />Export results</Btn>}
          <Btn onClick={runAll} disabled={!!busy}><Play className="w-3.5 h-3.5" />{busy ? 'Running…' : 'Run evaluation'}</Btn>
        </>} />
      {busy && <div className="text-xs text-sky-300 flex items-center gap-2"><FlaskConical className="w-4 h-4 animate-pulse" />{busy}</div>}

      <div className="grid md:grid-cols-3 gap-4">
        {(['rules', 'anomaly', 'hybrid'] as Mode[]).map((m) => {
          const x = results[m];
          return (
            <button key={m} onClick={() => setView(m)} className={cx('text-left p-4 rounded-xl border transition-colors', view === m ? 'border-sky-500/50 bg-sky-500/5' : 'border-slate-800 bg-slate-900/60 hover:border-slate-700')}>
              <div className="text-xs font-semibold text-slate-200">{MODE_LABEL[m]}</div>
              {x ? (
                <div className="grid grid-cols-3 gap-2 mt-3 text-center">
                  <div><div className="text-lg font-bold text-white tabular-nums">{pct(x.precision)}</div><div className="text-[10px] text-slate-500">precision</div></div>
                  <div><div className="text-lg font-bold text-white tabular-nums">{pct(x.recall)}</div><div className="text-[10px] text-slate-500">recall</div></div>
                  <div><div className="text-lg font-bold text-white tabular-nums">{x.f1.toFixed(2)}</div><div className="text-[10px] text-slate-500">F1</div></div>
                  <div className="col-span-3 text-[10px] text-slate-500 mt-1">benign alarm rate {pct(x.benignAlarmRate)} · {x.fpPerCapture.toFixed(2)} FP/capture · {x.ms} ms total</div>
                </div>
              ) : <div className="text-[11px] text-slate-500 mt-3">Not run yet.</div>}
            </button>
          );
        })}
      </div>
      <div className="text-[11px] text-slate-500 flex gap-1.5 leading-relaxed"><Info className="w-3.5 h-3.5 shrink-0 mt-0.5" />Rules/hybrid are scored per detector (expected detectors fired = TP; unexpected, non-corroborating detectors = FP). Anomaly-only cannot name a technique, so it is scored per scenario (any alarm on a suspicious capture = detected; any alarm on a benign capture = false alarm).</div>

      {r && (
        <Card className="overflow-x-auto">
          <table className="w-full text-[11px] min-w-[860px]">
            <thead className="text-slate-500 bg-slate-900/80"><tr><th className="text-left p-2.5">Scenario</th><th className="text-right p-2.5">Pkts</th><th className="text-right p-2.5">Flows</th><th className="text-left p-2.5">Expected</th><th className="text-left p-2.5">Fired</th><th className="text-center p-2.5">TP/FP/FN</th><th className="text-right p-2.5">Latency</th><th className="text-center p-2.5">Result</th></tr></thead>
            <tbody>{r.rows.map((x) => {
              const pass = view === 'anomaly' ? x.alarm !== x.benign : x.fn === 0 && x.fp === 0;
              return (
                <tr key={x.scenario} className="border-t border-slate-800/60 align-top">
                  <td className="p-2.5"><div className="font-mono text-slate-200">{x.scenario}</div><Pill className={x.benign ? 'text-emerald-300 mt-1' : 'text-rose-300 mt-1'}>{x.benign ? 'benign' : 'suspicious'}</Pill></td>
                  <td className="p-2.5 text-right tabular-nums">{x.packets.toLocaleString()}</td><td className="p-2.5 text-right tabular-nums">{x.flows}</td>
                  <td className="p-2.5"><div className="flex flex-wrap gap-1">{x.expected.map((d) => <Pill key={d} className="font-mono">{d.replace(/^rule_/, '')}</Pill>)}{!x.expected.length && <span className="text-slate-600">{view === 'anomaly' ? '(scenario-level)' : 'none'}</span>}</div></td>
                  <td className="p-2.5"><div className="flex flex-wrap gap-1">{x.fired.map((d) => <Pill key={d} className={cx('font-mono', x.expected.includes(d) ? 'text-emerald-300' : 'text-slate-400')}>{d.replace(/^rule_/, '')}</Pill>)}{!x.fired.length && <span className="text-slate-600">none</span>}</div></td>
                  <td className="p-2.5 text-center font-mono">{x.tp}/{x.fp}/{x.fn}</td><td className="p-2.5 text-right tabular-nums">{x.ms} ms</td>
                  <td className="p-2.5 text-center">{pass ? <CheckCircle2 className="w-4 h-4 text-emerald-400 inline" /> : <XCircle className="w-4 h-4 text-rose-400 inline" />}</td>
                </tr>
              );
            })}</tbody>
          </table>
        </Card>
      )}

      <Card className="p-5">
        <SectionTitle icon={<Upload className="w-4 h-4 text-sky-400" />}>Add your own labelled capture</SectionTitle>
        <div className="flex flex-wrap items-end gap-2">
          <label className="text-[11px] text-slate-400">Expected detector (ground truth)
            <Select value={pendingExpected} onChange={(e) => setPendingExpected(e.target.value)} className="block mt-1"><option value="">None — benign capture</option>{DETECTORS.filter((d) => d.source === 'rule').map((d) => <option key={d.id} value={d.id}>{d.id}</option>)}</Select>
          </label>
          <Btn variant="secondary" onClick={() => fileRef.current?.click()}><Upload className="w-3.5 h-3.5" />Choose PCAP</Btn>
          <input ref={fileRef} type="file" accept=".pcap,.pcapng,.cap" className="hidden" onChange={(e) => { if (e.target.files?.[0]) addCustom(e.target.files[0]); e.target.value = ''; }} />
        </div>
        {custom.length > 0 && <div className="flex flex-wrap gap-1.5 mt-3">{custom.map((c) => <Pill key={c.file}>{c.file} → {c.expected[0] || 'benign'}</Pill>)}</div>}
        <p className="text-[10px] text-slate-500 mt-2">Custom captures are evaluated in memory only and are not added to any case. Use only legally obtained or synthetic data.</p>
      </Card>

      <Card className="p-5">
        <SectionTitle>Built-in scenarios (synthetic ground truth)</SectionTitle>
        <div className="grid md:grid-cols-2 gap-3">{SAMPLES.map((x) => (
          <div key={x.file} className="p-3 rounded-lg border border-slate-800 bg-slate-950/50 text-[11px]">
            <div className="font-semibold text-slate-200">{x.title}</div><div className="text-slate-500 mt-0.5 leading-relaxed">{x.description}</div>
            <div className="mt-1.5 text-slate-400">Expected: <span className="font-mono">{x.expected.join(', ') || 'no findings'}</span></div>
          </div>
        ))}</div>
      </Card>
    </div>
  );
}
