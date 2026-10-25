import { useState } from 'react';
import { SlidersHorizontal, Brain, Scale, ListChecks, Save, RotateCcw, Play, Gauge } from 'lucide-react';
import { useStore } from '../store/useStore';
import { Card, PageHeader, SectionTitle, Btn, Input, Textarea } from '../components/ui';
import { DEFAULT_CONFIG, THRESHOLD_DOCS } from '../engine/config';
import { DETECTORS } from '../engine/detectors';
import type { AnalysisConfig } from '../engine/types';
import { stableHash } from '../engine/util';

function Num({ label, help, value, onChange, step = 1, min, max }: { label: string; help?: string; value: number; onChange: (v: number) => void; step?: number; min?: number; max?: number }) {
  return (
    <label className="block">
      <div className="flex justify-between text-[11px]"><span className="text-slate-300">{label}</span></div>
      <Input type="number" step={step} min={min} max={max} value={value} onChange={(e) => onChange(Number(e.target.value))} className="w-full mt-1 font-mono" />
      {help && <span className="text-[10px] text-slate-500">{help}</span>}
    </label>
  );
}

export function SettingsPage() {
  const s = useStore();
  const [cfg, setCfg] = useState<AnalysisConfig>(structuredClone(s.config));
  const dirty = JSON.stringify(cfg) !== JSON.stringify(s.config);
  const setT = (k: keyof AnalysisConfig['thresholds'], v: number) => setCfg({ ...cfg, thresholds: { ...cfg.thresholds, [k]: v } });
  const setW = (k: keyof AnalysisConfig['weights'], v: number) => setCfg({ ...cfg, weights: { ...cfg.weights, [k]: v } });
  const setM = (k: keyof AnalysisConfig['ml'], v: number) => setCfg({ ...cfg, ml: { ...cfg.ml, [k]: v } });
  const wsum = Object.values(cfg.weights).reduce((a, b) => a + b, 0);

  const save = async (rerun: boolean) => {
    await s.saveConfig(cfg);
    s.toast('success', `Settings saved (config ${stableHash(cfg)}).`);
    if (rerun && s.activeCaptureId) {
      try { await s.analyzeCapture(s.activeCaptureId, cfg); s.toast('success', 'Re-analysis complete — dispositions were carried forward.'); }
      catch (e) { s.toast('error', e instanceof Error ? e.message : String(e)); }
    }
  };


  return (
    <div className="space-y-5">
      <PageHeader title="Detection Settings" subtitle="Every threshold, model parameter and risk weight is explicit, versioned by config hash, and recorded in each analysis run and report. Changes apply to the next analysis; re-running carries analyst dispositions forward."
        right={<>
          <Btn variant="ghost" size="sm" onClick={() => setCfg(structuredClone(DEFAULT_CONFIG))}><RotateCcw className="w-3.5 h-3.5" />Defaults</Btn>
          <Btn variant="secondary" size="sm" disabled={!dirty} onClick={() => save(false)}><Save className="w-3.5 h-3.5" />Save</Btn>
          <Btn size="sm" disabled={!s.activeCaptureId || !!s.progress} onClick={() => save(true)}><Play className="w-3.5 h-3.5" />Save & re-analyse</Btn>
        </>} />
      <div className="text-[11px] text-slate-500 font-mono">current config {stableHash(s.config)}{dirty && <span className="text-amber-300"> · unsaved changes → {stableHash(cfg)}</span>}</div>

      <div className="grid lg:grid-cols-3 gap-5">
        <Card className="p-5 lg:col-span-2">
          <SectionTitle icon={<SlidersHorizontal className="w-4 h-4 text-sky-400" />}>Rule thresholds</SectionTitle>
          <div className="grid sm:grid-cols-2 xl:grid-cols-3 gap-4">
            {(Object.keys(THRESHOLD_DOCS) as Array<keyof AnalysisConfig['thresholds']>).map((k) => (
              <Num key={k} label={THRESHOLD_DOCS[k].label} help={THRESHOLD_DOCS[k].help} value={cfg.thresholds[k]} step={THRESHOLD_DOCS[k].step} min={THRESHOLD_DOCS[k].min} max={THRESHOLD_DOCS[k].max} onChange={(v) => setT(k, v)} />
            ))}
          </div>
        </Card>
        <div className="space-y-5">
          <Card className="p-5 space-y-3">
            <SectionTitle icon={<ListChecks className="w-4 h-4 text-emerald-400" />}>Detection layers</SectionTitle>
            {([['runRules', 'Rule layer (14 detectors)'], ['runStatistical', 'Statistical baseline (robust z)'], ['runML', 'Isolation Forest model']] as const).map(([k, l]) => (
              <label key={k} className="flex items-center justify-between text-xs text-slate-300 bg-slate-950 border border-slate-800 rounded-lg px-3 py-2"><span>{l}</span><input type="checkbox" checked={cfg[k]} onChange={(e) => setCfg({ ...cfg, [k]: e.target.checked })} /></label>
            ))}
            <Num label="Flow idle timeout (s)" value={cfg.flowIdleTimeout} onChange={(v) => setCfg({ ...cfg, flowIdleTimeout: v })} min={1} />
            <Num label="Correlation window (s)" help="Max gap between findings sharing an entity" value={cfg.correlationWindow} onChange={(v) => setCfg({ ...cfg, correlationWindow: v })} min={1} />
          </Card>
          <Card className="p-5 space-y-3">
            <SectionTitle icon={<Gauge className="w-4 h-4 text-amber-400" />}>Resource limits</SectionTitle>
            <Num label="Max packets analysed" value={cfg.maxPackets} step={10000} onChange={(v) => setCfg({ ...cfg, maxPackets: v })} min={1000} />
            <Num label="Max file size (MB)" value={cfg.maxFileMB} step={10} onChange={(v) => setCfg({ ...cfg, maxFileMB: v })} min={1} max={2000} />
            <p className="text-[10px] text-slate-500">Large captures are parsed in the browser's memory; keep limits within the device's capacity.</p>
          </Card>
        </div>
      </div>

      <div className="grid lg:grid-cols-3 gap-5">
        <Card className="p-5">
          <SectionTitle icon={<Brain className="w-4 h-4 text-fuchsia-400" />}>Isolation Forest</SectionTitle>
          <div className="grid grid-cols-2 gap-3">
            <Num label="Trees" value={cfg.ml.trees} onChange={(v) => setM('trees', v)} min={10} max={500} />
            <Num label="Sample size ψ" value={cfg.ml.sampleSize} onChange={(v) => setM('sampleSize', v)} min={16} max={4096} />
            <Num label="Contamination" step={0.01} value={cfg.ml.contamination} onChange={(v) => setM('contamination', v)} min={0.005} max={0.5} />
            <Num label="Min score" step={0.01} value={cfg.ml.minScore} onChange={(v) => setM('minScore', v)} min={0.5} max={1} />
            <Num label="Random seed" value={cfg.ml.seed} onChange={(v) => setM('seed', v)} />
            <Num label="Max findings" value={cfg.ml.maxFindings} onChange={(v) => setM('maxFindings', v)} min={0} max={100} />
          </div>
          <p className="text-[10px] text-slate-500 mt-2">Seeded for reproducibility: the same capture + config always yields the same scores.</p>
        </Card>
        <Card className="p-5">
          <SectionTitle icon={<Scale className="w-4 h-4 text-sky-400" />}>Risk priority weights</SectionTitle>
          {(Object.keys(cfg.weights) as Array<keyof AnalysisConfig['weights']>).map((k) => (
            <div key={k} className="mb-2">
              <div className="flex justify-between text-[11px] text-slate-300"><span className="capitalize">{k}</span><span className="font-mono">{cfg.weights[k].toFixed(2)} ({Math.round((cfg.weights[k] / (wsum || 1)) * 100)}%)</span></div>
              <input type="range" min={0} max={1} step={0.05} value={cfg.weights[k]} onChange={(e) => setW(k, Number(e.target.value))} className="w-full" aria-label={`${k} weight`} />
            </div>
          ))}
          <p className="text-[10px] text-slate-500">Priority = Σ wᵢ·componentᵢ / Σ wᵢ × 100. Weights are normalised automatically and shown beside every score.</p>
        </Card>
        <Card className="p-5 space-y-3">
          <SectionTitle>Context lists</SectionTitle>
          <label className="block text-[11px] text-slate-300">Critical assets (one IP per line)
            <Textarea rows={4} value={cfg.criticalAssets.join('\n')} onChange={(e) => setCfg({ ...cfg, criticalAssets: e.target.value.split('\n').map((x) => x.trim()).filter(Boolean) })} className="mt-1 font-mono" placeholder="10.10.0.5" />
          </label>
          <label className="block text-[11px] text-slate-300">Allowlist — IPs or domains to suppress (kept for audit)
            <Textarea rows={4} value={cfg.allowlist.join('\n')} onChange={(e) => setCfg({ ...cfg, allowlist: e.target.value.split('\n').map((x) => x.trim()).filter(Boolean) })} className="mt-1 font-mono" placeholder="10.0.0.250 (vuln scanner)" />
          </label>
        </Card>
      </div>

      <Card className="p-5">
        <SectionTitle>Detector catalogue</SectionTitle>
        <div className="overflow-x-auto">
          <table className="w-full text-[11px] min-w-[800px]">
            <thead className="text-slate-500"><tr><th className="text-left p-2">Detector</th><th className="text-left p-2">Layer</th><th className="text-left p-2">What it looks for</th><th className="text-left p-2">Known blind spots</th><th className="text-left p-2">ATT&CK</th></tr></thead>
            <tbody>{DETECTORS.map((d) => (
              <tr key={d.id} className="border-t border-slate-800/60 align-top">
                <td className="p-2"><div className="font-mono text-sky-300">{d.id}</div><div className="text-slate-500">v{d.version} · default {d.defaultSeverity}</div></td>
                <td className="p-2 text-slate-300">{d.source}</td><td className="p-2 text-slate-400 leading-relaxed">{d.description}</td><td className="p-2 text-slate-500 leading-relaxed">{d.caveat}</td>
                <td className="p-2 font-mono text-rose-300/80">{d.mitre.map((m) => m.id).join(', ') || '—'}</td>
              </tr>
            ))}</tbody>
          </table>
        </div>
      </Card>
    </div>
  );
}
