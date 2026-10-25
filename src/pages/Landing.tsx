import { Link, useNavigate } from 'react-router-dom';
import {
  Shield, ArrowRight, UploadCloud, Network, Brain, Layers, FileCheck2, Lock, Eye, Target, Shuffle, ListChecks, AlertOctagon, Share2, Clock,
  MessageSquareText, GitCompareArrows, FlaskConical, Fingerprint, Gauge, Github, Cpu, Sparkles, ShieldCheck, Binary, ScanSearch,
} from 'lucide-react';
import { DETECTORS } from '../engine/detectors';

const FEATURES = [
  { icon: UploadCloud, t: 'PCAP & PCAPNG, in-browser', d: 'Drag-and-drop captures up to 200 MB. Magic-byte validation, SHA-256 chain of custody, bounds-checked dissection in a Web Worker.' },
  { icon: Network, t: 'Flow reconstruction', d: 'Bidirectional 5-tuple flows with idle-timeout and port-reuse splitting, Zeek-style connection states and 14 behavioural features per flow.' },
  { icon: Binary, t: 'Protocol-aware decoding', d: 'Ethernet/VLAN/SLL, IPv4/IPv6, TCP/UDP/ICMP, DNS, HTTP, SSH, QUIC and TLS ClientHello parsing with SNI, ALPN and JA3/JA3S fingerprints.' },
  { icon: Target, t: '14 transparent rules', d: 'Scans, sweeps, failed handshakes, DNS tunnelling & DGA, beaconing, floods, exfiltration, ARP spoofing, lateral movement, cleartext credentials and more.' },
  { icon: Brain, t: 'Isolation Forest + baselines', d: 'Seeded unsupervised outlier scoring with path-based feature attribution, plus robust median/MAD host baselines — clearly labelled as relative signals.' },
  { icon: Eye, t: 'Structured explanations', d: 'Every finding separates observed facts, rule evidence, model signal, interpretation, alternative explanations, next checks and limitations.' },
  { icon: Layers, t: 'Incident correlation', d: 'Union-find grouping on shared entities and time proximity, with the grouping rationale shown and analyst split/merge controls.' },
  { icon: Gauge, t: 'Transparent risk priority', d: 'Configurable weighted score from severity, anomaly, evidence strength, corroboration and asset context — components always shown.' },
  { icon: Share2, t: 'Interactive host graph', d: 'Force-directed topology with severity rings, volume-weighted edges, drag, zoom and click-through to host profiles and findings.' },
  { icon: Clock, t: 'Swim-lane timeline', d: 'Findings on the capture clock with incident windows, zoom handles and entity filters.' },
  { icon: MessageSquareText, t: 'Evidence assistant', d: 'Ask “what did 10.10.0.23 do?” — deterministic answers computed from case evidence, with clickable citations. No external AI.' },
  { icon: GitCompareArrows, t: 'PCAP diff', d: 'Baseline vs. comparison: new hosts, SNI, JA3, DNS names, ports, protocol shifts and volume changes.' },
  { icon: FlaskConical, t: 'Evaluation lab', d: 'Measure precision, recall and false-alarm rates for rules-only, anomaly-only and hybrid modes on labelled captures — live.' },
  { icon: Fingerprint, t: 'ATT&CK hypotheses', d: 'Findings map to MITRE ATT&CK techniques where evidence supports it, presented as hypotheses, never attribution.' },
  { icon: FileCheck2, t: 'Reports & exports', d: 'Print-ready HTML/PDF, JSON, CSV and STIX 2.1 with provenance, config hash, versions, limitations and full audit trail.' },
  { icon: ShieldCheck, t: 'Analyst workspace', d: 'Cases, dispositions, tags, assignees, notes, saved filters, bulk triage, case bundles and an immutable-style audit log.' },
];

const PIPE = [
  ['Validate', 'magic bytes · size · SHA-256'], ['Dissect', 'L2 → L7 metadata'], ['Reconstruct', 'flows · hosts · passive DNS'],
  ['Detect', 'rules · baselines · Isolation Forest'], ['Explain & correlate', 'evidence · incidents · priority'], ['Review & report', 'triage · audit · export'],
];

export function Landing() {
  const nav = useNavigate();
  return (
    <div className="min-h-screen bg-ink-950 text-slate-100">
      <header className="sticky top-0 z-40 bg-ink-950/80 backdrop-blur border-b border-slate-800/80">
        <div className="max-w-7xl mx-auto px-4 md:px-6 h-16 flex items-center justify-between">
          <Link to="/" className="flex items-center gap-3">
            <div className="w-9 h-9 rounded-lg bg-sky-500/10 border border-sky-500/30 flex items-center justify-center"><Shield className="w-5 h-5 text-sky-400" /></div>
            <span className="font-bold text-lg tracking-tight">NetSentry</span><span className="text-xs font-semibold px-2 py-0.5 rounded bg-sky-500/20 text-sky-400 border border-sky-500/40">XAI</span>
          </Link>
          <nav className="hidden md:flex items-center gap-6 text-xs text-slate-400">
            <a href="#features" className="hover:text-white">Features</a><a href="#explain" className="hover:text-white">Explainability</a><a href="#detectors" className="hover:text-white">Detectors</a><a href="#privacy" className="hover:text-white">Privacy</a>
          </nav>
          <Link to="/app/dashboard" className="inline-flex items-center gap-1.5 px-3.5 py-2 text-xs font-semibold rounded-lg bg-sky-600 hover:bg-sky-500 text-white">Launch workspace<ArrowRight className="w-3.5 h-3.5" /></Link>
        </div>
      </header>

      <section className="relative overflow-hidden">
        <div className="absolute inset-0 grid-bg [mask-image:radial-gradient(ellipse_at_top,black,transparent_70%)]" />
        <div className="absolute -top-40 left-1/2 -translate-x-1/2 w-[900px] h-[500px] rounded-full bg-sky-500/10 blur-3xl" />
        <div className="relative max-w-7xl mx-auto px-4 md:px-6 pt-16 md:pt-24 pb-16 grid lg:grid-cols-2 gap-12 items-center">
          <div>
            <div className="inline-flex items-center gap-2 text-[11px] px-3 py-1 rounded-full border border-emerald-500/30 bg-emerald-500/10 text-emerald-300 mb-5"><Lock className="w-3 h-3" />100% local — your captures never leave the browser</div>
            <h1 className="text-4xl md:text-5xl font-extrabold tracking-tight leading-[1.08]">From raw packets to an <span className="text-sky-400">explainable</span> investigation.</h1>
            <p className="text-slate-400 mt-5 text-base leading-relaxed max-w-xl">NetSentry XAI turns PCAP/PCAPNG captures into evidence-linked findings: reconstructed flows, transparent detection rules, unsupervised anomaly scoring, correlated incidents and audit-ready reports — every claim traceable to packets, flows and timestamps.</p>
            <div className="flex flex-wrap gap-3 mt-8">
              <button onClick={() => nav('/app/ingest?demo=enterprise')} className="inline-flex items-center gap-2 px-5 py-3 text-sm font-semibold rounded-xl bg-sky-600 hover:bg-sky-500 text-white shadow-lg shadow-sky-900/40"><Sparkles className="w-4 h-4" />Run the live demo</button>
              <Link to="/app/ingest" className="inline-flex items-center gap-2 px-5 py-3 text-sm font-semibold rounded-xl bg-slate-900 hover:bg-slate-800 border border-slate-700 text-slate-200"><UploadCloud className="w-4 h-4" />Analyse your own PCAP</Link>
            </div>
            <div className="flex flex-wrap gap-x-6 gap-y-2 mt-8 text-[11px] text-slate-500">
              <span className="flex items-center gap-1.5"><Cpu className="w-3.5 h-3.5 text-sky-400" />Web Worker engine</span>
              <span className="flex items-center gap-1.5"><ScanSearch className="w-3.5 h-3.5 text-sky-400" />{DETECTORS.length} detectors</span>
              <span className="flex items-center gap-1.5"><Fingerprint className="w-3.5 h-3.5 text-sky-400" />JA3 · SNI · passive DNS</span>
              <span className="flex items-center gap-1.5"><FileCheck2 className="w-3.5 h-3.5 text-sky-400" />PDF · JSON · CSV · STIX</span>
            </div>
          </div>

          <div className="relative">
            <div className="absolute -inset-4 bg-gradient-to-tr from-sky-500/10 to-fuchsia-500/10 rounded-3xl blur-2xl" />
            <div className="relative bg-ink-800 border border-slate-800 rounded-2xl shadow-2xl overflow-hidden">
              <div className="flex items-center gap-1.5 px-4 py-3 border-b border-slate-800 bg-slate-900/60"><span className="w-2.5 h-2.5 rounded-full bg-rose-400/70" /><span className="w-2.5 h-2.5 rounded-full bg-amber-400/70" /><span className="w-2.5 h-2.5 rounded-full bg-emerald-400/70" /><span className="ml-3 text-[11px] text-slate-500 font-mono">rule_beacon_periodicity v2.0.0</span><span className="ml-auto text-[9px] uppercase tracking-wider text-slate-600">illustrative</span></div>
              <div className="p-5 space-y-3">
                <div className="flex gap-1.5"><span className="text-[10px] px-2 py-0.5 rounded font-bold uppercase border bg-amber-500/15 text-amber-300 border-amber-500/40">high</span><span className="text-[10px] px-2 py-0.5 rounded border bg-slate-800 text-slate-300 border-slate-700">c2 beaconing</span><span className="text-[10px] px-2 py-0.5 rounded border text-emerald-300 border-emerald-500/30">evidence: high</span></div>
                <div className="text-sm font-semibold text-white">Beacon-like periodicity: 10.10.0.23 → 45.137.21.9:443 (cdn-sync-update.com) every ~30s</div>
                <div className="grid grid-cols-2 gap-3 text-[11px]">
                  <div className="p-3 rounded-lg bg-slate-900/80 border border-slate-800"><div className="text-slate-500 uppercase text-[9px] font-bold tracking-wider mb-1 flex items-center gap-1"><Eye className="w-3 h-3 text-emerald-400" />Observed facts</div><div className="text-slate-300 leading-relaxed">24 TLS sessions to one destination at a near-constant ~30 s interval with near-identical upload sizes.</div></div>
                  <div className="p-3 rounded-lg bg-slate-900/80 border border-slate-800"><div className="text-slate-500 uppercase text-[9px] font-bold tracking-wider mb-1 flex items-center gap-1"><Target className="w-3 h-3 text-amber-400" />Rule evidence</div><div className="text-slate-300 leading-relaxed">≥ 4 connections and timing coefficient of variation ≤ 0.25.</div></div>
                  <div className="p-3 rounded-lg bg-slate-900/80 border border-slate-800"><div className="text-slate-500 uppercase text-[9px] font-bold tracking-wider mb-1 flex items-center gap-1"><Shuffle className="w-3 h-3 text-indigo-400" />Alternatives</div><div className="text-slate-300 leading-relaxed">Telemetry agents, update checks, keep-alives.</div></div>
                  <div className="p-3 rounded-lg bg-slate-900/80 border border-slate-800"><div className="text-slate-500 uppercase text-[9px] font-bold tracking-wider mb-1 flex items-center gap-1"><ListChecks className="w-3 h-3 text-emerald-400" />Next checks</div><div className="text-slate-300 leading-relaxed">Domain reputation, JA3 vs. known clients.</div></div>
                </div>
                <div className="flex items-center justify-between p-3 rounded-lg bg-slate-950 border border-slate-800">
                  <div className="text-[11px] text-slate-400">Priority <span className="text-white font-bold text-base ml-1">73</span><span className="text-slate-600">/100</span></div>
                  <div className="flex gap-1">{[0.75, 0.2, 1, 1, 0.5].map((v, i) => <div key={i} className="w-8 h-1.5 bg-slate-800 rounded-full overflow-hidden"><div className="h-full bg-sky-500" style={{ width: `${v * 100}%` }} /></div>)}</div>
                </div>
                <div className="text-[10px] text-slate-500 italic flex gap-1.5"><AlertOctagon className="w-3 h-3 text-amber-400 shrink-0" />Relative score — not a probability of compromise. Human review required.</div>
              </div>
            </div>
          </div>
        </div>
      </section>

      <section className="max-w-7xl mx-auto px-4 md:px-6 py-12">
        <div className="grid grid-cols-2 md:grid-cols-6 gap-2">
          {PIPE.map(([t, d], i) => (
            <div key={t} className="relative p-4 rounded-xl border border-slate-800 bg-slate-900/50">
              <div className="text-[10px] font-mono text-sky-400">0{i + 1}</div>
              <div className="text-sm font-semibold text-white mt-1">{t}</div>
              <div className="text-[11px] text-slate-500 mt-0.5">{d}</div>
            </div>
          ))}
        </div>
      </section>

      <section id="features" className="max-w-7xl mx-auto px-4 md:px-6 py-16">
        <div className="max-w-2xl mb-10">
          <div className="text-[11px] font-bold uppercase tracking-wider text-sky-400">Capabilities</div>
          <h2 className="text-3xl font-bold tracking-tight mt-2">A complete PCAP investigation workbench</h2>
          <p className="text-slate-400 mt-3 text-sm leading-relaxed">Everything from the NetSentry XAI blueprint — ingestion to reporting — running as a static site you can host anywhere.</p>
        </div>
        <div className="grid sm:grid-cols-2 lg:grid-cols-4 gap-4">
          {FEATURES.map(({ icon: I, t, d }) => (
            <div key={t} className="p-5 rounded-xl border border-slate-800 bg-slate-900/50 hover:border-sky-500/30 transition-colors">
              <div className="w-9 h-9 rounded-lg bg-sky-500/10 border border-sky-500/20 flex items-center justify-center mb-3"><I className="w-4.5 h-4.5 text-sky-400" /></div>
              <div className="text-sm font-semibold text-white">{t}</div>
              <p className="text-xs text-slate-400 mt-1.5 leading-relaxed">{d}</p>
            </div>
          ))}
        </div>
      </section>

      <section id="explain" className="border-y border-slate-800/80 bg-ink-900/60">
        <div className="max-w-7xl mx-auto px-4 md:px-6 py-16 grid lg:grid-cols-2 gap-10 items-start">
          <div>
            <div className="text-[11px] font-bold uppercase tracking-wider text-sky-400">Explainability by design</div>
            <h2 className="text-3xl font-bold tracking-tight mt-2">Facts, rationale and interpretation — never blurred</h2>
            <p className="text-slate-400 mt-3 text-sm leading-relaxed">An AI narrative must never be mistaken for raw evidence. Each finding keeps what the capture shows, why a rule or model fired, and what it might mean in separate, labelled fields — along with alternative explanations, the next analyst check and known limitations.</p>
            <ul className="mt-6 space-y-2 text-sm text-slate-300">
              {['Every factual claim links to packets, flows or timestamps', 'Rule triggers show exact thresholds vs. observed values', 'Model scores are labelled as relative, with approximate attribution', 'Evidence confidence is reported separately from severity', 'Parse warnings and capture limits flow into every explanation'].map((x) => <li key={x} className="flex gap-2"><ShieldCheck className="w-4 h-4 text-emerald-400 shrink-0 mt-0.5" />{x}</li>)}
            </ul>
          </div>
          <div className="rounded-xl border border-slate-800 overflow-hidden text-xs">
            {[
              ['Finding', 'Possible vertical port scan: 10.10.0.23 → 10.10.0.5'],
              ['Observed facts', '32 distinct destination ports in 1.9 s; 27 of 32 attempts rejected (RST).'],
              ['Rule evidence', 'Distinct ports in a 15 s window (32) ≥ threshold (12).'],
              ['Model signal', 'Corroborated by host egress outlier (robust z 14.9) on the same source.'],
              ['Interpretation', 'Consistent with service discovery prior to exploitation, or an authorised scan.'],
              ['Alternatives', 'Vulnerability assessment, inventory, monitoring.'],
              ['Next check', 'Confirm the source role; review which ports answered SYN-ACK.'],
              ['Limitations', 'Single vantage point; capture may be incomplete; not proof of compromise.'],
            ].map(([k, v], i) => (
              <div key={k} className={`grid grid-cols-3 ${i % 2 ? 'bg-slate-900/40' : 'bg-slate-900/80'}`}>
                <div className="p-3 text-slate-500 font-semibold border-r border-slate-800">{k}</div>
                <div className="p-3 col-span-2 text-slate-300 leading-relaxed">{v}</div>
              </div>
            ))}
          </div>
        </div>
      </section>

      <section id="detectors" className="max-w-7xl mx-auto px-4 md:px-6 py-16">
        <div className="text-[11px] font-bold uppercase tracking-wider text-sky-400">Layered detection</div>
        <h2 className="text-3xl font-bold tracking-tight mt-2 mb-8">Detector catalogue — with documented blind spots</h2>
        <div className="grid md:grid-cols-2 gap-3">
          {DETECTORS.map((d) => (
            <div key={d.id} className="p-4 rounded-xl border border-slate-800 bg-slate-900/50">
              <div className="flex items-center justify-between gap-2">
                <span className="text-sm font-semibold text-white">{d.name}</span>
                <span className={`text-[10px] px-2 py-0.5 rounded border ${d.source === 'rule' ? 'text-emerald-300 border-emerald-500/30' : d.source === 'model' ? 'text-fuchsia-300 border-fuchsia-500/30' : 'text-indigo-300 border-indigo-500/30'}`}>{d.source}</span>
              </div>
              <p className="text-xs text-slate-400 mt-1.5 leading-relaxed">{d.description}</p>
              <p className="text-[11px] text-slate-500 mt-1.5 leading-relaxed"><span className="text-amber-300/80">Blind spot:</span> {d.caveat}</p>
              {d.mitre.length > 0 && <div className="text-[10px] font-mono text-rose-300/70 mt-1.5">{d.mitre.map((m) => m.id).join(' · ')}</div>}
            </div>
          ))}
        </div>
      </section>

      <section id="privacy" className="max-w-7xl mx-auto px-4 md:px-6 pb-16">
        <div className="rounded-2xl border border-emerald-500/20 bg-gradient-to-br from-emerald-500/10 via-slate-900 to-slate-900 p-8 md:p-10 grid md:grid-cols-3 gap-8">
          <div className="md:col-span-2">
            <div className="text-[11px] font-bold uppercase tracking-wider text-emerald-300">Privacy-by-design</div>
            <h2 className="text-2xl md:text-3xl font-bold tracking-tight mt-2">There is no server to send your packets to.</h2>
            <p className="text-slate-400 mt-3 text-sm leading-relaxed">The site is static. Captures are parsed by a Web Worker on your machine and stored only in your browser's IndexedDB, with one-click deletion. No telemetry, no third-party enrichment, no outbound requests with your data. Credentials found in cleartext protocols are flagged but never stored. The tool is strictly read-only — it never blocks traffic or changes infrastructure.</p>
          </div>
          <div className="space-y-2 text-xs text-slate-300">
            {['Static hosting (Netlify-ready)', 'Strict Content-Security-Policy', 'SHA-256 provenance on every capture', 'Explicit retention & purge controls', 'Analyst actions fully audited'].map((x) => <div key={x} className="flex items-center gap-2 p-2.5 rounded-lg bg-slate-950/60 border border-slate-800"><Lock className="w-3.5 h-3.5 text-emerald-400" />{x}</div>)}
          </div>
        </div>
      </section>

      <section className="max-w-7xl mx-auto px-4 md:px-6 pb-20 text-center">
        <h2 className="text-2xl md:text-3xl font-bold tracking-tight">See the complete evidence path in under a minute</h2>
        <p className="text-slate-400 mt-2 text-sm">Load a synthetic multi-stage intrusion and follow it from packet to report.</p>
        <div className="flex flex-wrap justify-center gap-3 mt-6">
          <button onClick={() => nav('/app/ingest?demo=enterprise')} className="inline-flex items-center gap-2 px-5 py-3 text-sm font-semibold rounded-xl bg-sky-600 hover:bg-sky-500 text-white"><Sparkles className="w-4 h-4" />Run the live demo</button>
          <Link to="/app/dashboard" className="inline-flex items-center gap-2 px-5 py-3 text-sm font-semibold rounded-xl bg-slate-900 hover:bg-slate-800 border border-slate-700 text-slate-200">Open workspace<ArrowRight className="w-4 h-4" /></Link>
        </div>
      </section>

      <footer className="border-t border-slate-800/80">
        <div className="max-w-7xl mx-auto px-4 md:px-6 py-8 flex flex-col md:flex-row justify-between gap-3 text-[11px] text-slate-500">
          <div className="flex items-center gap-2"><Shield className="w-4 h-4 text-sky-400" />NetSentry XAI — explainable, evidence-first network forensics.</div>
          <div className="flex items-center gap-4"><span>Analyse only traffic you are authorised to inspect.</span><span className="flex items-center gap-1"><Github className="w-3.5 h-3.5" />Open-source friendly</span></div>
        </div>
      </footer>
    </div>
  );
}
