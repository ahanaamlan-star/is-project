import { useEffect, useState } from 'react';
import { Settings2, HardDrive, Cpu, ShieldCheck, Trash2, CheckCircle2, XCircle } from 'lucide-react';
import { useStore } from '../store/useStore';
import { Card, PageHeader, SectionTitle, KV, Btn } from '../components/ui';
import { fmtBytes } from '../lib/format';
import { ENGINE_VERSION, PARSER_NAME, PARSER_VERSION } from '../engine/types';
import { DETECTORS } from '../engine/detectors';
import { LINKTYPE_NAMES } from '../engine/pcap';

export function DiagnosticsPage() {
  const s = useStore();
  const [est, setEst] = useState<{ usage?: number; quota?: number } | null>(null);
  const [persisted, setPersisted] = useState<boolean | null>(null);
  useEffect(() => {
    navigator.storage?.estimate?.().then(setEst).catch(() => setEst(null));
    navigator.storage?.persisted?.().then(setPersisted).catch(() => setPersisted(null));
  }, [s.captures.length]);

  const caps: Array<[string, boolean]> = [
    ['Web Workers', typeof Worker !== 'undefined'],
    ['WebCrypto SHA-256', !!(globalThis.crypto && crypto.subtle)],
    ['IndexedDB persistence', s.persistent],
    ['Storage API', !!navigator.storage],
    ['Structured clone', typeof structuredClone === 'function'],
  ];

  return (
    <div className="space-y-5">
      <PageHeader title="System Diagnostics" subtitle="Engine versions, browser capabilities, local storage usage and data-retention controls." />
      <div className="grid lg:grid-cols-3 gap-5">
        <Card className="p-5">
          <SectionTitle icon={<Cpu className="w-4 h-4 text-sky-400" />}>Engine</SectionTitle>
          <KV k="Engine version" v={ENGINE_VERSION} mono />
          <KV k="Parser" v={`${PARSER_NAME} ${PARSER_VERSION}`} mono />
          <KV k="Execution" v="Browser Web Worker (no backend)" />
          <KV k="Formats" v="PCAP (µs/ns, LE/BE), PCAPNG" />
          <KV k="Link types" v={Object.values(LINKTYPE_NAMES).filter((v, i, a) => a.indexOf(v) === i && !v.includes('802.11')).join(', ')} />
          <KV k="Dissectors" v="ARP, IPv4, IPv6+ext, TCP, UDP, ICMP/v6, DNS, TLS (SNI, ALPN, JA3/JA3S), HTTP, SSH, FTP/POP3/IMAP/SMTP auth, QUIC, SMB/RDP/Telnet by port" />
          <KV k="Active detectors" v={DETECTORS.length} />
        </Card>
        <Card className="p-5">
          <SectionTitle icon={<ShieldCheck className="w-4 h-4 text-emerald-400" />}>Browser capabilities</SectionTitle>
          {caps.map(([k, ok]) => <KV key={k} k={k} v={ok ? <span className="text-emerald-300 flex items-center gap-1 justify-end"><CheckCircle2 className="w-3.5 h-3.5" />available</span> : <span className="text-rose-300 flex items-center gap-1 justify-end"><XCircle className="w-3.5 h-3.5" />missing</span>} />)}
          {!s.persistent && <p className="text-[11px] text-amber-300 mt-2">IndexedDB is unavailable (private mode?). Data will be lost on reload.</p>}
        </Card>
        <Card className="p-5">
          <SectionTitle icon={<HardDrive className="w-4 h-4 text-amber-400" />}>Local storage & retention</SectionTitle>
          <KV k="Cases / captures" v={`${s.cases.length} / ${s.captures.length}`} />
          <KV k="Stored capture bytes" v={fmtBytes(s.captures.reduce((a, c) => a + c.size, 0))} />
          <KV k="Origin storage used" v={est?.usage != null ? `${fmtBytes(est.usage)} of ${fmtBytes(est.quota || 0)}` : 'unknown'} />
          <KV k="Persistent storage" v={persisted == null ? 'unknown' : persisted ? 'granted' : 'best-effort'} />
          <div className="flex flex-col gap-2 mt-3">
            {persisted === false && <Btn size="sm" variant="secondary" onClick={() => navigator.storage.persist().then(setPersisted)}>Request persistent storage</Btn>}
            <Btn size="sm" variant="danger" onClick={async () => { if (confirm('Permanently delete ALL cases, captures, analyses, settings and audit events stored by NetSentry XAI in this browser?')) { await s.purgeAll(); s.toast('success', 'All local data purged.'); } }}><Trash2 className="w-3.5 h-3.5" />Purge all local data</Btn>
          </div>
        </Card>
      </div>
      <Card className="p-5">
        <SectionTitle icon={<Settings2 className="w-4 h-4 text-slate-400" />}>Design guarantees</SectionTitle>
        <div className="grid md:grid-cols-2 gap-x-8 gap-y-2 text-xs text-slate-400 leading-relaxed">
          <p>• <b className="text-slate-200">Evidence first</b> — every finding stores packet indices, flow IDs, timestamps, observed values and thresholds.</p>
          <p>• <b className="text-slate-200">Explainable by default</b> — observed facts, rule rationale, model signal, interpretation, alternatives, next checks and limitations are separated.</p>
          <p>• <b className="text-slate-200">Human-led</b> — read-only analysis; no blocking, no containment, no outbound connections.</p>
          <p>• <b className="text-slate-200">Honest uncertainty</b> — scores are relative; evidence confidence is reported separately from severity.</p>
          <p>• <b className="text-slate-200">Reproducible</b> — seeded model, config hash, parser/detector versions and stage timings on every run.</p>
          <p>• <b className="text-slate-200">Privacy by design</b> — metadata-first, credentials never stored, explicit deletion controls, no telemetry.</p>
        </div>
      </Card>
    </div>
  );
}
