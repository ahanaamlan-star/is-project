import { useMemo, useState, useEffect } from 'react';
import { useSearchParams } from 'react-router-dom';
import { Search, Download, ChevronLeft, ChevronRight, X, ArrowUpDown, Info } from 'lucide-react';
import { useStore } from '../store/useStore';
import { NeedsRun } from '../components/Guards';
import { Card, PageHeader, Input, Select, Btn, Pill, cx } from '../components/ui';
import { fmtBytes, fmtTs, fmtDur, download } from '../lib/format';
import { flowsCsv, toCsv } from '../lib/report';
import type { Flow, PacketRecord } from '../engine/types';

const PAGE = 100;

// Tiny display-filter language: ip:1.2.3.4 port:443 proto:tls state:S0 sni:example host:abc  (free text otherwise)
function parseFilter(q: string) {
  const tokens: Record<string, string[]> = {};
  const free: string[] = [];
  for (const t of q.trim().split(/\s+/).filter(Boolean)) {
    const m = t.match(/^(ip|port|proto|state|sni|host|flag|len>|len<):(.+)$/i) || t.match(/^(len)([<>])(\d+)$/i);
    if (m && m[1].toLowerCase() === 'len' && m[2]) (tokens[`len${m[2]}`] ||= []).push(m[3]);
    else if (m) (tokens[m[1].toLowerCase()] ||= []).push(m[2].toLowerCase());
    else free.push(t.toLowerCase());
  }
  return { tokens, free };
}

export function FlowsPage() {
  return <NeedsRun><Flows /></NeedsRun>;
}

function Flows() {
  const s = useStore();
  const run = s.run!;
  const [params, setParams] = useSearchParams();
  const findingId = params.get('finding');
  const finding = findingId ? run.findings.find((f) => f.id === findingId) : null;
  const [tab, setTab] = useState<'flows' | 'packets'>(finding && !finding.evidence.flowIds.length ? 'packets' : 'flows');
  const [q, setQ] = useState('');
  const [app, setApp] = useState('');
  const [state, setState] = useState('');
  const [anomOnly, setAnomOnly] = useState(false);
  const [page, setPage] = useState(0);
  const [sort, setSort] = useState<{ k: keyof Flow; dir: 1 | -1 }>({ k: 'start', dir: 1 });
  useEffect(() => setPage(0), [q, app, state, anomOnly, tab, findingId]);

  const apps = useMemo(() => [...new Set(run.flows.map((f) => f.app))].sort(), [run.flows]);
  const states = useMemo(() => [...new Set(run.flows.map((f) => f.state))].sort(), [run.flows]);

  const flows = useMemo(() => {
    const { tokens, free } = parseFilter(q);
    const ev = finding ? new Set(finding.evidence.flowIds) : null;
    const evPk = finding ? new Set(finding.evidence.packetIdx) : null;
    const out = run.flows.filter((f) => {
      if (ev && !ev.has(f.id) && !(evPk && f.packetIdx.some((i) => evPk.has(i)))) return false;
      if (app && f.app !== app) return false;
      if (state && f.state !== state) return false;
      if (anomOnly && !f.isAnomaly) return false;
      if (tokens.ip && !tokens.ip.some((ip) => f.src.toLowerCase().includes(ip) || f.dst.toLowerCase().includes(ip))) return false;
      if (tokens.port && !tokens.port.some((p) => String(f.sport) === p || String(f.dport) === p)) return false;
      if (tokens.proto && !tokens.proto.some((p) => f.app.toLowerCase() === p || f.transport.toLowerCase() === p)) return false;
      if (tokens.state && !tokens.state.some((p) => f.state.toLowerCase() === p)) return false;
      if (tokens.sni && !tokens.sni.some((p) => (f.sni || '').toLowerCase().includes(p))) return false;
      if (tokens.host && !tokens.host.some((p) => `${f.sni || ''} ${f.httpHost || ''} ${(f.dnsQueries || []).join(' ')}`.toLowerCase().includes(p))) return false;
      if (free.length) {
        const hay = `${f.id} ${f.src} ${f.dst} ${f.sport} ${f.dport} ${f.app} ${f.transport} ${f.sni || ''} ${f.httpHost || ''} ${f.state} ${f.ja3Hash || ''}`.toLowerCase();
        if (!free.every((t) => hay.includes(t))) return false;
      }
      return true;
    });
    out.sort((a, b) => {
      const x = a[sort.k] as number | string, y = b[sort.k] as number | string;
      return (x > y ? 1 : x < y ? -1 : 0) * sort.dir;
    });
    return out;
  }, [run.flows, q, app, state, anomOnly, finding, sort]);

  const packets = useMemo(() => {
    const { tokens, free } = parseFilter(q);
    const ev = finding ? new Set(finding.evidence.packetIdx) : null;
    const flowPk = finding && finding.evidence.flowIds.length ? new Set(run.flows.filter((f) => finding.evidence.flowIds.includes(f.id)).flatMap((f) => f.packetIdx)) : null;
    return run.packets.filter((p) => {
      if (ev && !ev.has(p.i) && !(flowPk && flowPk.has(p.i))) return false;
      if (app && p.proto !== app && p.transport !== app) return false;
      if (tokens.ip && !tokens.ip.some((ip) => (p.src || '').toLowerCase().includes(ip) || (p.dst || '').toLowerCase().includes(ip))) return false;
      if (tokens.port && !tokens.port.some((x) => String(p.sport) === x || String(p.dport) === x)) return false;
      if (tokens.proto && !tokens.proto.some((x) => p.proto.toLowerCase() === x || p.transport.toLowerCase() === x)) return false;
      if (tokens.flag && !tokens.flag.some((x) => p.flags.toLowerCase().includes(x))) return false;
      if (tokens['len>'] && !tokens['len>'].every((x) => p.len > Number(x))) return false;
      if (tokens['len<'] && !tokens['len<'].every((x) => p.len < Number(x))) return false;
      if (tokens.sni && !tokens.sni.some((x) => (p.meta.tls?.sni || '').toLowerCase().includes(x))) return false;
      if (tokens.host && !tokens.host.some((x) => `${p.meta.dns?.query || ''} ${p.meta.http?.host || ''} ${p.meta.tls?.sni || ''}`.toLowerCase().includes(x))) return false;
      if (free.length && !free.every((t) => p.info.toLowerCase().includes(t) || String(p.i) === t)) return false;
      return true;
    });
  }, [run.packets, run.flows, q, app, finding]);

  const total = tab === 'flows' ? flows.length : packets.length;
  const pages = Math.max(1, Math.ceil(total / PAGE));
  const th = (k: keyof Flow, label: string, right?: boolean) => (
    <th className={cx('p-2 font-medium cursor-pointer select-none hover:text-slate-300 whitespace-nowrap', right ? 'text-right' : 'text-left')} onClick={() => setSort({ k, dir: sort.k === k ? (sort.dir === 1 ? -1 : 1) : (typeof run.flows[0]?.[k] === 'number' ? -1 : 1) })}>
      <span className="inline-flex items-center gap-1">{label}<ArrowUpDown className={cx('w-3 h-3', sort.k === k ? 'text-sky-400' : 'opacity-30')} /></span>
    </th>
  );

  const exportCsv = () => {
    if (tab === 'flows') download(`flows_${run.runId}.csv`, flowsCsv({ ...run, flows }), 'text/csv');
    else download(`packets_${run.runId}.csv`, toCsv(packets.slice(0, 100000).map((p: PacketRecord) => ({ index: p.i, time: fmtTs(p.ts), src: p.src, sport: p.sport, dst: p.dst, dport: p.dport, transport: p.transport, protocol: p.proto, length: p.len, flags: p.flags, info: p.info }))), 'text/csv');
  };

  return (
    <div className="space-y-4">
      <PageHeader title="Packets & Flows" subtitle="Searchable evidence explorer. Every row links to its full decode, raw bytes, feature vector and related findings." right={<Btn size="sm" variant="secondary" onClick={exportCsv}><Download className="w-3.5 h-3.5" />Export {tab} CSV</Btn>} />
      {finding && (
        <div className="p-3 rounded-lg border border-sky-500/30 bg-sky-500/5 text-xs text-sky-200 flex items-center justify-between gap-2">
          <span>Showing evidence for <b className="font-mono">{finding.id}</b> — {finding.title}</span>
          <Btn size="sm" variant="ghost" onClick={() => setParams({})}><X className="w-3 h-3" />Clear</Btn>
        </div>
      )}
      <div className="flex gap-1">
        {(['flows', 'packets'] as const).map((t) => <button key={t} onClick={() => setTab(t)} className={cx('px-4 py-2 text-xs font-semibold rounded-lg border', tab === t ? 'bg-sky-500/10 border-sky-500/40 text-sky-300' : 'border-slate-800 text-slate-400 hover:text-slate-200')}>{t === 'flows' ? `Flows (${run.flows.length.toLocaleString()})` : `Packets (${run.packets.length.toLocaleString()})`}</button>)}
      </div>
      <Card className="p-3 flex flex-wrap items-center gap-2">
        <div className="relative flex-1 min-w-[240px]">
          <Search className="w-3.5 h-3.5 text-slate-500 absolute left-2.5 top-1/2 -translate-y-1/2" />
          <Input value={q} onChange={(e) => setQ(e.target.value)} placeholder={tab === 'flows' ? 'ip:10.0.0.5 port:443 proto:tls state:S0 sni:example …' : 'ip:10.0.0.5 port:53 proto:dns flag:syn len>1000 host:example …'} className="w-full pl-8 font-mono" />
        </div>
        <Select value={app} onChange={(e) => setApp(e.target.value)}><option value="">All protocols</option>{(tab === 'flows' ? apps : Object.keys(run.summary.protocols).sort()).map((a) => <option key={a} value={a}>{a}</option>)}</Select>
        {tab === 'flows' && <Select value={state} onChange={(e) => setState(e.target.value)}><option value="">All states</option>{states.map((a) => <option key={a} value={a}>{a}</option>)}</Select>}
        {tab === 'flows' && <label className="text-[11px] text-slate-400 flex items-center gap-1.5"><input type="checkbox" checked={anomOnly} onChange={(e) => setAnomOnly(e.target.checked)} />IF outliers only</label>}
        <span className="text-[11px] text-slate-500 ml-auto">{total.toLocaleString()} rows</span>
      </Card>
      {tab === 'flows' && <div className="text-[10px] text-slate-500 flex items-center gap-1.5"><Info className="w-3 h-3" />States: S0 no reply · REJ rejected · HALF half-open · S1 established · SF established & closed · RST reset after establishment.</div>}

      <Card className="overflow-x-auto">
        {tab === 'flows' ? (
          <table className="w-full text-[11px] min-w-[960px]">
            <thead className="text-slate-500 bg-slate-900/80 border-b border-slate-800"><tr>
              {th('id', 'Flow')}{th('start', 'Start')}{th('src', 'Source')}{th('dst', 'Destination')}{th('app', 'App')}{th('totalPkts', 'Pkts', true)}{th('totalBytes', 'Bytes', true)}{th('duration', 'Dur', true)}{th('state', 'State')}
              <th className="p-2 text-left font-medium">Name</th>{th('anomalyScore', 'IF', true)}
            </tr></thead>
            <tbody>
              {flows.slice(page * PAGE, page * PAGE + PAGE).map((f) => (
                <tr key={f.id} onClick={() => s.setInspect({ inspectFlowId: f.id })} className="border-t border-slate-800/60 hover:bg-slate-800/40 cursor-pointer">
                  <td className="p-2 font-mono text-indigo-300">{f.id}</td>
                  <td className="p-2 font-mono text-slate-400 whitespace-nowrap">{fmtTs(f.start, false)}</td>
                  <td className="p-2 font-mono text-slate-200 whitespace-nowrap">{f.src}{f.sport != null && <span className="text-slate-500">:{f.sport}</span>}</td>
                  <td className="p-2 font-mono text-slate-200 whitespace-nowrap">{f.dst}{f.dport != null && <span className="text-slate-500">:{f.dport}</span>}</td>
                  <td className="p-2"><Pill>{f.app}</Pill></td>
                  <td className="p-2 text-right tabular-nums">{f.totalPkts}</td>
                  <td className="p-2 text-right tabular-nums">{fmtBytes(f.totalBytes)}</td>
                  <td className="p-2 text-right tabular-nums text-slate-400">{fmtDur(f.duration)}</td>
                  <td className={cx('p-2 font-mono', ['S0', 'REJ', 'HALF'].includes(f.state) ? 'text-amber-300' : 'text-slate-400')}>{f.state}</td>
                  <td className="p-2 font-mono text-slate-400 truncate max-w-[200px]">{f.sni || f.httpHost || f.dnsQueries?.[0] || ''}</td>
                  <td className={cx('p-2 text-right tabular-nums font-mono', f.isAnomaly ? 'text-fuchsia-300 font-bold' : 'text-slate-500')}>{f.anomalyScore ?? '—'}</td>
                </tr>
              ))}
            </tbody>
          </table>
        ) : (
          <table className="w-full text-[11px] min-w-[900px]">
            <thead className="text-slate-500 bg-slate-900/80 border-b border-slate-800"><tr>
              <th className="p-2 text-left font-medium">#</th><th className="p-2 text-left font-medium">Time</th><th className="p-2 text-left font-medium">Source</th><th className="p-2 text-left font-medium">Destination</th><th className="p-2 text-left font-medium">Proto</th><th className="p-2 text-right font-medium">Len</th><th className="p-2 text-left font-medium">Info</th>
            </tr></thead>
            <tbody>
              {packets.slice(page * PAGE, page * PAGE + PAGE).map((p) => (
                <tr key={p.i} onClick={() => s.setInspect({ inspectPacket: p.i })} className="border-t border-slate-800/60 hover:bg-slate-800/40 cursor-pointer">
                  <td className="p-2 font-mono text-emerald-300">{p.i}</td>
                  <td className="p-2 font-mono text-slate-400 whitespace-nowrap">{fmtTs(p.ts, false)}</td>
                  <td className="p-2 font-mono text-slate-200 whitespace-nowrap">{p.src ?? p.srcMac ?? '—'}</td>
                  <td className="p-2 font-mono text-slate-200 whitespace-nowrap">{p.dst ?? p.dstMac ?? '—'}</td>
                  <td className="p-2"><Pill>{p.proto}</Pill></td>
                  <td className="p-2 text-right tabular-nums">{p.len}</td>
                  <td className="p-2 font-mono text-slate-300 truncate max-w-[480px]">{p.info}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
        {total === 0 && <div className="p-8 text-center text-xs text-slate-500">No rows match.</div>}
      </Card>
      <div className="flex items-center justify-end gap-2 text-xs text-slate-400">
        <Btn size="sm" variant="secondary" disabled={page === 0} onClick={() => setPage(page - 1)} aria-label="Previous page"><ChevronLeft className="w-3.5 h-3.5" /></Btn>
        <span>Page {page + 1} / {pages}</span>
        <Btn size="sm" variant="secondary" disabled={page >= pages - 1} onClick={() => setPage(page + 1)} aria-label="Next page"><ChevronRight className="w-3.5 h-3.5" /></Btn>
      </div>
    </div>
  );
}
