import { useMemo, useState } from 'react';
import { AreaChart, Area, XAxis, YAxis, Tooltip, ResponsiveContainer, CartesianGrid, BarChart, Bar as RBar, Cell } from 'recharts';
import { AlertTriangle, Cpu, Network, HardDrive, Clock, Globe2, Lock, Server, Timer, Table2 } from 'lucide-react';
import { useStore } from '../store/useStore';
import { NeedsRun } from '../components/Guards';
import { Card, PageHeader, SectionTitle, Stat, Bar, Pill } from '../components/ui';
import { fmtBytes, fmtDur, fmtTs, PROTO_COLORS, OTHER_COLOR } from '../lib/format';
import { WELL_KNOWN } from '../engine/util';

export function OverviewPage() {
  return <NeedsRun><Overview /></NeedsRun>;
}

function Overview() {
  const { run, setInspect } = useStore();
  const r = run!;
  const s = r.summary;
  const [metric, setMetric] = useState<'packets' | 'bytes'>('packets');
  const [showTable, setShowTable] = useState(false);

  const series = useMemo(() => s.buckets.map((b) => ({ t: b.t, label: fmtTs(b.t, false).slice(0, 8), packets: b.packets, bytes: b.bytes, findings: b.findings })), [s.buckets]);
  const protos = useMemo(() => {
    const e = Object.entries(s.protocols).sort((a, b) => b[1] - a[1]);
    const head = e.slice(0, 7).map(([name, value], i) => ({ name, value, color: PROTO_COLORS[i] }));
    const rest = e.slice(7).reduce((a, [, v]) => a + v, 0);
    if (rest) head.push({ name: 'Other', value: rest, color: OTHER_COLOR });
    return head;
  }, [s.protocols]);
  const maxSrc = s.topSrc[0]?.bytes || 1;
  const maxDst = s.topDst[0]?.bytes || 1;

  return (
    <div className="space-y-6">
      <PageHeader title="Capture Analysis Overview" subtitle={`${r.summary.format.toUpperCase()} · ${s.linktypes.join(', ')} · ${fmtTs(s.start)} → ${fmtTs(s.end)} (${fmtDur(s.duration)})`} />
      {r.warnings.length > 0 && (
        <div className="p-3.5 rounded-lg bg-amber-500/10 border border-amber-500/30 text-amber-300 text-xs flex items-start gap-2">
          <AlertTriangle className="w-4 h-4 shrink-0 mt-0.5" />
          <div className="space-y-1"><div className="font-semibold">Parser diagnostics & evidence limitations</div>{r.warnings.map((w, i) => <div key={i} className="text-[11px] text-amber-200/90">{w}</div>)}</div>
        </div>
      )}
      <div className="grid grid-cols-2 lg:grid-cols-5 gap-4">
        <Stat label="Packets" value={s.parsedPackets.toLocaleString()} sub={s.parsedPackets < s.totalPackets ? `of ${s.totalPackets.toLocaleString()} total` : 'all decoded'} icon={<Cpu className="w-3.5 h-3.5" />} />
        <Stat label="Flows" value={s.totalFlows.toLocaleString()} sub="bidirectional, idle-timeout split" icon={<Network className="w-3.5 h-3.5" />} accent="text-indigo-400" />
        <Stat label="Bytes on wire" value={fmtBytes(s.totalBytes)} sub={`${fmtBytes(s.totalBytes / Math.max(1, s.duration))}/s avg`} icon={<HardDrive className="w-3.5 h-3.5" />} accent="text-emerald-400" />
        <Stat label="Hosts" value={s.hostsInternal + s.hostsExternal} sub={`${s.hostsInternal} internal · ${s.hostsExternal} external`} icon={<Server className="w-3.5 h-3.5" />} accent="text-amber-400" />
        <Stat label="Duration" value={fmtDur(s.duration)} sub={`${s.bucketSeconds}s buckets`} icon={<Clock className="w-3.5 h-3.5" />} accent="text-fuchsia-400" />
      </div>

      <Card className="p-5">
        <SectionTitle icon={<Clock className="w-4 h-4 text-sky-400" />} right={
          <div className="flex gap-1">
            {(['packets', 'bytes'] as const).map((m) => <button key={m} onClick={() => setMetric(m)} className={`text-[11px] px-2.5 py-1 rounded-md border ${metric === m ? 'bg-sky-500/15 border-sky-500/40 text-sky-300' : 'border-slate-800 text-slate-400 hover:text-slate-200'}`}>{m}</button>)}
            <button onClick={() => setShowTable(!showTable)} className="text-[11px] px-2 py-1 rounded-md border border-slate-800 text-slate-400 hover:text-slate-200" title="Table view"><Table2 className="w-3.5 h-3.5" /></button>
          </div>
        }>Traffic over time ({metric} per {s.bucketSeconds}s)</SectionTitle>
        {showTable ? (
          <div className="max-h-64 overflow-y-auto text-[11px]"><table className="w-full"><thead className="text-slate-500"><tr><th className="text-left p-1">Bucket start</th><th className="text-right p-1">Packets</th><th className="text-right p-1">Bytes</th><th className="text-right p-1">Findings</th></tr></thead>
            <tbody>{series.map((b) => <tr key={b.t} className="border-t border-slate-800/60"><td className="p-1 font-mono text-slate-400">{fmtTs(b.t)}</td><td className="p-1 text-right">{b.packets}</td><td className="p-1 text-right">{fmtBytes(b.bytes)}</td><td className="p-1 text-right">{b.findings}</td></tr>)}</tbody></table></div>
        ) : (
          <div className="h-64">
            <ResponsiveContainer>
              <AreaChart data={series} margin={{ top: 8, right: 8, left: 0, bottom: 0 }}>
                <defs><linearGradient id="g1" x1="0" y1="0" x2="0" y2="1"><stop offset="0%" stopColor="#0284c7" stopOpacity={0.45} /><stop offset="100%" stopColor="#0284c7" stopOpacity={0.02} /></linearGradient></defs>
                <CartesianGrid stroke="#1e293b" strokeDasharray="0" vertical={false} />
                <XAxis dataKey="label" tick={{ fill: '#64748b', fontSize: 10 }} axisLine={{ stroke: '#334155' }} tickLine={false} minTickGap={40} />
                <YAxis tick={{ fill: '#64748b', fontSize: 10 }} axisLine={false} tickLine={false} width={56} tickFormatter={(v) => (metric === 'bytes' ? fmtBytes(v) : v.toLocaleString())} />
                <Tooltip cursor={{ stroke: '#475569' }} content={({ active, payload }) => {
                  if (!active || !payload?.length) return null;
                  const d = payload[0].payload as (typeof series)[number];
                  return <div className="bg-ink-800 border border-slate-700 rounded-lg p-2.5 text-[11px] shadow-xl"><div className="font-mono text-slate-400 mb-1">{fmtTs(d.t)}</div><div className="text-slate-200">{d.packets.toLocaleString()} packets · {fmtBytes(d.bytes)}</div>{d.findings > 0 && <div className="text-rose-300 mt-0.5">{d.findings} finding(s) start in this bucket</div>}</div>;
                }} />
                <Area type="monotone" dataKey={metric} stroke="#0284c7" strokeWidth={2} fill="url(#g1)" dot={(p: { cx?: number; cy?: number; payload?: { findings: number }; index?: number }) => (p.payload?.findings ? <circle key={p.index} cx={p.cx} cy={p.cy} r={4.5} fill="#fb7185" stroke="#0e1626" strokeWidth={2} /> : <g key={p.index} />)} activeDot={{ r: 4, stroke: '#0e1626', strokeWidth: 2 }} isAnimationActive={false} />
              </AreaChart>
            </ResponsiveContainer>
          </div>
        )}
        <div className="text-[10px] text-slate-500 mt-2 flex items-center gap-1.5"><span className="inline-block w-2.5 h-2.5 rounded-full bg-rose-400" />Red markers: buckets where at least one finding begins.</div>
      </Card>

      <div className="grid lg:grid-cols-2 gap-5">
        <Card className="p-5">
          <SectionTitle icon={<Network className="w-4 h-4 text-indigo-400" />}>Protocol distribution (highest decoded layer)</SectionTitle>
          <div className="h-60">
            <ResponsiveContainer>
              <BarChart data={protos} layout="vertical" margin={{ left: 8, right: 40, top: 0, bottom: 0 }} barCategoryGap={4}>
                <XAxis type="number" hide />
                <YAxis type="category" dataKey="name" tick={{ fill: '#cbd5e1', fontSize: 11 }} axisLine={false} tickLine={false} width={72} />
                <Tooltip cursor={{ fill: 'rgba(148,163,184,.06)' }} content={({ active, payload }) => active && payload?.length ? <div className="bg-ink-800 border border-slate-700 rounded-lg p-2 text-[11px]"><b className="text-slate-200">{payload[0].payload.name}</b><div className="text-slate-400">{Number(payload[0].value).toLocaleString()} packets ({((Number(payload[0].value) / s.parsedPackets) * 100).toFixed(1)}%)</div></div> : null} />
                <RBar dataKey="value" radius={[0, 4, 4, 0]} isAnimationActive={false} label={{ position: 'right', fill: '#94a3b8', fontSize: 10, formatter: (v: number) => `${((v / s.parsedPackets) * 100).toFixed(1)}%` }}>
                  {protos.map((p) => <Cell key={p.name} fill={p.color} />)}
                </RBar>
              </BarChart>
            </ResponsiveContainer>
          </div>
        </Card>
        <Card className="p-5">
          <SectionTitle icon={<Server className="w-4 h-4 text-amber-400" />}>Top destination ports</SectionTitle>
          <div className="space-y-2">
            {s.topPorts.map((p) => (
              <div key={p.port} className="grid grid-cols-12 gap-2 items-center text-xs">
                <span className="col-span-3 font-mono text-slate-200">{p.port}</span>
                <span className="col-span-3 text-slate-500 text-[11px]">{WELL_KNOWN[p.port] || '—'}</span>
                <div className="col-span-4"><Bar value={p.flows} max={s.topPorts[0].flows} color="#d97706" /></div>
                <span className="col-span-2 text-right text-slate-400 tabular-nums">{p.flows}</span>
              </div>
            ))}
            {!s.topPorts.length && <p className="text-xs text-slate-500">No port-based flows.</p>}
          </div>
        </Card>
      </div>

      <div className="grid lg:grid-cols-2 gap-5">
        {[{ title: 'Top sources (by bytes sent)', rows: s.topSrc, max: maxSrc, color: '#0284c7' }, { title: 'Top destinations (by bytes received)', rows: s.topDst, max: maxDst, color: '#059669' }].map((blk) => (
          <Card key={blk.title} className="p-5">
            <SectionTitle icon={<HardDrive className="w-4 h-4 text-sky-400" />}>{blk.title}</SectionTitle>
            <div className="space-y-1.5">
              {blk.rows.map((t) => {
                const h = r.hosts.find((x) => x.ip === t.ip);
                return (
                  <button key={t.ip} onClick={() => setInspect({ inspectHost: t.ip })} className="w-full grid grid-cols-12 gap-2 items-center text-xs hover:bg-slate-800/40 rounded px-1 py-1">
                    <span className="col-span-5 font-mono text-slate-200 truncate text-left">{t.ip}{h?.hostnames[0] && <span className="text-slate-500"> · {h.hostnames[0]}</span>}</span>
                    <span className="col-span-1">{h && <Pill className={h.internal ? 'text-emerald-300' : 'text-amber-300'}>{h.internal ? 'int' : 'ext'}</Pill>}</span>
                    <div className="col-span-3"><Bar value={t.bytes} max={blk.max} color={blk.color} /></div>
                    <span className="col-span-3 text-right text-slate-400 tabular-nums">{fmtBytes(t.bytes)}</span>
                  </button>
                );
              })}
            </div>
          </Card>
        ))}
      </div>

      <div className="grid lg:grid-cols-3 gap-5">
        <Card className="p-5">
          <SectionTitle icon={<Globe2 className="w-4 h-4 text-emerald-400" />}>Top DNS queries</SectionTitle>
          {s.topDomains.length ? s.topDomains.map((d) => <div key={d.name} className="flex justify-between gap-2 text-[11px] py-1 border-b border-slate-800/50"><span className="font-mono text-slate-300 truncate">{d.name}</span><span className="text-slate-500 tabular-nums">{d.count}</span></div>) : <p className="text-xs text-slate-500">No DNS queries observed.</p>}
        </Card>
        <Card className="p-5">
          <SectionTitle icon={<Lock className="w-4 h-4 text-fuchsia-400" />}>TLS server names (SNI)</SectionTitle>
          {s.topSni.length ? s.topSni.map((d) => <div key={d.name} className="flex justify-between gap-2 text-[11px] py-1 border-b border-slate-800/50"><span className="font-mono text-slate-300 truncate">{d.name}</span><span className="text-slate-500 tabular-nums">{d.count}</span></div>) : <p className="text-xs text-slate-500">No TLS ClientHello SNI observed.</p>}
        </Card>
        <Card className="p-5">
          <SectionTitle icon={<Timer className="w-4 h-4 text-sky-400" />}>Pipeline stage timings</SectionTitle>
          {r.timings.map((t) => (
            <div key={t.stage} className="grid grid-cols-12 gap-2 items-center text-[11px] py-1">
              <span className="col-span-5 text-slate-400">{t.stage.replace(/_/g, ' ')}</span>
              <div className="col-span-4"><Bar value={t.ms} max={Math.max(...r.timings.map((x) => x.ms))} /></div>
              <span className="col-span-3 text-right font-mono text-slate-300">{t.ms} ms</span>
            </div>
          ))}
          <div className="text-[10px] text-slate-500 mt-2">Run {r.runId} · config {r.configHash}</div>
        </Card>
      </div>
    </div>
  );
}
