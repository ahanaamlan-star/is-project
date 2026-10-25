import { useMemo } from 'react';
import { Binary, Network, Server, AlertTriangle } from 'lucide-react';
import { useStore } from '../store/useStore';
import { Modal, KV, Pill, SeverityBadge, Btn } from './ui';
import { fmtBytes, fmtTs, fmtDur, hexDump } from '../lib/format';
import { WELL_KNOWN } from '../engine/util';

export function PacketModal() {
  const { run, buffer, inspectPacket, setInspect } = useStore();
  const p = run && inspectPacket != null ? run.packets[inspectPacket - 1] : null;
  const rows = useMemo(() => (p && buffer && p.off + p.caplen <= buffer.byteLength ? hexDump(new Uint8Array(buffer, p.off, p.caplen)) : []), [p, buffer]);
  if (!p) return null;
  const flow = run!.flows.find((f) => f.packetIdx.includes(p.i));
  const related = run!.findings.filter((f) => f.evidence.packetIdx.includes(p.i));
  const m = p.meta;
  return (
    <Modal open wide onClose={() => setInspect({ inspectPacket: null })} header={
      <div><div className="text-[11px] text-slate-500 uppercase tracking-wider font-bold flex items-center gap-1.5"><Binary className="w-3.5 h-3.5 text-emerald-400" />Packet #{p.i}</div>
        <div className="text-sm font-mono text-slate-200 mt-1 break-all">{p.info}</div></div>
    }>
      <div className="grid md:grid-cols-2 gap-4">
        <div className="space-y-4">
          <div className="bg-slate-900/60 border border-slate-800 rounded-lg p-4">
            <div className="text-[11px] font-bold uppercase tracking-wider text-slate-400 mb-2">Frame</div>
            <KV k="Timestamp" v={fmtTs(p.ts)} mono />
            <KV k="Wire length / captured" v={`${p.len} / ${p.caplen} bytes${p.caplen < p.len ? ' (truncated)' : ''}`} />
            <KV k="File offset" v={`0x${p.off.toString(16)}`} mono />
            {p.srcMac && <KV k="Source MAC" v={p.srcMac} mono />}
            {p.dstMac && <KV k="Destination MAC" v={p.dstMac} mono />}
          </div>
          <div className="bg-slate-900/60 border border-slate-800 rounded-lg p-4">
            <div className="text-[11px] font-bold uppercase tracking-wider text-slate-400 mb-2">Network & transport</div>
            <KV k="Source" v={`${p.src ?? '—'}${p.sport != null ? ':' + p.sport : ''}`} mono />
            <KV k="Destination" v={`${p.dst ?? '—'}${p.dport != null ? ':' + p.dport + (WELL_KNOWN[p.dport] ? ` (${WELL_KNOWN[p.dport]})` : '') : ''}`} mono />
            <KV k="Transport / protocol" v={`${p.transport} / ${p.proto}`} />
            {p.ttl != null && <KV k="TTL / hop limit" v={p.ttl} />}
            {p.flags && <KV k="TCP flags" v={p.flags} mono />}
            {m.payloadLen != null && <KV k="Payload bytes (captured)" v={m.payloadLen} />}
            {m.fragment && <KV k="Fragmented" v="yes" />}
          </div>
          {(m.dns || m.tls || m.http || m.arp || m.icmp || m.cred || m.ssh) && (
            <div className="bg-slate-900/60 border border-slate-800 rounded-lg p-4">
              <div className="text-[11px] font-bold uppercase tracking-wider text-slate-400 mb-2">Application metadata</div>
              {m.dns && <>
                <KV k="DNS" v={`${m.dns.qr} id=0x${m.dns.id.toString(16)} ${m.dns.rcodeName}`} mono />
                {m.dns.query && <KV k="Query" v={`${m.dns.qtype || ''} ${m.dns.query}`} mono />}
                {m.dns.entropy != null && <KV k="Length / entropy / subdomain entropy" v={`${m.dns.queryLen} / ${m.dns.entropy} / ${m.dns.subdomainEntropy}`} />}
                {m.dns.answers?.length ? <KV k="Answers" v={m.dns.answers.join(', ')} mono /> : null}
              </>}
              {m.tls && <>
                <KV k="TLS" v={`${m.tls.type}${m.tls.version ? ' · ' + m.tls.version : ''}`} />
                {m.tls.sni && <KV k="SNI" v={m.tls.sni} mono />}
                {m.tls.alpn && <KV k="ALPN" v={m.tls.alpn.join(', ')} mono />}
                {m.tls.ja3Hash && <KV k="JA3" v={m.tls.ja3Hash} mono />}
                {m.tls.ja3sHash && <KV k="JA3S" v={m.tls.ja3sHash} mono />}
                {m.tls.cipher && <KV k="Cipher" v={m.tls.cipher} mono />}
              </>}
              {m.http && <>
                <KV k="HTTP" v={m.http.firstLine} mono />
                {m.http.host && <KV k="Host" v={m.http.host} mono />}
                {m.http.userAgent && <KV k="User-Agent" v={m.http.userAgent} mono />}
              </>}
              {m.arp && <KV k="ARP" v={`${m.arp.op}: ${m.arp.senderIp} (${m.arp.senderMac}) → ${m.arp.targetIp}`} mono />}
              {m.icmp && <KV k="ICMP" v={`type ${m.icmp.type} code ${m.icmp.code} — ${m.icmp.label}`} />}
              {m.ssh && <KV k="SSH banner" v={m.ssh} mono />}
              {m.cred && <KV k="Credential material" v={`${m.cred.protocol} ${m.cred.kind} — value redacted`} />}
            </div>
          )}
          <div className="flex flex-wrap gap-2">
            {flow && <Btn size="sm" variant="secondary" onClick={() => setInspect({ inspectPacket: null, inspectFlowId: flow.id })}><Network className="w-3.5 h-3.5" />Open flow {flow.id}</Btn>}
            {related.map((f) => <Btn key={f.id} size="sm" variant="secondary" onClick={() => setInspect({ inspectPacket: null, inspectFindingId: f.id })}><AlertTriangle className="w-3.5 h-3.5" />{f.id}</Btn>)}
          </div>
        </div>
        <div className="bg-slate-950 border border-slate-800 rounded-lg p-3 overflow-x-auto">
          <div className="text-[11px] font-bold uppercase tracking-wider text-slate-400 mb-2">Raw bytes ({p.caplen})</div>
          {rows.length ? (
            <pre className="font-mono text-[10.5px] leading-[1.55] text-slate-300">
              {rows.map((r) => <div key={r.off}><span className="text-slate-600">{r.off}</span>  <span className="text-sky-300/90">{r.hex.padEnd(47, ' ')}</span>  <span className="text-emerald-300/80">{r.ascii}</span></div>)}
            </pre>
          ) : <p className="text-xs text-slate-500">Original capture bytes are not loaded for this run (imported bundle or purged capture).</p>}
        </div>
      </div>
    </Modal>
  );
}

export function FlowModal() {
  const { run, inspectFlowId, setInspect } = useStore();
  const f = run?.flows.find((x) => x.id === inspectFlowId);
  if (!f) return null;
  const pk = f.packetIdx.slice(0, 200).map((i) => run!.packets[i - 1]).filter(Boolean);
  const related = run!.findings.filter((x) => x.evidence.flowIds.includes(f.id));
  return (
    <Modal open wide onClose={() => setInspect({ inspectFlowId: null })} header={
      <div><div className="text-[11px] text-slate-500 uppercase tracking-wider font-bold flex items-center gap-1.5"><Network className="w-3.5 h-3.5 text-indigo-400" />Flow {f.id} · {f.transport}/{f.app} · state {f.state}</div>
        <div className="text-sm font-mono text-slate-200 mt-1 break-all">{f.src}:{f.sport} ⇄ {f.dst}:{f.dport}</div></div>
    }>
      <div className="grid md:grid-cols-3 gap-4">
        <div className="bg-slate-900/60 border border-slate-800 rounded-lg p-4">
          <div className="text-[11px] font-bold uppercase tracking-wider text-slate-400 mb-2">Summary</div>
          <KV k="Start" v={fmtTs(f.start)} mono /><KV k="End" v={fmtTs(f.end)} mono /><KV k="Duration" v={fmtDur(f.duration)} />
          <KV k="Packets → / ←" v={`${f.pktsFwd} / ${f.pktsBwd}`} /><KV k="Bytes → / ←" v={`${fmtBytes(f.bytesFwd)} / ${fmtBytes(f.bytesBwd)}`} />
          <KV k="TCP flags" v={f.flagsSeen} mono />
          {f.sni && <KV k="TLS SNI" v={f.sni} mono />}{f.ja3Hash && <KV k="JA3" v={f.ja3Hash} mono />}{f.httpHost && <KV k="HTTP Host" v={f.httpHost} mono />}
          {f.dnsQueries && <KV k="DNS names" v={f.dnsQueries.slice(0, 4).join(', ')} mono />}
          {f.anomalyScore != null && <KV k="Isolation Forest score" v={<span className={f.isAnomaly ? 'text-fuchsia-300 font-bold' : ''}>{f.anomalyScore}{f.isAnomaly ? ' (outlier)' : ''}</span>} />}
          <div className="text-[10px] text-slate-500 mt-2">Canonical key: <span className="font-mono break-all">{f.key}</span></div>
        </div>
        <div className="bg-slate-900/60 border border-slate-800 rounded-lg p-4">
          <div className="text-[11px] font-bold uppercase tracking-wider text-slate-400 mb-2">Feature vector</div>
          {Object.entries(f.features).map(([k, v]) => <KV key={k} k={k} v={v} mono />)}
        </div>
        <div className="space-y-3">
          <div className="bg-slate-900/60 border border-slate-800 rounded-lg p-4">
            <div className="text-[11px] font-bold uppercase tracking-wider text-slate-400 mb-2">Related findings</div>
            {related.length ? related.map((r) => (
              <button key={r.id} onClick={() => setInspect({ inspectFlowId: null, inspectFindingId: r.id })} className="w-full text-left p-2 rounded border border-slate-800 hover:border-sky-500/40 mb-1.5">
                <div className="flex items-center gap-1.5"><SeverityBadge s={r.severity} /><span className="text-[10px] font-mono text-slate-500">{r.id}</span></div>
                <div className="text-[11px] text-slate-300 mt-1 leading-snug">{r.title}</div>
              </button>
            )) : <p className="text-xs text-slate-500">Not referenced by any finding.</p>}
          </div>
          <div className="flex gap-2 flex-wrap">
            <Btn size="sm" variant="secondary" onClick={() => setInspect({ inspectFlowId: null, inspectHost: f.src })}><Server className="w-3.5 h-3.5" />{f.src}</Btn>
            <Btn size="sm" variant="secondary" onClick={() => setInspect({ inspectFlowId: null, inspectHost: f.dst })}><Server className="w-3.5 h-3.5" />{f.dst}</Btn>
          </div>
        </div>
      </div>
      <div className="mt-4 bg-slate-950 border border-slate-800 rounded-lg overflow-x-auto max-h-72">
        <table className="w-full text-[11px]">
          <thead className="bg-slate-900 text-slate-500 sticky top-0"><tr><th className="text-left p-2">#</th><th className="text-left p-2">Time</th><th className="text-left p-2">Dir</th><th className="text-left p-2">Len</th><th className="text-left p-2">Info</th></tr></thead>
          <tbody>
            {pk.map((p) => (
              <tr key={p.i} className="border-t border-slate-900 hover:bg-slate-900/70 cursor-pointer" onClick={() => setInspect({ inspectFlowId: null, inspectPacket: p.i })}>
                <td className="p-2 font-mono text-emerald-300">{p.i}</td><td className="p-2 font-mono text-slate-400">{fmtTs(p.ts, false)}</td>
                <td className="p-2">{p.src === f.src ? '→' : '←'}</td><td className="p-2 text-slate-400">{p.len}</td><td className="p-2 font-mono text-slate-300 truncate max-w-[520px]">{p.info}</td>
              </tr>
            ))}
          </tbody>
        </table>
        {f.packetIdx.length > 200 && <div className="p-2 text-[11px] text-slate-500">Showing first 200 of {f.totalPkts} packets.</div>}
      </div>
    </Modal>
  );
}

export function HostModal() {
  const { run, inspectHost, setInspect } = useStore();
  if (!run || !inspectHost) return null;
  const h = run.hosts.find((x) => x.ip === inspectHost);
  const findings = run.findings.filter((f) => f.evidence.entities.includes(inspectHost));
  const flows = run.flows.filter((f) => f.src === inspectHost || f.dst === inspectHost).sort((a, b) => b.totalBytes - a.totalBytes).slice(0, 60);
  return (
    <Modal open wide onClose={() => setInspect({ inspectHost: null })} header={
      <div><div className="text-[11px] text-slate-500 uppercase tracking-wider font-bold flex items-center gap-1.5"><Server className="w-3.5 h-3.5 text-sky-400" />{h ? (h.internal ? 'Internal host' : 'External host') : 'Entity'}</div>
        <div className="text-base font-mono text-white mt-1 break-all">{inspectHost}</div>
        {h?.hostnames.length ? <div className="text-xs text-slate-400 mt-0.5">{h.hostnames.join(', ')}</div> : null}</div>
    }>
      {h ? (
        <div className="grid md:grid-cols-3 gap-4">
          <div className="bg-slate-900/60 border border-slate-800 rounded-lg p-4">
            <div className="text-[11px] font-bold uppercase tracking-wider text-slate-400 mb-2">Behaviour profile</div>
            <KV k="Inferred role" v={<Pill>{h.role}</Pill>} />
            <KV k="Bytes out / in" v={`${fmtBytes(h.bytesOut)} / ${fmtBytes(h.bytesIn)}`} />
            <KV k="Flows out / in" v={`${h.flowsOut} / ${h.flowsIn}`} />
            <KV k="Fan-out / fan-in" v={`${h.fanOut} / ${h.fanIn}`} />
            <KV k="Distinct dst ports" v={h.distinctDstPorts} />
            <KV k="Failed connections" v={h.failedConns} />
            <KV k="Protocols" v={h.protocols.join(', ')} />
            <KV k="MAC address(es)" v={h.macs.join(', ') || '—'} mono />
            <KV k="First / last seen" v={`${fmtTs(h.firstSeen, false)} – ${fmtTs(h.lastSeen, false)}`} mono />
            {h.topDstPorts.length > 0 && <KV k="Top dst ports" v={h.topDstPorts.slice(0, 8).join(', ')} mono />}
          </div>
          <div className="md:col-span-2 space-y-4">
            <div className="bg-slate-900/60 border border-slate-800 rounded-lg p-4">
              <div className="text-[11px] font-bold uppercase tracking-wider text-slate-400 mb-2">Findings involving this host ({findings.length})</div>
              {findings.length ? findings.map((r) => (
                <button key={r.id} onClick={() => setInspect({ inspectHost: null, inspectFindingId: r.id })} className="w-full text-left p-2 rounded border border-slate-800 hover:border-sky-500/40 mb-1.5 flex items-center gap-2">
                  <SeverityBadge s={r.severity} /><span className="text-[11px] text-slate-300 truncate">{r.title}</span>
                </button>
              )) : <p className="text-xs text-slate-500">None.</p>}
            </div>
            <div className="bg-slate-950 border border-slate-800 rounded-lg overflow-x-auto max-h-72">
              <table className="w-full text-[11px]">
                <thead className="bg-slate-900 text-slate-500 sticky top-0"><tr><th className="text-left p-2">Flow</th><th className="text-left p-2">Peer</th><th className="text-left p-2">Port</th><th className="text-left p-2">App</th><th className="text-right p-2">Bytes</th><th className="text-left p-2">State</th></tr></thead>
                <tbody>{flows.map((f) => {
                  const peer = f.src === inspectHost ? f.dst : f.src;
                  return (
                    <tr key={f.id} className="border-t border-slate-900 hover:bg-slate-900/70 cursor-pointer" onClick={() => setInspect({ inspectHost: null, inspectFlowId: f.id })}>
                      <td className="p-2 font-mono text-indigo-300">{f.id}</td><td className="p-2 font-mono">{f.src === inspectHost ? '→ ' : '← '}{peer}</td><td className="p-2">{f.dport}</td><td className="p-2">{f.app}</td><td className="p-2 text-right">{fmtBytes(f.totalBytes)}</td><td className="p-2 text-slate-400">{f.state}</td>
                    </tr>
                  );
                })}</tbody>
              </table>
            </div>
          </div>
        </div>
      ) : (
        <div className="space-y-2">
          <p className="text-xs text-slate-400">This entity (domain/name) is referenced by findings but is not an IP endpoint.</p>
          {findings.map((r) => <button key={r.id} onClick={() => setInspect({ inspectHost: null, inspectFindingId: r.id })} className="w-full text-left p-2 rounded border border-slate-800 hover:border-sky-500/40 flex items-center gap-2"><SeverityBadge s={r.severity} /><span className="text-[11px] text-slate-300">{r.title}</span></button>)}
        </div>
      )}
    </Modal>
  );
}
