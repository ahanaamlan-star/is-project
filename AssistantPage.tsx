import { useEffect, useRef, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { Send, Bot, User, ShieldCheck, Sparkles } from 'lucide-react';
import { useStore } from '../store/useStore';
import { NeedsRun } from '../components/Guards';
import { Card, PageHeader, Btn, Input } from '../components/ui';
import { ask, SUGGESTIONS, type Answer, type Cite } from '../lib/assistant';

type Msg = { role: 'user'; text: string } | { role: 'bot'; a: Answer };

export function AssistantPage() {
  return <NeedsRun><Assistant /></NeedsRun>;
}

function rich(t: string) {
  const parts = t.split(/(\*\*[^*]+\*\*)/g);
  return parts.map((p, i) => (p.startsWith('**') ? <b key={i} className="text-white">{p.slice(2, -2)}</b> : <span key={i}>{p}</span>));
}

function Assistant() {
  const s = useStore();
  const nav = useNavigate();
  const run = s.run!;
  const [msgs, setMsgs] = useState<Msg[]>([]);
  const [q, setQ] = useState('');
  const end = useRef<HTMLDivElement>(null);
  useEffect(() => { setMsgs([{ role: 'bot', a: ask('what happened', run) }]); }, [run.runId]); // eslint-disable-line
  useEffect(() => { end.current?.scrollIntoView({ behavior: 'smooth', block: 'end' }); }, [msgs]);

  const send = (text: string) => {
    if (!text.trim()) return;
    setMsgs((m) => [...m, { role: 'user', text }, { role: 'bot', a: ask(text, run) }]);
    setQ('');
  };
  const open = (c: Cite) => {
    if (c.kind === 'finding') s.setInspect({ inspectFindingId: c.id });
    else if (c.kind === 'flow') s.setInspect({ inspectFlowId: c.id });
    else if (c.kind === 'host') s.setInspect({ inspectHost: c.id });
    else if (c.kind === 'packet') s.setInspect({ inspectPacket: Number(c.id) });
    else nav(`/app/incidents?id=${c.id}`);
  };
  const citeStyle: Record<Cite['kind'], string> = {
    finding: 'text-rose-300 border-rose-500/30', flow: 'text-indigo-300 border-indigo-500/30', host: 'text-sky-300 border-sky-500/30', incident: 'text-amber-300 border-amber-500/30', packet: 'text-emerald-300 border-emerald-500/30',
  };

  return (
    <div className="max-w-4xl mx-auto">
      <PageHeader title="Evidence Assistant" subtitle="Ask questions in plain language. Answers are computed deterministically from this case's structured evidence and cite the findings, flows, hosts and packets they rely on — no external AI service, nothing leaves your browser." />
      <Card className="flex flex-col h-[calc(100vh-15rem)] min-h-[480px]">
        <div className="flex-1 overflow-y-auto p-4 md:p-5 space-y-4">
          {msgs.map((m, i) => m.role === 'user' ? (
            <div key={i} className="flex justify-end gap-2"><div className="bg-sky-600/20 border border-sky-500/30 rounded-xl rounded-tr-sm px-3.5 py-2 text-xs text-sky-100 max-w-[80%]">{m.text}</div><User className="w-6 h-6 p-1 rounded-full bg-slate-800 text-slate-300 shrink-0" /></div>
          ) : (
            <div key={i} className="flex gap-2">
              <Bot className="w-6 h-6 p-1 rounded-full bg-sky-500/15 text-sky-300 shrink-0" />
              <div className="bg-slate-950/60 border border-slate-800 rounded-xl rounded-tl-sm px-4 py-3 text-xs text-slate-300 max-w-[90%] space-y-1.5 leading-relaxed">
                {m.a.text.map((t, j) => <p key={j}>{rich(t)}</p>)}
                {m.a.table && (
                  <table className="w-full text-[11px] mt-2 border border-slate-800 rounded">
                    <thead className="bg-slate-900 text-slate-500"><tr>{m.a.table.cols.map((c) => <th key={c} className="text-left p-1.5">{c}</th>)}</tr></thead>
                    <tbody>{m.a.table.rows.map((r, k) => <tr key={k} className="border-t border-slate-800">{r.map((c, l) => <td key={l} className="p-1.5 font-mono">{c}</td>)}</tr>)}</tbody>
                  </table>
                )}
                {m.a.cites.length > 0 && (
                  <div className="flex flex-wrap gap-1 pt-2 border-t border-slate-800/80 mt-2">
                    <span className="text-[10px] text-slate-500 mr-1 flex items-center gap-1"><ShieldCheck className="w-3 h-3" />Evidence:</span>
                    {m.a.cites.map((c) => <button key={`${c.kind}-${c.id}`} onClick={() => open(c)} className={`text-[10px] font-mono px-1.5 py-0.5 rounded border bg-slate-900 hover:bg-slate-800 ${citeStyle[c.kind]}`}>{c.label}</button>)}
                  </div>
                )}
              </div>
            </div>
          ))}
          <div ref={end} />
        </div>
        <div className="border-t border-slate-800 p-3 space-y-2">
          <div className="flex flex-wrap gap-1.5">
            {SUGGESTIONS.slice(0, 6).map((x) => <button key={x} onClick={() => send(x)} className="text-[10px] px-2 py-1 rounded-full border border-slate-700 text-slate-400 hover:text-sky-300 hover:border-sky-500/40 flex items-center gap-1"><Sparkles className="w-2.5 h-2.5" />{x}</button>)}
          </div>
          <form onSubmit={(e) => { e.preventDefault(); send(q); }} className="flex gap-2">
            <Input value={q} onChange={(e) => setQ(e.target.value)} placeholder="e.g. What did 10.10.0.23 do?  ·  Why was NSX-0002 flagged?  ·  Was data exfiltrated?" className="flex-1 !py-2" />
            <Btn type="submit" aria-label="Send"><Send className="w-3.5 h-3.5" /></Btn>
          </form>
        </div>
      </Card>
    </div>
  );
}
