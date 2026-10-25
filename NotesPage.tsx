import { useMemo, useState } from 'react';
import { FileText, MessageSquarePlus, History, Download, UserCircle } from 'lucide-react';
import { useStore } from '../store/useStore';
import { Card, PageHeader, SectionTitle, Btn, Textarea, Input, Select, EmptyState, Pill } from '../components/ui';
import { download, humanize } from '../lib/format';
import { toCsv } from '../lib/report';

export function NotesPage() {
  const s = useStore();
  const [note, setNote] = useState('');
  const [kind, setKind] = useState('');
  const events = useMemo(() => s.events.filter((e) => e.caseId === s.activeCaseId && (!kind || e.action === kind)), [s.events, s.activeCaseId, kind]);
  const actions = [...new Set(s.events.filter((e) => e.caseId === s.activeCaseId).map((e) => e.action))];
  if (!s.activeCaseId) return <EmptyState icon={<FileText className="w-6 h-6" />} title="No active case" body="Create a case to start recording notes and audit events." />;

  return (
    <div className="space-y-5">
      <PageHeader title="Analyst Notes & Audit Trail" subtitle="Every upload, analysis run, disposition, tag, assignment, incident split/merge, settings change and export is recorded with actor and timestamp." right={
        <Btn size="sm" variant="secondary" onClick={() => download('audit_trail.csv', toCsv(events.map((e) => ({ timestamp: e.ts, actor: e.actor, action: e.action, finding: e.findingId || '', prior: e.prior || '', next: e.next || '', note: e.note }))), 'text/csv')}><Download className="w-3.5 h-3.5" />Export audit CSV</Btn>
      } />
      <div className="grid lg:grid-cols-3 gap-5">
        <div className="space-y-5">
          <Card className="p-5">
            <SectionTitle icon={<UserCircle className="w-4 h-4 text-sky-400" />}>Analyst identity</SectionTitle>
            <Input defaultValue={s.analyst} onBlur={(e) => e.target.value.trim() && s.setAnalyst(e.target.value.trim())} className="w-full" />
            <p className="text-[10px] text-slate-500 mt-2">Recorded as the actor on new audit events in this browser.</p>
          </Card>
          <Card className="p-5">
            <SectionTitle icon={<MessageSquarePlus className="w-4 h-4 text-emerald-400" />}>Add case note</SectionTitle>
            <Textarea rows={5} value={note} onChange={(e) => setNote(e.target.value)} placeholder="Hypotheses, interviews, external confirmations, hand-off notes…" />
            <Btn className="mt-2 w-full" disabled={!note.trim()} onClick={async () => { await s.addNote(note.trim()); setNote(''); s.toast('success', 'Note recorded'); }}>Record note</Btn>
          </Card>
        </div>
        <Card className="p-5 lg:col-span-2">
          <SectionTitle icon={<History className="w-4 h-4 text-amber-400" />} right={<Select value={kind} onChange={(e) => setKind(e.target.value)}><option value="">All events ({s.events.filter((e) => e.caseId === s.activeCaseId).length})</option>{actions.map((a) => <option key={a} value={a}>{humanize(a)}</option>)}</Select>}>Audit trail</SectionTitle>
          <div className="space-y-2 max-h-[70vh] overflow-y-auto pr-1">
            {events.map((e) => (
              <div key={e.id} className="p-3 rounded-lg border border-slate-800 bg-slate-950/50 text-xs">
                <div className="flex flex-wrap items-center gap-1.5 text-[10px]">
                  <span className="font-mono text-slate-500">{e.ts.replace('T', ' ').slice(0, 19)}Z</span>
                  <Pill className={e.action === 'note' ? 'text-emerald-300' : e.action === 'disposition' ? 'text-amber-300' : ''}>{humanize(e.action)}</Pill>
                  <span className="text-slate-400">by <b className="text-slate-300">{e.actor}</b></span>
                  {e.findingId && <button onClick={() => s.setInspect({ inspectFindingId: e.findingId! })} className="font-mono text-rose-300 hover:underline">{e.findingId}</button>}
                  {e.prior && e.next && <span className="text-slate-500">{humanize(e.prior)} → <span className="text-slate-300">{humanize(e.next)}</span></span>}
                </div>
                <div className="text-slate-300 mt-1 break-words leading-relaxed">{e.note}</div>
              </div>
            ))}
            {!events.length && <p className="text-xs text-slate-500">No events.</p>}
          </div>
        </Card>
      </div>
    </div>
  );
}
