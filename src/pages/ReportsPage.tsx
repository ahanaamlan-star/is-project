import { useMemo, useState } from 'react';
import { FileCheck2, FileJson, FileSpreadsheet, Printer, Share2, Eye, FileCode2 } from 'lucide-react';
import { useStore } from '../store/useStore';
import { NeedsRun } from '../components/Guards';
import { Card, PageHeader, SectionTitle, Btn, Input } from '../components/ui';
import { download } from '../lib/format';
import { htmlReport, jsonReport, findingsCsv, flowsCsv, stixBundle, selectFindings, type ReportInput } from '../lib/report';

export function ReportsPage() {
  return <NeedsRun><Reports /></NeedsRun>;
}

function Reports() {
  const s = useStore();
  const run = s.run!;
  const c = s.cases.find((x) => x.id === s.activeCaseId)!;
  const cap = s.captures.find((x) => x.id === s.activeCaptureId)!;
  const [signoff, setSignoff] = useState('');
  const [incDismissed, setIncDismissed] = useState(false);
  const [incSuppressed, setIncSuppressed] = useState(false);
  const input: ReportInput = { c, cap, run, events: s.events.filter((e) => e.caseId === c.id), analyst: s.analyst, signoff, includeDismissed: incDismissed, includeSuppressed: incSuppressed };
  const html = useMemo(() => htmlReport(input), [run, c, cap, signoff, incDismissed, incSuppressed, s.events, s.analyst]); // eslint-disable-line
  const base = `${c.name.replace(/\W+/g, '_')}_${run.runId}`;
  const count = selectFindings(input).length;

  const exp = async (kind: string, fn: () => void) => { fn(); await s.log('export', `Exported ${kind} report (${count} findings)`); s.toast('success', `${kind} exported`); };
  const print = () => {
    const w = window.open('', '_blank');
    if (!w) { s.toast('error', 'Pop-up blocked — allow pop-ups to print / save as PDF, or download the HTML report.'); return; }
    w.document.open(); w.document.write(html); w.document.close();
    setTimeout(() => { w.focus(); w.print(); }, 400);
    s.log('export', 'Printed / saved PDF report');
  };

  return (
    <div className="space-y-5">
      <PageHeader title="Investigation Reports" subtitle="Reports bundle the executive summary, capture provenance (SHA-256), incidents, every finding with its evidence and explanation, analysis configuration and versions, limitations, detector catalogue and the audit trail." />
      <div className="grid lg:grid-cols-3 gap-5">
        <div className="space-y-5">
          <Card className="p-5 space-y-3">
            <SectionTitle icon={<FileCheck2 className="w-4 h-4 text-sky-400" />}>Report options</SectionTitle>
            <label className="text-[11px] text-slate-400 block">Reviewer / sign-off name<Input value={signoff} onChange={(e) => setSignoff(e.target.value)} placeholder="e.g. SOC lead" className="w-full mt-1" /></label>
            <label className="text-[11px] text-slate-400 flex items-center gap-2"><input type="checkbox" checked={incDismissed} onChange={(e) => setIncDismissed(e.target.checked)} />Include findings dispositioned benign / FP</label>
            <label className="text-[11px] text-slate-400 flex items-center gap-2"><input type="checkbox" checked={incSuppressed} onChange={(e) => setIncSuppressed(e.target.checked)} />Include allowlisted (suppressed) findings</label>
            <div className="text-[11px] text-slate-500">{count} findings will be included.</div>
          </Card>
          <Card className="p-5 space-y-2">
            <SectionTitle>Export</SectionTitle>
            <Btn className="w-full justify-start" onClick={print}><Printer className="w-4 h-4" />Print / Save as PDF</Btn>
            <Btn variant="secondary" className="w-full justify-start" onClick={() => exp('HTML', () => download(`${base}.html`, html, 'text/html'))}><FileCode2 className="w-4 h-4" />HTML report (standalone)</Btn>
            <Btn variant="secondary" className="w-full justify-start" onClick={() => exp('JSON', () => download(`${base}.json`, jsonReport(input), 'application/json'))}><FileJson className="w-4 h-4" />JSON (machine-readable)</Btn>
            <Btn variant="secondary" className="w-full justify-start" onClick={() => exp('Findings CSV', () => download(`${base}_findings.csv`, findingsCsv(input), 'text/csv'))}><FileSpreadsheet className="w-4 h-4" />Findings CSV</Btn>
            <Btn variant="secondary" className="w-full justify-start" onClick={() => exp('Flows CSV', () => download(`${base}_flows.csv`, flowsCsv(run), 'text/csv'))}><FileSpreadsheet className="w-4 h-4" />Flows CSV</Btn>
            <Btn variant="secondary" className="w-full justify-start" onClick={() => exp('STIX 2.1', () => download(`${base}_stix21.json`, stixBundle(input), 'application/json'))}><Share2 className="w-4 h-4" />STIX 2.1 bundle (observed-data + notes)</Btn>
            <p className="text-[10px] text-slate-500 leading-relaxed pt-1">STIX export uses observed-data and analyst notes rather than indicators, so hypotheses are not shared as confirmed IOCs.</p>
          </Card>
        </div>
        <Card className="lg:col-span-2 overflow-hidden">
          <div className="px-4 py-2.5 border-b border-slate-800 text-[11px] text-slate-400 flex items-center gap-1.5"><Eye className="w-3.5 h-3.5" />Live preview</div>
          <iframe title="Report preview" srcDoc={html} sandbox="" className="w-full h-[75vh] bg-white" />
        </Card>
      </div>
    </div>
  );
}
