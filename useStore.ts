import { create } from 'zustand';
import * as db from './db';
import { hashBuffer, runAnalysis } from './engineClient';
import type { AnalysisConfig, AnalysisResult, Finding, FindingStatus } from '../engine/types';
import { DEFAULT_CONFIG } from '../engine/config';
import { uid } from '../engine/util';

export type Provenance = 'synthetic' | 'public_dataset' | 'authorized_lab' | 'production_authorized' | 'unknown';

export interface CaseRec {
  id: string;
  name: string;
  description: string;
  status: 'open' | 'in_progress' | 'closed';
  owner: string;
  createdAt: string;
  tags: string[];
}

export interface CaptureRec {
  id: string;
  caseId: string;
  filename: string;
  size: number;
  sha256: string;
  format: 'pcap' | 'pcapng';
  provenance: Provenance;
  uploadedAt: string;
  packetCount?: number;
  start?: number | null;
  end?: number | null;
  lastRunId?: string;
  findingsCount?: number;
}

export interface AuditEvent {
  id: string;
  caseId: string;
  findingId?: string;
  action: string;
  prior?: string;
  next?: string;
  note: string;
  actor: string;
  ts: string;
}

export interface Toast { id: string; kind: 'success' | 'error' | 'info'; text: string }

export interface Progress { stage: string; pct: number; detail?: string; captureId: string }

interface State {
  ready: boolean;
  persistent: boolean;
  cases: CaseRec[];
  captures: CaptureRec[];
  events: AuditEvent[];
  activeCaseId: string | null;
  activeCaptureId: string | null;
  run: AnalysisResult | null;
  buffer: ArrayBuffer | null;
  config: AnalysisConfig;
  analyst: string;
  progress: Progress | null;
  toasts: Toast[];
  inspectFindingId: string | null;
  inspectPacket: number | null;
  inspectFlowId: string | null;
  inspectHost: string | null;
  paletteOpen: boolean;

  init: () => Promise<void>;
  toast: (kind: Toast['kind'], text: string) => void;
  dismissToast: (id: string) => void;
  setAnalyst: (name: string) => void;
  createCase: (name: string, description: string, tags?: string[]) => Promise<CaseRec>;
  updateCase: (id: string, patch: Partial<CaseRec>) => Promise<void>;
  deleteCase: (id: string) => Promise<void>;
  selectCase: (id: string) => Promise<void>;
  ingestFile: (file: File | { name: string; buffer: ArrayBuffer }, provenance: Provenance) => Promise<CaptureRec>;
  analyzeCapture: (captureId: string, cfg?: AnalysisConfig) => Promise<AnalysisResult>;
  selectCapture: (captureId: string) => Promise<void>;
  deleteCapture: (captureId: string) => Promise<void>;
  loadRunFor: (captureId: string) => Promise<AnalysisResult | null>;
  updateFinding: (findingId: string, patch: Partial<Pick<Finding, 'status' | 'tags' | 'assignee'>>, note?: string) => Promise<void>;
  addNote: (note: string, findingId?: string) => Promise<void>;
  updateRun: (mutate: (r: AnalysisResult) => AnalysisResult, action: string, note: string) => Promise<void>;
  log: (action: string, note: string, extra?: Partial<AuditEvent>) => Promise<void>;
  saveConfig: (cfg: AnalysisConfig) => Promise<void>;
  purgeAll: () => Promise<void>;
  importBundle: (json: string) => Promise<void>;
  exportBundle: () => Promise<string>;
  setInspect: (p: Partial<Pick<State, 'inspectFindingId' | 'inspectPacket' | 'inspectFlowId' | 'inspectHost'>>) => void;
  setPalette: (open: boolean) => void;
}

const now = () => new Date().toISOString();

export const useStore = create<State>((set, get) => ({
  ready: false,
  persistent: true,
  cases: [],
  captures: [],
  events: [],
  activeCaseId: null,
  activeCaptureId: null,
  run: null,
  buffer: null,
  config: DEFAULT_CONFIG,
  analyst: 'lead_analyst',
  progress: null,
  toasts: [],
  inspectFindingId: null,
  inspectPacket: null,
  inspectFlowId: null,
  inspectHost: null,
  paletteOpen: false,

  init: async () => {
    const persistent = await db.isPersistent();
    const [cases, captures, events] = await Promise.all([db.all<CaseRec>('cases'), db.all<CaptureRec>('captures'), db.all<AuditEvent>('events')]);
    const cfg = (await db.get<AnalysisConfig>('meta', 'config')) || DEFAULT_CONFIG;
    const analyst = (await db.get<string>('meta', 'analyst')) || 'lead_analyst';
    const lastCase = await db.get<string>('meta', 'activeCase');
    cases.sort((a, b) => b.createdAt.localeCompare(a.createdAt));
    events.sort((a, b) => b.ts.localeCompare(a.ts));
    const merged: AnalysisConfig = { ...DEFAULT_CONFIG, ...cfg, ml: { ...DEFAULT_CONFIG.ml, ...cfg.ml }, thresholds: { ...DEFAULT_CONFIG.thresholds, ...cfg.thresholds }, weights: { ...DEFAULT_CONFIG.weights, ...cfg.weights } };
    set({ persistent, cases, captures, events, config: merged, analyst, ready: true });
    const active = cases.find((c) => c.id === lastCase) || cases[0];
    if (active) await get().selectCase(active.id);
  },

  toast: (kind, text) => {
    const id = uid('t');
    set((s) => ({ toasts: [...s.toasts, { id, kind, text }] }));
    setTimeout(() => get().dismissToast(id), 4500);
  },
  dismissToast: (id) => set((s) => ({ toasts: s.toasts.filter((t) => t.id !== id) })),

  setAnalyst: (name) => {
    set({ analyst: name });
    db.put('meta', 'analyst', name);
  },

  log: async (action, note, extra = {}) => {
    const caseId = extra.caseId || get().activeCaseId;
    if (!caseId) return;
    const ev: AuditEvent = { id: uid('ev'), caseId, action, note, actor: get().analyst, ts: now(), ...extra };
    await db.put('events', ev.id, ev);
    set((s) => ({ events: [ev, ...s.events] }));
  },

  createCase: async (name, description, tags = []) => {
    const c: CaseRec = { id: uid('case_'), name, description, status: 'open', owner: get().analyst, createdAt: now(), tags };
    await db.put('cases', c.id, c);
    set((s) => ({ cases: [c, ...s.cases] }));
    await get().selectCase(c.id);
    await get().log('case_created', `Case "${name}" created`, { caseId: c.id });
    return c;
  },

  updateCase: async (id, patch) => {
    const c = get().cases.find((x) => x.id === id);
    if (!c) return;
    const next = { ...c, ...patch };
    await db.put('cases', id, next);
    set((s) => ({ cases: s.cases.map((x) => (x.id === id ? next : x)) }));
    if (patch.status && patch.status !== c.status) await get().log('case_status', `Case status ${c.status} → ${patch.status}`, { caseId: id, prior: c.status, next: patch.status });
  },

  deleteCase: async (id) => {
    const caps = get().captures.filter((c) => c.caseId === id);
    for (const cap of caps) {
      if (cap.lastRunId) await db.del('runs', cap.lastRunId);
      await db.del('blobs', cap.id);
      await db.del('captures', cap.id);
    }
    for (const ev of get().events.filter((e) => e.caseId === id)) await db.del('events', ev.id);
    await db.del('cases', id);
    const cases = get().cases.filter((c) => c.id !== id);
    set((s) => ({ cases, captures: s.captures.filter((c) => c.caseId !== id), events: s.events.filter((e) => e.caseId !== id) }));
    if (get().activeCaseId === id) {
      set({ activeCaseId: null, activeCaptureId: null, run: null, buffer: null });
      if (cases[0]) await get().selectCase(cases[0].id);
    }
  },

  selectCase: async (id) => {
    set({ activeCaseId: id, activeCaptureId: null, run: null, buffer: null });
    db.put('meta', 'activeCase', id);
    const caps = get().captures.filter((c) => c.caseId === id).sort((a, b) => b.uploadedAt.localeCompare(a.uploadedAt));
    const withRun = caps.find((c) => c.lastRunId);
    if (withRun) await get().selectCapture(withRun.id);
    else if (caps[0]) set({ activeCaptureId: caps[0].id });
  },

  ingestFile: async (file, provenance) => {
    const caseId = get().activeCaseId;
    if (!caseId) throw new Error('Create or select a case first.');
    const name = 'buffer' in file ? file.name : file.name;
    const safeName = name.replace(/[^\w.\-() ]+/g, '_').slice(0, 120);
    const ext = safeName.toLowerCase().split('.').pop();
    if (!['pcap', 'pcapng', 'cap', 'dmp'].includes(ext || '')) throw new Error(`Unsupported file extension ".${ext}". Accepted: .pcap, .pcapng, .cap`);
    const size = 'buffer' in file ? file.buffer.byteLength : file.size;
    const maxB = get().config.maxFileMB * 1024 * 1024;
    if (size > maxB) throw new Error(`File is ${(size / 1048576).toFixed(1)} MB — above the ${get().config.maxFileMB} MB limit (configurable in Settings).`);
    if (size < 24) throw new Error('File is too small to be a valid capture.');
    const buf = 'buffer' in file ? file.buffer : await file.arrayBuffer();
    const h = await hashBuffer(buf);
    if (!h.format) throw new Error('Magic bytes do not match PCAP (a1b2c3d4 / a1b23c4d) or PCAPNG (0a0d0d0a). The file was rejected and not stored.');
    const dup = get().captures.find((c) => c.caseId === caseId && c.sha256 === h.sha256);
    if (dup) {
      get().toast('info', 'This exact capture (same SHA-256) is already in the case — reusing it.');
      return dup;
    }
    const cap: CaptureRec = { id: uid('cap_'), caseId, filename: safeName, size, sha256: h.sha256, format: h.format, provenance, uploadedAt: now() };
    await db.put('blobs', cap.id, h.buffer);
    await db.put('captures', cap.id, cap);
    set((s) => ({ captures: [...s.captures, cap], activeCaptureId: cap.id, buffer: h.buffer, run: null }));
    await get().log('capture_ingested', `Ingested ${safeName} (${(size / 1024).toFixed(1)} KB, ${h.format}, provenance: ${provenance}) sha256=${h.sha256}`);
    return cap;
  },

  analyzeCapture: async (captureId, cfg) => {
    const cap = get().captures.find((c) => c.id === captureId);
    if (!cap) throw new Error('Capture not found');
    const config = cfg || get().config;
    let buf = get().activeCaptureId === captureId && get().buffer ? get().buffer! : await db.get<ArrayBuffer>('blobs', captureId);
    if (!buf) throw new Error('Original capture bytes are no longer stored (purged). Re-upload the file to re-analyse.');
    buf = buf.slice(0);
    const runId = uid('run_');
    set({ progress: { stage: 'Queued', pct: 0, captureId } });
    try {
      const { result, buffer } = await runAnalysis(buf, { runId, captureId, caseId: cap.caseId }, config, (stage, pct, detail) => set({ progress: { stage, pct, detail, captureId } }));
      // carry analyst dispositions forward when re-running the same capture
      if (cap.lastRunId) {
        const prev = await db.get<AnalysisResult>('runs', cap.lastRunId);
        if (prev) {
          const key = (f: Finding) => `${f.detectorId}|${f.title}`;
          const prior = new Map(prev.findings.map((f) => [key(f), f]));
          for (const f of result.findings) {
            const p = prior.get(key(f));
            if (p) { f.status = p.status; f.tags = [...new Set([...p.tags, ...f.tags])]; f.assignee = p.assignee; }
          }
          await db.del('runs', cap.lastRunId);
        }
      }
      await db.put('runs', runId, result);
      const updated: CaptureRec = { ...cap, lastRunId: runId, packetCount: result.summary.totalPackets, start: result.summary.start, end: result.summary.end, findingsCount: result.findings.filter((f) => !f.suppressed).length };
      await db.put('captures', cap.id, updated);
      set((s) => ({ run: result, buffer, activeCaptureId: captureId, captures: s.captures.map((c) => (c.id === cap.id ? updated : c)), progress: null }));
      await get().log('analysis_run', `Analysis ${runId} on ${cap.filename}: ${result.summary.parsedPackets} packets, ${result.flows.length} flows, ${updated.findingsCount} findings, ${result.incidents.length} incidents (config ${result.configHash})`);
      return result;
    } catch (e) {
      set({ progress: null });
      throw e;
    }
  },

  loadRunFor: async (captureId) => {
    const cap = get().captures.find((c) => c.id === captureId);
    if (!cap?.lastRunId) return null;
    return (await db.get<AnalysisResult>('runs', cap.lastRunId)) || null;
  },

  selectCapture: async (captureId) => {
    const cap = get().captures.find((c) => c.id === captureId);
    if (!cap) return;
    const [run, buffer] = await Promise.all([cap.lastRunId ? db.get<AnalysisResult>('runs', cap.lastRunId) : undefined, db.get<ArrayBuffer>('blobs', captureId)]);
    set({ activeCaptureId: captureId, run: run || null, buffer: buffer || null });
  },

  deleteCapture: async (captureId) => {
    const cap = get().captures.find((c) => c.id === captureId);
    if (!cap) return;
    if (cap.lastRunId) await db.del('runs', cap.lastRunId);
    await db.del('blobs', captureId);
    await db.del('captures', captureId);
    set((s) => ({ captures: s.captures.filter((c) => c.id !== captureId), ...(s.activeCaptureId === captureId ? { activeCaptureId: null, run: null, buffer: null } : {}) }));
    await get().log('capture_deleted', `Capture ${cap.filename} (sha256 ${cap.sha256.slice(0, 16)}…) and its analysis were permanently deleted`);
  },

  updateFinding: async (findingId, patch, note) => {
    const run = get().run;
    if (!run) return;
    const f = run.findings.find((x) => x.id === findingId);
    if (!f) return;
    const prior = f.status;
    const updated = { ...f, ...patch };
    const next: AnalysisResult = { ...run, findings: run.findings.map((x) => (x.id === findingId ? updated : x)) };
    await db.put('runs', run.runId, next);
    set({ run: next });
    if (patch.status && patch.status !== prior) await get().log('disposition', note || `Disposition ${prior} → ${patch.status}`, { findingId, prior, next: patch.status });
    else if (patch.tags) await get().log('tagged', note || `Tags set to [${patch.tags.join(', ')}]`, { findingId });
    else if (patch.assignee !== undefined) await get().log('assigned', note || `Assigned to ${patch.assignee || 'nobody'}`, { findingId });
  },

  updateRun: async (mutate, action, note) => {
    const run = get().run;
    if (!run) return;
    const next = mutate(structuredClone(run));
    await db.put('runs', run.runId, next);
    set({ run: next });
    await get().log(action, note);
  },

  addNote: async (note, findingId) => {
    await get().log('note', note, { findingId });
  },

  saveConfig: async (cfg) => {
    await db.put('meta', 'config', cfg);
    set({ config: cfg });
    await get().log('settings_changed', 'Analysis configuration updated');
  },

  purgeAll: async () => {
    await db.clearAll();
    set({ cases: [], captures: [], events: [], activeCaseId: null, activeCaptureId: null, run: null, buffer: null, config: DEFAULT_CONFIG });
  },

  exportBundle: async () => {
    const caseId = get().activeCaseId;
    const c = get().cases.find((x) => x.id === caseId);
    if (!c) throw new Error('No active case');
    const caps = get().captures.filter((x) => x.caseId === caseId);
    const runs = [];
    for (const cap of caps) if (cap.lastRunId) { const r = await db.get<AnalysisResult>('runs', cap.lastRunId); if (r) runs.push(r); }
    await get().log('export', 'Case bundle exported (JSON)');
    return JSON.stringify({ format: 'netsentry-xai-case-bundle', version: 1, exportedAt: now(), exportedBy: get().analyst, case: c, captures: caps, runs, events: get().events.filter((e) => e.caseId === caseId) });
  },

  importBundle: async (json) => {
    const b = JSON.parse(json);
    if (b.format !== 'netsentry-xai-case-bundle') throw new Error('Not a NetSentry XAI case bundle.');
    const c: CaseRec = { ...b.case, id: uid('case_'), name: `${b.case.name} (imported)` };
    const capMap = new Map<string, string>();
    await db.put('cases', c.id, c);
    const caps: CaptureRec[] = [];
    for (const cap of b.captures as CaptureRec[]) {
      const nid = uid('cap_');
      capMap.set(cap.id, nid);
      const run = (b.runs as AnalysisResult[]).find((r) => r.captureId === cap.id);
      const nc = { ...cap, id: nid, caseId: c.id, lastRunId: run ? uid('run_') : undefined };
      if (run) await db.put('runs', nc.lastRunId!, { ...run, runId: nc.lastRunId, captureId: nid, caseId: c.id });
      await db.put('captures', nid, nc);
      caps.push(nc);
    }
    const evs: AuditEvent[] = (b.events as AuditEvent[]).map((e) => ({ ...e, id: uid('ev'), caseId: c.id }));
    for (const e of evs) await db.put('events', e.id, e);
    set((s) => ({ cases: [c, ...s.cases], captures: [...s.captures, ...caps], events: [...evs, ...s.events] }));
    await get().selectCase(c.id);
    await get().log('import', `Case bundle imported (${caps.length} captures; original bytes not included — analysis results only)`);
  },

  setInspect: (p) => set(p),
  setPalette: (open) => set({ paletteOpen: open }),
}));

export const STATUS_LABEL: Record<FindingStatus, string> = {
  new: 'New',
  under_review: 'Under review',
  benign_false_positive: 'Benign / FP',
  suspicious: 'Suspicious',
  escalated: 'Escalated',
};
