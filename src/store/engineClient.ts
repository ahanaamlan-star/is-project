// Promise wrapper around the analysis Web Worker.
import type { AnalysisConfig, AnalysisResult } from '../engine/types';

type Pending = {
  resolve: (v: any) => void;
  reject: (e: Error) => void;
  onProgress?: (stage: string, pct: number, detail?: string) => void;
};

let worker: Worker | null = null;
const pending = new Map<string, Pending>();
let seq = 0;

function getWorker() {
  if (worker) return worker;
  worker = new Worker(new URL('../engine/worker.ts', import.meta.url), { type: 'module' });
  worker.onmessage = (e: MessageEvent) => {
    const m = e.data;
    const p = pending.get(m.id);
    if (!p) return;
    if (m.type === 'progress') { p.onProgress?.(m.stage, m.pct, m.detail); return; }
    pending.delete(m.id);
    if (m.type === 'error') {
      const err = new Error(m.error) as Error & { buffer?: ArrayBuffer };
      err.buffer = m.buffer;
      p.reject(err);
    } else p.resolve(m);
  };
  worker.onerror = (e) => {
    for (const [, p] of pending) p.reject(new Error(e.message || 'Analysis worker crashed'));
    pending.clear();
    worker?.terminate();
    worker = null;
  };
  return worker;
}

export function hashBuffer(buffer: ArrayBuffer): Promise<{ sha256: string; format: 'pcap' | 'pcapng' | null; buffer: ArrayBuffer }> {
  const id = `h${++seq}`;
  return new Promise((resolve, reject) => {
    pending.set(id, { resolve, reject });
    getWorker().postMessage({ type: 'hash', id, buffer }, [buffer]);
  });
}

export function runAnalysis(
  buffer: ArrayBuffer,
  ids: { runId: string; captureId: string; caseId: string },
  config: AnalysisConfig,
  onProgress?: Pending['onProgress'],
): Promise<{ result: AnalysisResult; buffer: ArrayBuffer }> {
  const id = `a${++seq}`;
  return new Promise((resolve, reject) => {
    pending.set(id, { resolve, reject, onProgress });
    getWorker().postMessage({ type: 'analyze', id, buffer, ids, config }, [buffer]);
  });
}

export function workerAlive() {
  return worker !== null;
}
