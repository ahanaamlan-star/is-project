/// <reference lib="webworker" />
// Analysis worker: validates, hashes and analyses captures off the UI thread.
import { analyze } from './pipeline';
import { detectFormat } from './pcap';
import type { AnalysisConfig } from './types';

type Req =
  | { type: 'analyze'; id: string; buffer: ArrayBuffer; ids: { runId: string; captureId: string; caseId: string }; config: AnalysisConfig }
  | { type: 'hash'; id: string; buffer: ArrayBuffer };

const ctx = self as unknown as DedicatedWorkerGlobalScope;

async function sha256(buf: ArrayBuffer): Promise<string> {
  const d = await crypto.subtle.digest('SHA-256', buf);
  return [...new Uint8Array(d)].map((b) => b.toString(16).padStart(2, '0')).join('');
}

ctx.onmessage = async (e: MessageEvent<Req>) => {
  const msg = e.data;
  try {
    if (msg.type === 'hash') {
      const format = detectFormat(msg.buffer);
      const hash = await sha256(msg.buffer);
      ctx.postMessage({ type: 'hash', id: msg.id, sha256: hash, format, buffer: msg.buffer }, [msg.buffer]);
      return;
    }
    if (msg.type === 'analyze') {
      const result = analyze(msg.buffer, msg.ids, msg.config, (stage, pct, detail) => ctx.postMessage({ type: 'progress', id: msg.id, stage, pct, detail }));
      ctx.postMessage({ type: 'result', id: msg.id, result, buffer: msg.buffer }, [msg.buffer]);
    }
  } catch (err) {
    const buffer = (msg as { buffer?: ArrayBuffer }).buffer;
    ctx.postMessage({ type: 'error', id: msg.id, error: err instanceof Error ? err.message : String(err), buffer }, buffer ? [buffer] : []);
  }
};
