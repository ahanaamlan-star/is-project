// Minimal promise-based IndexedDB wrapper. All investigation data stays in
// the analyst's browser (local-first, privacy-by-design).
const DB_NAME = 'netsentry-xai';
const DB_VERSION = 1;
export const STORES = ['cases', 'captures', 'runs', 'blobs', 'events', 'meta'] as const;
export type StoreName = (typeof STORES)[number];

let dbp: Promise<IDBDatabase> | null = null;
let memoryFallback: Map<string, Map<string, unknown>> | null = null;

function open(): Promise<IDBDatabase> {
  if (dbp) return dbp;
  dbp = new Promise((resolve, reject) => {
    try {
      const req = indexedDB.open(DB_NAME, DB_VERSION);
      req.onupgradeneeded = () => {
        const db = req.result;
        for (const s of STORES) if (!db.objectStoreNames.contains(s)) db.createObjectStore(s);
      };
      req.onsuccess = () => resolve(req.result);
      req.onerror = () => reject(req.error);
      req.onblocked = () => reject(new Error('IndexedDB blocked'));
    } catch (e) {
      reject(e);
    }
  });
  dbp.catch(() => {
    memoryFallback = new Map(STORES.map((s) => [s, new Map()]));
  });
  return dbp;
}

async function tx<T>(store: StoreName, mode: IDBTransactionMode, fn: (s: IDBObjectStore) => IDBRequest<T>): Promise<T> {
  try {
    const db = await open();
    return await new Promise<T>((resolve, reject) => {
      const t = db.transaction(store, mode);
      const r = fn(t.objectStore(store));
      r.onsuccess = () => resolve(r.result);
      r.onerror = () => reject(r.error);
    });
  } catch (e) {
    if (!memoryFallback) memoryFallback = new Map(STORES.map((s) => [s, new Map()]));
    throw e;
  }
}

export const isPersistent = async () => {
  try { await open(); return true; } catch { return false; }
};

export async function put<T>(store: StoreName, key: string, value: T): Promise<void> {
  try { await tx(store, 'readwrite', (s) => s.put(value, key)); }
  catch { memoryFallback!.get(store)!.set(key, value); }
}
export async function get<T>(store: StoreName, key: string): Promise<T | undefined> {
  try { return (await tx(store, 'readonly', (s) => s.get(key))) as T | undefined; }
  catch { return memoryFallback?.get(store)?.get(key) as T | undefined; }
}
export async function del(store: StoreName, key: string): Promise<void> {
  try { await tx(store, 'readwrite', (s) => s.delete(key)); }
  catch { memoryFallback?.get(store)?.delete(key); }
}
export async function all<T>(store: StoreName): Promise<T[]> {
  try { return (await tx(store, 'readonly', (s) => s.getAll())) as T[]; }
  catch { return [...(memoryFallback?.get(store)?.values() || [])] as T[]; }
}
export async function clearAll(): Promise<void> {
  for (const s of STORES) {
    try { await tx(s, 'readwrite', (st) => st.clear()); } catch { memoryFallback?.get(s)?.clear(); }
  }
}
