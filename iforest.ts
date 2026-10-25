// Isolation Forest (Liu, Ting & Zhou 2008) — seeded, deterministic, in-browser.
// Feature attribution uses a path-based, DIFFI-style approximation: each split
// on the isolation path credits its feature by 1/(depth+1). This is labelled as
// an approximation in the UI — it is NOT SHAP.
import { mulberry32 } from './util';

interface Node {
  f?: number;
  t?: number;
  l?: Node;
  r?: Node;
  size?: number; // leaf size
}

const EULER = 0.5772156649;
export function cFactor(n: number) {
  if (n <= 1) return 0;
  if (n === 2) return 1;
  return 2 * (Math.log(n - 1) + EULER) - (2 * (n - 1)) / n;
}

export interface IForestResult {
  scores: number[]; // 0..1, ~0.5 = typical, → 1 = isolated quickly
  attributions: number[][]; // per sample, per feature share (sums to 1)
  threshold: number;
}

export function isolationForest(
  X: number[][],
  opts: { trees: number; sampleSize: number; seed: number; contamination: number },
): IForestResult {
  const n = X.length;
  const d = X[0]?.length || 0;
  const rand = mulberry32(opts.seed);
  const psi = Math.min(opts.sampleSize, n);
  const maxDepth = Math.ceil(Math.log2(Math.max(2, psi)));

  const build = (idx: number[], depth: number): Node => {
    if (depth >= maxDepth || idx.length <= 1) return { size: idx.length };
    // pick a feature that actually varies within this node (bounded retries)
    for (let attempt = 0; attempt < d * 2; attempt++) {
      const f = Math.floor(rand() * d);
      let lo = Infinity, hi = -Infinity;
      for (const i of idx) {
        const v = X[i][f];
        if (v < lo) lo = v;
        if (v > hi) hi = v;
      }
      if (hi - lo < 1e-12) continue;
      const t = lo + rand() * (hi - lo);
      const L: number[] = [];
      const R: number[] = [];
      for (const i of idx) (X[i][f] < t ? L : R).push(i);
      return { f, t, l: build(L, depth + 1), r: build(R, depth + 1) };
    }
    return { size: idx.length };
  };

  const trees: Node[] = [];
  const all = Array.from({ length: n }, (_, i) => i);
  for (let k = 0; k < opts.trees; k++) {
    // sample without replacement (partial Fisher–Yates)
    const s = all.slice();
    for (let i = 0; i < psi; i++) {
      const j = i + Math.floor(rand() * (n - i));
      [s[i], s[j]] = [s[j], s[i]];
    }
    trees.push(build(s.slice(0, psi), 0));
  }

  const cn = cFactor(psi);
  const scores: number[] = [];
  const attributions: number[][] = [];
  for (let i = 0; i < n; i++) {
    let total = 0;
    const credit = new Array(d).fill(0);
    for (const tree of trees) {
      let node = tree;
      let depth = 0;
      while (node.f !== undefined) {
        credit[node.f] += 1 / (depth + 1);
        node = X[i][node.f] < node.t! ? node.l! : node.r!;
        depth++;
      }
      total += depth + cFactor(node.size || 1);
    }
    const eh = total / trees.length;
    scores.push(Math.pow(2, -eh / (cn || 1)));
    const sum = credit.reduce((a, b) => a + b, 0) || 1;
    attributions.push(credit.map((c) => c / sum));
  }
  const sorted = [...scores].sort((a, b) => b - a);
  const k = Math.max(1, Math.floor(n * opts.contamination));
  const threshold = sorted[Math.min(k - 1, sorted.length - 1)] ?? 1;
  return { scores, attributions, threshold };
}
