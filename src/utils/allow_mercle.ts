import { buildPoseidon } from "circomlibjs";
import { randomBytes } from "node:crypto";

type Bigish = bigint | number | string;

type PaddingMode = "duplicate-last" | "zero-leaf";

export type FieldLike = string | number | bigint | Uint8Array;

export class PoseidonHelper {
  static _poseidon: any;
  static async init() {
    if (!this._poseidon) this._poseidon = await buildPoseidon();
  }
  static get F() {
    if (!this._poseidon) throw new Error("Poseidon not initialised");
    return this._poseidon.F;
  }
  static toF(x: FieldLike): bigint {
    // Normalize inputs into BN254 field element
    const F = PoseidonHelper.F;
    const p: bigint = F.p;
    if (typeof x === "bigint") return ((x % p) + p) % p;
    if (typeof x === "number") return BigInt(x) % p;
    if (typeof x === "string") {
      // Accept "0x..." or decimal. If it's UTF-8 text, caller must pre-encode.
      if (x.startsWith("0x") || x.startsWith("0X")) return BigInt(x) % p;
      return BigInt(x) % p;
    }
    // Uint8Array
    const hex = Buffer.from(x).toString("hex");
    return BigInt("0x" + hex) % p;
  }
  static H1(x: FieldLike): bigint {
    return this._poseidon([ x ]);
  }
  static H2(a: FieldLike, b: FieldLike): bigint {
    return this._poseidon([ a, b ]);
  }
  static H3(a: FieldLike, b: FieldLike, c: FieldLike): bigint {
    return this._poseidon([ a, b, c ]);
  }

  static genSalt(): bigint {
    if (!this._poseidon) throw new Error("Poseidon not initialised");
    const p = this._poseidon.F.p;

    const raw = randomBytes(32);
    const hex = "0x" + raw.toString("hex");
    return BigInt(hex) % p || 1n;
  }
}

interface BuildOpts {
  fixedDepth?: number;           // e.g., 16 to match circuit
  padding?: PaddingMode;         // default: "duplicate-last"
  sortAscending?: boolean;       // canonicalize order (default: true)
  uniqueValues?: boolean;        // drop duplicates (default: true)
}

interface Tree {
  depth: number;
  layers: bigint[][];     // layers[0] = padded leaves
  zeroLeaf: bigint;
  realLeafCount: number;  // number of canonical (pre-padding) leaves
}

interface Proof {
  root: bigint;
  leaf: bigint;
  indices: bigint[];           // 0 = current is left, 1 = current is right (per level from bottom to top)
  siblings: bigint[];          // sibling hash per level (same order as indices)
  index: number;               // leaf index in the padded layer
}

/** Convert to bigint safely */
function toBigInt(x: Bigish): bigint {
  if (typeof x === "bigint") return x;
  if (typeof x === "number") return BigInt(x);
  if (typeof x === "string") {
    if (x.startsWith("0x") || x.startsWith("0X")) return BigInt(x);
    return BigInt(x);
  }
  throw new Error("Unsupported type");
}

/** Next power of 2 >= n, with minimum 1 */
function nextPow2(n: number): number {
  return 1 << Math.ceil(Math.log2(Math.max(1, n)));
}

export async function canonicalizeValues(values: Bigish[]): Promise<bigint[]> {
  await PoseidonHelper.init();
  // 1) normalize to field
  const asField = values.map(v => PoseidonHelper.toF(toBigInt(v)));
  // 2) unique
  const uniq = Array.from(new Set(asField.map(x => x.toString()))).map(s => BigInt(s));
  // 3) sort ascending (fixed order)
  uniq.sort((a,b) => (a < b ? -1 : a > b ? 1 : 0));
  return uniq;
}

export async function buildAllowTree(values: Bigish[], opts: BuildOpts = {}): Promise<Tree> {
  await PoseidonHelper.init();

  // 0) canonicalize ONCE here
  const asField = values.map(v => PoseidonHelper.toF(v));
  const uniq = Array.from(new Set(asField.map(x => x.toString()))).map(s => BigInt(s));
  uniq.sort((a,b) => (a < b ? -1 : a > b ? 1 : 0));
  const canon = uniq;

  // 1) leaves = H1(value)
  let leaves = canon.map(v => PoseidonHelper.H1(v));

  const depth = opts.fixedDepth ?? Math.ceil(Math.log2(Math.max(1, leaves.length)));
  const padding: PaddingMode = opts.padding ?? "duplicate-last";
  const targetLeaves = 1 << depth;
  const ZERO_LEAF = PoseidonHelper.H1(0n);

  if (leaves.length === 0) leaves = [ZERO_LEAF];
  if (leaves.length > targetLeaves) throw new Error(`Too many leaves for fixedDepth=${depth}`);
  if (leaves.length < targetLeaves) {
    if (padding === "duplicate-last") {
      const last = leaves[leaves.length - 1];
      while (leaves.length < targetLeaves) leaves.push(last);
    } else {
      while (leaves.length < targetLeaves) leaves.push(ZERO_LEAF);
    }
  }

  const layers: bigint[][] = [leaves];
  for (let lv = 0; lv < depth; lv++) {
    const cur = layers[lv];
    const next: bigint[] = [];
    for (let i = 0; i < cur.length; i += 2) {
      next.push(PoseidonHelper.H2(cur[i], cur[i + 1])); // keep L/R
    }
    layers.push(next);
  }

  return { depth, layers, zeroLeaf: ZERO_LEAF, realLeafCount: canon.length };
}

/** Build a Merkle proof (siblings & indices) for a given leaf index in a padded tree */
export function getProofByIndex(tree: Tree, leafIndex: bigint): Proof {
  const { depth, layers } = tree;
  const leaves = layers[0];
  if (leafIndex < 0 || leafIndex >= leaves.length) throw new Error("leafIndex out of range");

  const indices: bigint[] = [];
  const siblings: bigint[] = [];

  let idx = leafIndex;
  for (let lv = 0; lv < depth; lv++) {
    const isRight = (idx & 1n) === 1n;
    // current node position flag for this level: 0=left, 1=right
    indices.push(isRight ? 1n : 0n);

    // sibling index is idx^1 (toggle last bit)
    const sibIdx = isRight ? idx - 1n : idx + 1n;
    siblings.push(layers[lv][Number(sibIdx)]);

    // move to parent index
    idx = idx >> 1n;
  }

  const root = layers[depth][0];
  const leaf = layers[0][Number(leafIndex)];
  return { root, leaf, indices, siblings, index: Number(leafIndex) };
}

export function findLeafIndex(tree: Tree, target: Bigish): number {
  // Leaf = Poseidon(value) with the SAME normalization used in buildAllowTree
  const targetLeaf = PoseidonHelper.H1(PoseidonHelper.toF(toBigInt(target)));
  const leaves = tree.layers[0];

  // Search ONLY within the canonical (pre-padding) region
  const n = tree.realLeafCount ?? leaves.length; // fallback if not set
  for (let i = 0; i < n; i++) {
    // Both sides already in field; direct bigint equality is safest
    if (PoseidonHelper.toF(leaves[i]) === PoseidonHelper.toF(targetLeaf)) return i;
  }
  return -1;
}
