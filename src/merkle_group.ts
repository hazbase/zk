// AllowlistCredential — generateProof (from scratch, strictly matching the circuit)
// Public order in circuit main:
//   [issuerRoot, allowRoot, nullifier, addr, statementHash, leaf]
//
// This module provides:
//   - Field normalization (toF)
//   - Poseidon H1/H2/H3 helpers
//   - Deterministic Merkle tree builder (for testing) with finalize() and getPath()
//   - Strict input types (either paths are provided, or we can build test trees)
//   - Full pre-proof sanity checks (recompute membership for issuer/allow roots)
//   - snarkjs groth16 fullProve wrapper returning (proof, publicSignals) in correct order

import { ethers }   from "ethers";
import { readFile } from "node:fs/promises";
import { groth16, zKey } from "snarkjs";

import path from "node:path";
import { fileURLToPath } from "node:url";
// @ts-ignore
import WitnessCalculatorGroup from "./utils/witness_calculator_group.js";
import { buildAllowTree, findLeafIndex, getProofByIndex, PoseidonHelper } from "./utils/allow_mercle.js";

// ---------------------------
// Field & Poseidon utilities
// ---------------------------

export type FieldLike = string | number | bigint | Uint8Array;

// ---------------------------------
// Deterministic Merkle (for tests)
//   - Leaf   : H1(value)
//   - Zero 0 : H1(0)
//   - Parent : H2(L, R)
//   - indices rule: 0 => (left=cur, right=sib), 1 => (left=sib, right=cur)
// ---------------------------------

class MerkleTree {
  readonly depth: number;
  readonly zeros: bigint[] = [];
  // nodes map: `${lvl}:${idx}` -> node value (bigint)
  private nodes = new Map<string, bigint>();
  root: bigint = 0n;

  /** Build an empty Merkle tree with fixed depth; zero nodes will be derived via Poseidon. */
  constructor(depth: number) {
    this.depth = depth;
  }

  /** Compose a consistent map key for level/index addressing. */
  key(lvl: number, idx: bigint) { return `${lvl}:${idx}`; }

  /** Initialize zero nodes (z0=H1(0), zi=H2(zi-1,zi-1)) and set initial root. */
  async initZeros() {
    await PoseidonHelper.init();
    this.zeros.length = 0;
    this.zeros.push(PoseidonHelper.H1(0n)); // z0 = H1(0)
    for (let i = 1; i <= this.depth; i++) {
      const prev = this.zeros[i-1];
      this.zeros.push(PoseidonHelper.H2(prev, prev)); // zi = H2(zi-1, zi-1)
    }
    this.root = this.zeros[this.depth];
  }

  /** Insert a leaf at an exact (padded) index and bubble up parents deterministically. */
  insertLeafAtIndex(value: FieldLike, index: number) {
    // value is raw attribute for allow-tree; leaf = H1(value)
    const leaf = PoseidonHelper.H1(value);
    let cur = leaf;
    let idx = BigInt(index);

    const checkSibVal = [];
    const checkSibPath = [];

    for (let lvl = 0; lvl < this.depth; lvl++) {
      const isRight = (idx & 1n) === 1n;
      const sibIdx  = isRight ? idx - 1n : idx + 1n;
      const sibVal = PoseidonHelper.toF(this.nodes.get(this.key(lvl, sibIdx)) ?? this.zeros[lvl]);
      checkSibVal.push(sibVal)
      checkSibPath.push(isRight? 1: 0)
      const L = isRight ? sibVal : cur;
      const R = isRight ? cur : sibVal;
      // store children if absent (normalize)
      cur = PoseidonHelper.H2(L, R);

      this.nodes.set(`${lvl}:${idx}`,     (isRight ? R : L) as bigint);
      this.nodes.set(`${lvl}:${sibIdx}`,  sibVal);
      // compute parent
      const parentIdx = idx >> 1n;
      this.nodes.set(`${lvl+1}:${parentIdx}`, cur as bigint);
      idx = parentIdx;
    }

    this.root = this.nodes.get(this.key(this.depth, 0n))!;
  }

  /** Densify level-0 to `width` and recompute all parents bottom-up to stabilize the root. */
  finalize(width: number) {
    // Ensure level-0 is densely set and rebuild upwards
    for (let i = 0; i < width; i++) {
      const k = this.key(0, BigInt(i));
      if (!this.nodes.has(k)) this.nodes.set(k, this.zeros[0]);
      else this.nodes.set(k, this.nodes.get(k)!);
    }
    for (let lvl = 0; lvl < this.depth; lvl++) {
      const parents = 1 << (this.depth - (lvl + 1));
      for (let i = 0; i < parents; i++) {
        const L = this.nodes.get(this.key(lvl, BigInt(2*i)))  ?? this.zeros[lvl];
        const R = this.nodes.get(this.key(lvl, BigInt(2*i+1)))?? this.zeros[lvl];
        const P = PoseidonHelper.H2(L, R);
        this.nodes.set(this.key(lvl+1, BigInt(i)), P);
      }
    }
    this.root = this.nodes.get(this.key(this.depth, 0n))!;
  }

  /** Build a Merkle proof (siblings+indices) from a padded index. */
  getPath(index: number) {
    let idx = BigInt(index);
    const siblings: bigint[] = [];
    const indices: bigint[] = [];
    for (let lvl = 0; lvl < this.depth; lvl++) {
      const isRight = (idx & 1n) === 1n;
      const sibIdx  = isRight ? idx - 1n : idx + 1n;
      const sib = this.nodes.get(this.key(lvl, sibIdx)) ?? this.zeros[lvl];
      siblings.push(PoseidonHelper.toF(sib));
      indices.push(isRight ? 1n : 0n);
      idx >>= 1n;
    }
    return { siblings, indices };
  }
}

// ---------------------------------
// Strict types for the generator
// ---------------------------------

export type AllowPath = { siblings: bigint[]; indices: bigint[]; root: bigint; };
export type IssuerPath = { siblings: bigint[]; indices: bigint[]; root: bigint; };

export interface GenerateArgsStrict {
  list: FieldLike[],          // Input allowlist universe
  // Policy binding
  policyId: FieldLike;        // Identifier of the policy being proven
  policyVersion: number;      // Version to prevent replay across policy updates
  // Address & domain (as field)
  addr: FieldLike;            // Holder address coerced into field (e.g., BigInt(address))
  // Attribute and secrets
  value: FieldLike;           // Attribute value to prove (e.g., 392)
  salt?: FieldLike;           // Optional user salt; generated if absent
  idNull: FieldLike;          // Nullifier secret to prevent cross-context linking
  chainId: number;            // EVM chain id for domain separation
  verifier: string;           // On-chain verifier address (for domain separator)
}

// ---------------------------------
// Helper: recompute membership checks
// ---------------------------------

/** Rebuild issuer root from (value,salt,addr,domain) and a path; used for pre-proof sanity. */
function recomputeIssuerRoot(value: FieldLike, salt: FieldLike, addrFelt: FieldLike, domainFelt: FieldLike, path: IssuerPath): bigint {
  const leaf = PoseidonHelper.H2(value, salt);                // leaf = Poseidon(value, salt)
  let cur = PoseidonHelper.H3(leaf, addrFelt, domainFelt);    // issuerLeaf = Poseidon(leaf, addr, domain)
  for (let i = 0; i < path.siblings.length; i++) {
    const sib = path.siblings[i];
    const idx = path.indices[i];
    cur = idx === 0n ? PoseidonHelper.H2(cur, sib) : PoseidonHelper.H2(sib, cur);
  }
  return PoseidonHelper.toF(cur);
}

/** Resolve package directory in both CJS/ESM environments. */
function pkgDir(): string {
  // @ts-ignore
  return typeof __dirname !== "undefined"
    ? __dirname
    : path.dirname(fileURLToPath(import.meta.url));
}

// ---------------------------------
// Statement / Nullifier
// ---------------------------------

/** Poseidon hash for statement binding: policyId/version + allowRoot + (addr,domain). */
function computeStatementHash(policyId: FieldLike, policyVersion: number, allowRoot: FieldLike, addrFelt: FieldLike, domainFelt: FieldLike): bigint {
  const s1 = PoseidonHelper.H2(policyId, policyVersion);
  const s2 = PoseidonHelper.H2(allowRoot, addrFelt);
  return PoseidonHelper.H3(s1, s2, domainFelt);
}

/** Nullifier binding idNull to (policyId, version) to avoid reuse across policies. */
function computeNullifier(idNull: FieldLike, policyId: FieldLike, policyVersion: number): bigint {
  const n1 = PoseidonHelper.H2(idNull, policyId);
  return PoseidonHelper.H2(n1, policyVersion);
}

// ---------------------------------
// Core generator
// ---------------------------------

/**
 * generateProofAllowlist()
 * Strict end-to-end prover that:
 *  1) Builds allow-tree path for `value` from `list` (deterministic)
 *  2) Builds issuer-tree path for (value,salt,addr,domain)
 *  3) Recomputes and checks both roots locally
 *  4) Constructs inputs in the exact public/private order the circuit expects
 *  5) Produces Groth16 proof and verifies it (defensive check)
 */
export async function generateProofAllowlist(args: GenerateArgsStrict) {
  await PoseidonHelper.init();

  const allow = await buildAllowFromList(args.list, args.value, 16);
  
  let domain = domainSeparator(args.chainId, args.verifier);

  const salt = args.salt? args.salt: PoseidonHelper.genSalt();
  const issuer = await buildIssuerForUser(args.value, salt, args.addr, domain, 0, 20);

  // 0) Field-normalize frequently used values
  const valueF   = PoseidonHelper.toF(args.value);
  const saltF    = PoseidonHelper.toF(salt);
  const addrF    = PoseidonHelper.toF(args.addr);
  const idNullF  = PoseidonHelper.toF(args.idNull);

  // 1) Pre-proof sanity checks: paths must reconstruct the given roots
  const ir = recomputeIssuerRoot(valueF, saltF, addrF, domain, issuer);
  if (ir !== PoseidonHelper.toF(issuer.root)) {
    throw new Error("issuer path/root mismatch");
  }

  // 2) Public signals (order must match the circuit)
  const allowRootF    = PoseidonHelper.F.toObject(allow.root).toString();
  const leafPublic    = PoseidonHelper.H2(valueF, saltF);             // public 'leaf' in circuit
  const statementHash = computeStatementHash(args.policyId, args.policyVersion, allowRootF, args.addr, domain.toString());
  const nullifier     = computeNullifier(idNullF, args.policyId, args.policyVersion);

  const sh = PoseidonHelper.F.toObject(statementHash);
  const nf = PoseidonHelper.F.toObject(nullifier);

  // 3) Build full inputs exactly as the circuit expects
  const inputs = {
    // public
    issuerRoot:      PoseidonHelper.F.toObject(issuer.root).toString(),
    allowRoot:       PoseidonHelper.F.toObject(allow.root).toString(),
    nullifier:       nf.toString(),
    addr:            addrF.toString(),
    statementHash:   sh.toString(),
    leaf:            PoseidonHelper.F.toObject(leafPublic).toString(),

    // private
    policyId:        PoseidonHelper.toF(args.policyId).toString(),
    policyVersion:   args.policyVersion.toString(),
    domain:          domain.toString(),
    value:           valueF.toString(),
    salt:            saltF.toString(),
    idNull:          idNullF.toString(),

    // issuer path
    pathIssuer:      issuer.siblings.map(String),
    posIssuer:       issuer.indices.map(String),   // "0"/"1"

    // allow path
    pathAllow:       allow.siblings.map(x => PoseidonHelper.F.toObject(x).toString()),
    posAllow:        allow.indices.map(String),    // "0"/"1"
  };
  
  const wasmPath = path.join(pkgDir(), "../assets/circuit_group.wasm");
  const zkeyPath = path.join(pkgDir(), "../assets/circuit_group.zkey");
  // 4) Prove
  const wc = await WitnessCalculatorGroup(await readFile(wasmPath));
  const wtns = await wc.calculateWTNSBin(inputs, 0);
  const { proof, publicSignals } = await groth16.prove(zkeyPath, wtns);
  
  const vKey = await zKey.exportVerificationKey(zkeyPath);
  const verified = await groth16.verify(vKey, publicSignals, proof);
  if (!verified) throw new Error("Groth16 verification failed");

  // Normalize proof tuple order for common on-chain verifiers (alt-bn128/Groth16)
  const a: readonly [string, string] = [proof.pi_a[0].toString(), proof.pi_a[1]];
  const b: readonly [[string, string], [string, string]] = [
    [proof.pi_b[0][1], proof.pi_b[0][0]],
    [proof.pi_b[1][1], proof.pi_b[1][0]]
  ];
  const c: readonly [string, string] = [proof.pi_c[0], proof.pi_c[1]];
  const pubsigs: any = publicSignals.map(BigInt);

  return {
    proof: { a, b, c },
    publicSignals: pubsigs
  };
}

// ---------------------------------
// (Optional) Convenience: build allow path from a list (for tests)
// ---------------------------------

/** Recompute a Merkle root from (leaf, indices, siblings) for local verification. */
function recomputeRootFromProof(
  leaf: bigint,
  indices: bigint[],
  siblings: bigint[]
): bigint {
  let cur = leaf;
  for (let i = 0; i < indices.length; i++) {
    const sib = siblings[i];
    const isRight = indices[i] === 1n;   // 1 => current is RIGHT
    
    const left  = isRight ? sib : cur;  // when current is right, sibling is left
    const right = isRight ? cur : sib;

    cur = PoseidonHelper.H2(left, right);
  }
  return cur;
}

/**
 * Build an allowlist proof for `target` from `values` with fixed depth (default 16).
 * Deterministically canonicalizes, builds the tree, selects the target index, and verifies locally.
 */
export async function buildAllowFromList(values: FieldLike[], target: FieldLike, depth = 16): Promise<AllowPath> {
  await PoseidonHelper.init();

  const tree = await buildAllowTree(values as any, { fixedDepth: depth, padding: "duplicate-last" });
  const allowRoot = tree.layers[tree.depth][0];

  const idx = findLeafIndex(tree, target as any);
  if (idx < 0) throw new Error("target not in allowlist");

  const proof = getProofByIndex(tree, BigInt(idx));

  // Recompute locally (strict)
  const leaf = PoseidonHelper.H1(target);
  const calcRoot = recomputeRootFromProof(leaf, proof.indices, proof.siblings);
  
  if (PoseidonHelper.toF(calcRoot) !== PoseidonHelper.toF(allowRoot)) {
    throw new Error("local recompute mismatch");
  }

  return {
    siblings: proof.siblings,
    indices: proof.indices,
    root: calcRoot,
  };
}

// ---------------------------------
// (Optional) Convenience: build issuer path (for tests)
// ---------------------------------

/** EIP-712-like domain separator in field: keccak256(abi.encode(chainId, verifier)) % Fr. */
const domainSeparator = (chainId: number, verifier: string) => {
  // keccak256(abi.encode(chainid, address(this))) % field
  const k = ethers.keccak256(
    ethers.AbiCoder.defaultAbiCoder().encode(["uint256","address"], [chainId, verifier])
  );
  return PoseidonHelper.toF(k);
};

/**
 * Build a single-entry issuer path for (value,salt,addr,domain) at an index (default 0).
 * Produces siblings/indices suitable for the circuit's issuer tree constraints.
 */
export async function buildIssuerForUser(value: FieldLike, salt: FieldLike, addrFelt: FieldLike, domainFelt: FieldLike, index = 0, depth = 20): Promise<IssuerPath> {
  await PoseidonHelper.init();
  
  const tree = new MerkleTree(depth);
  await tree.initZeros();

  const leaf = PoseidonHelper.H2(value, salt);
  const issuerLeaf = PoseidonHelper.H3(leaf, PoseidonHelper.toF(addrFelt), domainFelt);
  // For tests we insert only one entry at a fixed index
  
  let cur = issuerLeaf;
  let idx = BigInt(index);
  for (let lvl = 0; lvl < depth; lvl++) {
    const isRight = (idx & 1n) === 1n;
    const sibIdx  = isRight ? idx - 1n : idx + 1n;
    const sibVal  = PoseidonHelper.toF((tree as any).nodes.get(`${lvl}:${sibIdx}`) ?? (tree as any).zeros[lvl]);
    
    const L = isRight ? sibVal : cur;
    const R = isRight ? cur    : sibVal;

    cur = PoseidonHelper.H2(L, R);

    (tree as any).nodes.set(`${lvl}:${idx}`,     (isRight ? R : L) as bigint);
    (tree as any).nodes.set(`${lvl}:${sibIdx}`,  sibVal);

    const parentIdx = idx >> 1n;
    (tree as any).nodes.set(`${lvl+1}:${parentIdx}`, cur as bigint);
    idx = parentIdx;
  }
  (tree as any).nodes.set(`${depth}:0`, cur as bigint);
  tree.root = cur;
  
  const { siblings, indices } = tree.getPath(index);
  return { siblings, indices, root: tree.root };
}
