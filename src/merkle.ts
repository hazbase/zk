import { readFile } from "node:fs/promises";
import { ethers, ZeroAddress }   from "ethers";
import { buildPoseidon } from "circomlibjs";
import { groth16, zKey } from "snarkjs";
// @ts-ignore
import WitnessCalculator from "./utils/witness_calculator.js";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { randomBytes } from "node:crypto";

const DOMAIN_MSG = "Hazbase KYC — Generate idNull v1";

export interface NaturalKYC {
  govId:       string;
  name:        string;
  dobYMD:      number;
  country:     number;
  salt?:       bigint;
}

export interface CorporateKYC {
  corpId:      string;
  name:        string;
  incDateYMD:  number;
  country:     number;
  role?:       string;
  salt?:       bigint;
}

export type KYCInput = NaturalKYC | CorporateKYC;

export interface ProofBundle {
  proof: { a: readonly [string, string], b: readonly [[string, string], [string, string]], c: readonly [string, string] };
  publicSignals: readonly [bigint, bigint, bigint, bigint, bigint, bigint];  // [mode, root, nullifier, addr, threshold, leaf]
  input: Record<string, string | string[]>;
  /** The idNull used to create the nullifier */
  idNull: bigint;
}

/* ──────────────────────────────────────────────────────────── */
/*                      Poseidon helper                        */
/* ──────────────────────────────────────────────────────────── */

class PoseidonHelper {
  /**
   * ⚠️  This static field is now public so other helpers can read the initialised
   *     Poseidon instance (e.g. for `F.p` checks) without fighting TS privacy.
   */
  static FIELD_PRIME = 21888242871839275222246405745257275088548364400416034343698204186575808495617n;
  static _poseidon: any;
  static async init() {
    if (!this._poseidon) this._poseidon = await buildPoseidon();
  }
  static get F() {
    if (!this._poseidon) throw new Error("Poseidon not initialised");
    return this._poseidon.F;
  }
  static toF(x: string | bigint | number | Uint8Array): bigint {
    if (!this._poseidon) throw new Error("Poseidon not initialised");
    const p = this._poseidon.F.p;

    if (typeof x === "bigint") return x % p;
    if (typeof x === "number") return BigInt(x) % p;
    if (typeof x === "string") {
      const hexLike = x.startsWith("0x") ? x : ethers.keccak256(ethers.toUtf8Bytes(x));
      return BigInt(hexLike) % p;
    }
    // Uint8Array
    const hex = Buffer.from(x).toString("hex");
    return BigInt("0x" + hex) % p;
  }
  static H2(a: bigint, b: bigint) {
    if (!this._poseidon) throw new Error("Poseidon not initialised");
    return this._poseidon([a, b]) as bigint;
  }
  static genSalt(): bigint {
    if (!this._poseidon) throw new Error("Poseidon not initialised");
    const p = this._poseidon.F.p;

    const raw = randomBytes(32);
    const hex = "0x" + raw.toString("hex");
    return BigInt(hex) % p || 1n;
  }
}

/* ──────────────────────────────────────────────────────────── */
/*                     Incremental Merkle                      */
/* ──────────────────────────────────────────────────────────── */

const DEPTH = 20;        // ≒ 1 M leaves
const ZERO  = 0n;

class IncrementalTree {
  private zeros: bigint[] = [ZERO];
  private nodes: Map<string,bigint> = new Map();

  constructor(private root = ZERO) {}

  async initZeros() {
    await PoseidonHelper.init();
    for (let i = 1; i < DEPTH; i++) {
      this.zeros.push(PoseidonHelper.H2(this.zeros[i-1], this.zeros[i-1]));
    }
  }

  /**
   * Insert leaf at given index (no re‑balancing). Returns new root & proof path.
   */
  insert(leaf: bigint, index: number) {
    let cur = leaf;
    let idx = BigInt(index);
    const siblings: bigint[] = [];
    const pathPos : bigint[] = [];

    for (let lvl = 0; lvl < DEPTH; lvl++) {
      const isRight = (idx & 1n) === 1n;
      const sibIdx  = isRight ? idx - 1n : idx + 1n;
      const sibVal  = PoseidonHelper.toF(this.nodes.get(`${lvl}:${sibIdx}`) ?? this.zeros[lvl]);
      siblings.push(sibVal);
      pathPos .push(isRight ? 1n : 0n);

      const L = isRight ? sibVal : cur;
      const R = isRight ? cur    : sibVal;
      cur = PoseidonHelper.H2(L, R);

      this.nodes.set(`${lvl}:${idx}`,     isRight ? R : L);
      this.nodes.set(`${lvl}:${sibIdx}`,  sibVal);
      idx >>= 1n;
    }
    this.nodes.set(`${DEPTH}:0`, cur);
    this.root = cur;
    return { root: cur, siblings, pathPos } as const;
  }
}

/* ──────────────────────────────────────────────────────────── */
/*                   High‑level proof generator                 */
/* ──────────────────────────────────────────────────────────── */
type ProofMode = "NONE" | "GT" | "LT" | "NEQ" | "EQ" | "GTE" | "LTE" | number;

export interface GenerateProofOpts {
  mode?: ProofMode;        // ★ default "KYC"
  threshold?: bigint;      // ★ SCORE
  score?: bigint;          // ★ SCORE
  wasmPath? : string;      // compiled circuit.wasm
  zkeyPath? : string;      // final proving key
  currentRoot?: bigint;    // root recorded on chain (0 = empty tree)
  nextIndex?: number;      // leaf index to insert (default 0)
  idNull?: bigint;
  chainId?: number;
  verifierAddress?: string;
}

function pkgDir(): string {
  // @ts-ignore
  return typeof __dirname !== "undefined"
    ? __dirname
    : path.dirname(fileURLToPath(import.meta.url));
}

export async function deriveIdNull(signer: ethers.Signer, opts?: any): Promise<bigint> {
  // 1. Obtain personal-sign signature (EIP-191, \x19Ethereum Signed Message)
  const message = DOMAIN_MSG + (opts?.message? opts?.message : "");
  const signature = await signer.signMessage(message);

  // 2. Hash the signature → 256-bit digest
  const digest = ethers.keccak256(signature as ethers.BytesLike);

  // 3. Convert to BigInt and reduce into the Poseidon field
  const idNull =
    (BigInt(digest) % PoseidonHelper.FIELD_PRIME) as bigint; // < 254 bits

  return idNull;
}

export async function genValues(n: bigint, opts?: GenerateProofOpts): Promise<any>{
  await PoseidonHelper.init();
  const rand      = opts?.idNull ?? PoseidonHelper.genSalt();

  const commitRaw = PoseidonHelper.H2(n, rand);
  const commitVal = PoseidonHelper.F.toObject(commitRaw).toString();
  return {
    value: Number(BigInt.asUintN(32, commitVal)),
    leafFull: commitVal
  }
}

const domainSeparator = (chainId: number, verifier: string) => {
  // keccak256(abi.encode(chainid, address(this))) % field
  const k = ethers.keccak256(
    ethers.AbiCoder.defaultAbiCoder().encode(["uint256","address"], [chainId, verifier])
  );
  return PoseidonHelper.toF(k);
};

export async function generateProof(
  kyc: KYCInput,
  walletAddress: string,
  opts?: GenerateProofOpts
): Promise<ProofBundle> {
  await PoseidonHelper.init();

  const mode = opts?.mode === "NONE"? 0
            : opts?.mode  === "GT"  ? 1
            : opts?.mode  === "LT"  ? 2
            : opts?.mode  === "NEQ" ? 3
            : opts?.mode  === "EQ"  ? 4
            : opts?.mode  === "GTE" ? 5
            : opts?.mode  === "LTE" ? 6
            : typeof opts?.mode === 'number'? opts?.mode : 0;

  const threshold = mode > 0 ? (opts?.threshold ?? 0n) : 0n;
  const score     = mode > 0 ? (opts?.score     ?? 0n) : 0n;

  /* ------------------------------------------------------------------ */
  /* 1. Build KYC leaf (basicLeaf)                                      */
  /* ------------------------------------------------------------------ */
  
  const salt = opts?.idNull ?? PoseidonHelper.genSalt();
  const basicLeaf: bigint =
    "govId" in kyc
      ? PoseidonHelper._poseidon([
          PoseidonHelper.H2(
            PoseidonHelper.toF(
              ethers.keccak256(ethers.toUtf8Bytes(kyc.govId))
            ),
            PoseidonHelper.toF(
              ethers.keccak256(ethers.toUtf8Bytes(kyc.name))
            )
          ),
          BigInt(kyc.dobYMD),
          BigInt(kyc.country),
          salt
        ])
      : PoseidonHelper._poseidon([
          PoseidonHelper.toF(
            ethers.keccak256(ethers.toUtf8Bytes(kyc.corpId))
          ),
          PoseidonHelper.toF(
            ethers.keccak256(ethers.toUtf8Bytes(kyc.name))
          ),
          BigInt(kyc.incDateYMD),
          BigInt(kyc.country),
          PoseidonHelper.toF(kyc.role ?? ""),
          salt
        ]);

  let chainId = !!opts?.chainId ? opts?.chainId: 1
  let verifierAddress = !!opts?.verifierAddress ? opts.verifierAddress: ZeroAddress;

  const domain = domainSeparator(chainId, verifierAddress);
  const commitLeaf = mode <= 0 ? basicLeaf : PoseidonHelper.H2(score, salt);
  /* ------------------------------------------------------------------ */
  /* 2. Compose Merkle leaf = Poseidon(commitLeaf, walletAddress)        */
  /* ------------------------------------------------------------------ */
  const treeLeaf = PoseidonHelper._poseidon([ 
    commitLeaf, 
    PoseidonHelper.toF(walletAddress), 
    domain 
  ]) as bigint;

  /* ------------------------------------------------------------------ */
  /* 3. Insert the leaf into an off-chain Merkle tree                   */
  /* ------------------------------------------------------------------ */
  const tree = new IncrementalTree(opts?.currentRoot ?? ZERO);
  await tree.initZeros();
  const { root, siblings, pathPos } = tree.insert(
    treeLeaf,
    opts?.nextIndex ?? 0
  );

  /* ------------------------------------------------------------------ */
  /* 4. Generate nullifier = Poseidon(idNull, root)                     */
  /* ------------------------------------------------------------------ */
  //const idNull = opts?.idNull ?? PoseidonHelper.genSalt();
  //console.log('idNull', idNull)
  const nullifier = PoseidonHelper.H2(salt, root);

  const rootBig = PoseidonHelper.F.toObject(root);
  const nf = PoseidonHelper.F.toObject(nullifier);

  /* ------------------------------------------------------------------ */
  /* 5. Prepare the witness input                                       */
  /* ------------------------------------------------------------------ */
  const input = {
    // public signals (order matches circuit main)
    mode      : mode.toString(),
    root      : rootBig.toString(),
    nullifier : nf.toString(),
    addr      : PoseidonHelper.toF(walletAddress).toString(),
    threshold : threshold.toString(),
    leaf      : PoseidonHelper.F.toObject(commitLeaf).toString(),
    
    // private signals
    idNull    : salt.toString(),
    path      : siblings.map(String),
    pathPos   : pathPos.map(String),
    score     : score.toString(),
    rand      : salt.toString(),
    domain    : domain.toString(),
  } as Record<string,string|string[]>;

  /* ------------------------------------------------------------------ */
  /* 6. Generate witness and proof                                      */
  /* ------------------------------------------------------------------ */
  const wasmPath = path.join(pkgDir(), "../assets/circuit.wasm");
  const zkeyPath = path.join(pkgDir(), "../assets/circuit.zkey");

  const wc = await WitnessCalculator(await readFile(wasmPath));
  const wtns = await wc.calculateWTNSBin(input, 0);
  const { proof, publicSignals } = await groth16.prove(zkeyPath, wtns);

  /* ------------------------------------------------------------------ */
  /* 7. Local safety verification                                       */
  /* ------------------------------------------------------------------ */
  const vKey = await zKey.exportVerificationKey(zkeyPath);
  const verified = await groth16.verify(vKey, publicSignals, proof);
  if (!verified) throw new Error("Groth16 verification failed");

  /* ------------------------------------------------------------------ */
  /* 8. Re-format proof for Solidity verifier                           */
  /* ------------------------------------------------------------------ */
  const a: readonly [string, string] = [proof.pi_a[0].toString(), proof.pi_a[1]];
  const b: readonly [[string, string], [string, string]] = [
    [proof.pi_b[0][1], proof.pi_b[0][0]],
    [proof.pi_b[1][1], proof.pi_b[1][0]]
  ];
  const c: readonly [string, string] = [proof.pi_c[0], proof.pi_c[1]];
  const pubsigs: any = publicSignals.map(BigInt);
  return {
    proof: { a, b, c },
    publicSignals: pubsigs,
    input,
    idNull: salt
  };
}

/* ──────────────────────────────────────────────────────────── */
/*                    Convenience exports                      */
/* ──────────────────────────────────────────────────────────── */
export const FpPrime = async () => { await PoseidonHelper.init(); return PoseidonHelper.F.p; };
export { PoseidonHelper };
