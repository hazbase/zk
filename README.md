# @hazbase/zk
[![npm version](https://badge.fury.io/js/@hazbase%2Fzk.svg)](https://badge.fury.io/js/@hazbase%2Fzk)
[![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)

## Overview
`@hazbase/zk` is an utility toolkit for **Poseidon hashing**, **Merkle trees**, and **Groth16 proofs**.  
It is designed to be used **together with MultiTrustCredential (MTC) and Whitelist** and provides low-level APIs to verify **commitment-based metrics** (e.g., score ≥ threshold, membership, allowlists) with **minimal disclosure**.

Core capabilities:
- Poseidon helpers (`init`, `toF`, `H1/H2/H3`, `genSalt`)
- Repeatable, **deterministic** Merkle construction (normalize → deduplicate → sort ascending → pad)
- Root recomputation, path generation, and verification (`buildAllowTree`, `getProofByIndex`, `findLeafIndex`, etc.)
- **Groth16** proof generation (`generateProofAllowlist`) with pre-proof sanity checks
- First-class integration with **MTC (@hazbase/kit)** for on-chain proof flows

---

## Requirements
- **Node.js**: 18+ (ESM recommended)
- **Deps**: `snarkjs`, `circomlibjs`, `ethers`
- **MTC**: use with `@hazbase/kit` `MultiTrustCredentialHelper` `WhitelistHelper`

---

## Installation
```bash
npm i @hazbase/zk
```

---

## Configuration
This package does **not** read environment variables directly. Provide **paths to circuit assets** and **network/domain info** explicitly from your application.

---

## Quick start (MTC + ZK)
End-to-end example proving that a holder satisfies a **policy** (e.g., allowlist membership or score ≥ threshold) **without revealing raw values**, then verifying on-chain via `proveMetric`.

### Proof of Group Membership

```ts
import { ethers } from "ethers";
import { PoseidonHelper, buildAllowFromList, generateProofAllowlist } from "@hazbase/zk";
import { MultiTrustCredentialHelper } from "@hazbase/kit";

async function run() {
  // 1) Prepare MTC deployment/attachment
  const provider = new ethers.JsonRpcProvider(process.env.RPC_URL!);
  const admin = new ethers.Wallet(process.env.ADMIN_KEY!, provider);
  const issuer = new ethers.Wallet(process.env.ISSUER_KEY!, provider);
  const alice  = new ethers.Wallet(process.env.ALICE_KEY!, provider);

  const { address } = await MultiTrustCredentialHelper.deploy({ admin: admin.address }, admin);
  const mtc = MultiTrustCredentialHelper.attach(address, admin);

  // 2) Register a commitment metric (e.g., "intlExamScore") and authorize issuer
  const MetricId = ethers.id('country-code');
  const ROLE = ethers.id("COUNTRY_CODE_ROLE");
  await mtc.registerMetric(MetricId, "CountryCode", ROLE, true, MultiTrustCredentialHelper.CompareMask.IN);
  await mtc.contract.grantRole(ROLE, issuer.address);

  // 3) Mint commitment NFT to Alice (store only the leaf commitment on-chain)
  
  const idNull = PoseidonHelper.genSalt(); // Example;
  // const idNull = await deriveIdNull(examinator, {message: ':' + alice.address + ':' + MetricId}) if you want to use fixed value for user.
  
  const values = await genValues(392n, {idNull}); // Country code of Japan
  await mtc.connect(issuer).mint(alice.address, { metricId: MetricId, value: 0, leafFull: values.leafFull, uri: "" });

  // 4) Build allow/issuer paths and generate Groth16 proof off-chain
  const allowValues = [392n, 840n, 124n]; // Example: ISO country list

  await mtc.updateGroupVerifier(); // Enable Group Verifier

  const proofBundle = await generateProofAllowlist({
    list: allowValues,
    policyId: MetricId,
    policyVersion: 1,
    addr: alice.address,     // coerced into field internally
    value: 392n,             // attribute value to prove (e.g., country=392)
    salt: idNull,            // Salt
    idNull,                  // user-bound nullifier
    chainId: 11155111,       // Sepolia
    verifier: await mtc.gVerifier(), // On-chain verifier address
  });

  // 5) Prove on-chain that Alice satisfies the metric policy
  const tokenId = MultiTrustCredentialHelper.tokenIdFor(alice.address);
  const { a, b, c } = proofBundle.proof;
  await mtc.connect(alice).proveGroupMetric(tokenId, MetricId, a, b, c, proofBundle.publicSignals);
}
```

### Proof of Threshold
```ts
import { ethers } from "ethers";
import { PoseidonHelper, buildAllowFromList, generateProof } from "@hazbase/zk";
import { MultiTrustCredentialHelper } from "@hazbase/kit";

async function run() {
  // 1) Prepare MTC deployment/attachment
  const provider = new ethers.JsonRpcProvider(process.env.RPC_URL!);
  const admin = new ethers.Wallet(process.env.ADMIN_KEY!, provider);
  const examinator = new ethers.Wallet(process.env.EXAMINATOR_KEY!, provider);
  const student  = new ethers.Wallet(process.env.STUDENT_KEY!, provider);

  const { address } = await MultiTrustCredentialHelper.deploy({ admin: admin.address }, admin);
  const mtc = MultiTrustCredentialHelper.attach(address, admin);

  // 2) Register a commitment metric (e.g., "ExamScore") and authorize issuer
  const MetricId = ethers.id('exam-score');
  const ROLE = ethers.id("EXAM_SCORE_ROLE");
  await mtc.registerMetric(MetricId, "ExamScore", ROLE, true, MultiTrustCredentialHelper.CompareMask.GTE);
  await mtc.contract.grantRole(ROLE, examinator.address);

  // 3) Mint commitment NFT to Alice (store only the leaf commitment on-chain)
  
  const idNull = PoseidonHelper.genSalt(); // Example;
  // const idNull = await deriveIdNull(examinator, {message: ':' + student.address + ':' + MetricId}) if you want to use fixed value for user.
  
  const realScore = 80n;
  const values = await genValues(realScore, {idNull}); // Country code of Japan
  await mtc.connect(examinator).mint(student.address, { metricId: MetricId, value: 0, leafFull: values.leafFull, uri: "" });

  await mtc.updateVerifier(); // Enable Default Verifier

  const { proof, publicSignals } = await generateProof(
    {
      govId : "X987654",       // Example subject attribute
      name  : "Alice Chember", // Example subject attribute
      dobYMD: 12345678,        // Example subject attribute
      country: 392             // Example subject attribute
    },
    student.address,           // Holder address bound into the proof
    {
      mode      : CompareMask.GTE,   // Policy: prove score >= threshold
      threshold : 60,                // The threshold to be satisfied
      score     : realScore,         // The actual (private) score used inside the proof
      idNull,                        // Same nullifier binding used at mint-time
      chainId: 11155111,             // Sepolia
      verifier: await mtc.gVerifier(), // On-chain verifier address
    }
  );

  // 5) Prove on-chain that Student satisfies the metric policy
  const tokenId = MultiTrustCredentialHelper.tokenIdFor(student.address);
  const { a, b, c } = proofBundle.proof;
  await mtc.connect(student).proveMetric(tokenId, MetricId, a, b, c, proofBundle.publicSignals);
}
```

---

## Function reference (Core API)

### Poseidon / Field
- **`PoseidonHelper.init(): Promise<void>`**  
  Lazily initialize Poseidon. Call once before hashing/field operations.

- **`PoseidonHelper.toF(x): bigint`**  
  Normalize string/number/Uint8Array into **BN254 Field (Fr)**.

- **`PoseidonHelper.H1(x) / H2(a,b) / H3(a,b,c): bigint`**  
  Fixed-arity Poseidon hashes; **order is preserved**.

- **`PoseidonHelper.genSalt(): bigint`**  
  Generate a non-zero random field element (useful for salts/nonces).

### Proof generator

- **`generateProof(subject, holderAddr, opts)` → `Promise<{ proof, publicSignals }>`**
  General-purpose Groth16 proof creator (used with the “group” circuit) that orders public signals exactly as required for on-chain verification.

**Params**
- `subject`: object of private attributes used by the circuit (e.g., `{ govId, name, dobYMD, country }`).
- `holderAddr`: EVM address to bind the proof to (string).
- `opts`: `{ mode, threshold, score, idNull, chainId, verifierAddress }`
  - `mode`: comparison policy (e.g., `CompareMask.GTE`).
  - `threshold`: policy threshold (bigint).
  - `score`: private score used inside the proof (bigint).
  - `idNull`: per-policy nullifier (bigint/string).
  - `chainId`: EVM chain id (number).
  - `verifierAddress`: on-chain verifier contract (string).

**Returns** a `{ proof: { a, b, c }, publicSignals }` tuple aligned to `[issuerRoot, allowRoot, nullifier, addr, statementHash, leaf]`.

---

- **`generateProofAllowlist(args: GenerateArgsStrict)` → `Promise<{ proof, publicSignals }>`**

  Strict end-to-end Groth16 prover for **allowlist/membership** style policies. It deterministically builds the allow path for `args.value` from `args.list`, constructs the issuer path for `(value,salt,addr,domain)`, performs **local root recomputation checks**, assembles inputs in the circuit’s exact order, and returns an on-chain-ready proof tuple.

**Params**
- `args.list`: `FieldLike[]` — universe of allowed values (e.g., ISO countries).
- `args.policyId`: `FieldLike` — policy identifier bound into the statement hash.
- `args.policyVersion`: `number` — versioning to prevent cross-policy replay.
- `args.addr`: `FieldLike` — holder address (coerced to field internally).
- `args.value`: `FieldLike` — the target value to prove is in the allowlist.
- `args.idNull`: `FieldLike` — per-policy nullifier (unlinkability across policies).
- `args.chainId`: `number` — EVM chain id for domain separation.
- `args.verifier`: `string` — on-chain verifier contract address (used in domain separator).

**Behavior**
1) Builds deterministic allow path and single-entry issuer path.  
2) Recomputes both roots locally; throws on mismatch.  
3) Produces inputs in the circuit’s public order: `[issuerRoot, allowRoot, nullifier, addr, statementHash, leaf]`.  
4) Generates Groth16 proof and self-verifies with the verification key.

**Returns**
- `proof`: `{ a, b, c }` — tuple shaped for common alt-bn128 on-chain verifiers.
- `publicSignals`: `bigint[]` — aligned to the circuit’s expected ordering.

---

- **`deriveIdNull(signer, { message })` → `Promise<bigint | string>`**
  Derives a holder-/issuer-/metric-scoped nullifier from a signed message, enabling unlinkable proofs across policies while preserving per-policy uniqueness.

**Params**
- `signer`: an `ethers.Signer` (e.g., issuer/examiner wallet).
- `message`: domain string you define (e.g., `":" + holder + ":" + metricId`).

**Usage**
```ts
const idNull = await deriveIdNull(examiner, { message: `:${holder}:${metricId}` });
```

---

- **`genValues(score, { idNull })` → `Promise<{ leafFull: bigint, value?: bigint }>`**
  Prepares commitment materials for minting a commitment-based MTC metric without revealing the raw score.

**Params**
- `score`: private numeric value (bigint).
- `idNull`: the same nullifier used later in `generateProof`.

**Returns**
- `leafFull`: full commitment to store on-chain at mint time.
- `value` (optional): a hashed/encoded public hint (commonly omitted / set to `0` for maximum privacy).

**Usage**
```ts
const { leafFull } = await genValues(650n, { idNull });
await mtc.mint(holder, { metricId, value: 0, leafFull, uri: "" });
```

---

## Troubleshooting
- **"root mismatch / local recompute mismatch"**  
  Verify normalization parity (toF/sort/dedupe) and circuit consistency.  
- **MTC verification failure**  
  Validate `publicSignals` ordering, `CompareMask`, and network/verifier address alignment.

---

## Tip: common imports
```ts
import {
  generateProof, generateProofAllowlist,
  deriveIdNull, genValues,
  PoseidonHelper, // Optional
} from "@hazbase/zk";
```

---

## License
Apache-2.0
