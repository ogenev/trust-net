# TrustNet

> **Verifiable, explainable reputation for AI agents (ERC‑8004‑native).**  
> Admit or deny agent actions using a tiny **2‑hop proof** and a deterministic, **observer‑relative** score.

## ✨ What is TrustNet?

TrustNet is a reputation layer that turns **ERC‑8004** agent feedback + curator ratings into a **single Merkle root** and
**portable proofs**. Gateways and contracts use these proofs to **allow/deny** agent actions (payments, code‑exec, writes, DeFi)
and always show a short **“Why?”** (two edges + direct override).

- 🔗 **ERC‑8004‑native** (Identity + Reputation ingestion)  
- 🔐 **Explainable** (observer‑relative, context‑scoped, direct veto respected)  
- 🌱 **MVP‑small** (events‑only contracts, one root, tiny proofs)  
- 🧪 **Open** (MIT/Apache‑2.0, reproducible builds)

## 🧩 API (MVP)
 - GET /v1/root → { epoch, graphRoot, manifest }
-	GET /v1/context → [{ name, idHex }]
-	GET /v1/score/:observer/:target?contextId=<hex>
-	Returns { score, epoch, path:{hinge,lOY,lYT,lOT}, proof:{graphRoot, merkleOY[], merkleYT[], merkleOT[], otIsAbsent} }
-	If hinge omitted, server selects best hinge deterministically.

## 🔐 Contracts (MVP)
-	**TrustGraph** — emit EdgeRated(rater, target, level, contextId); no storage.
-	**RootRegistry** — setGraphRoot(bytes32 root, uint64 epoch) (owner‑only; strictly increasing).
-	**TrustPathVerifier** — verifies three SMM paths against graphRoot, computes score, requireAtLeast(threshold).

We ship Foundry tests + vectors to ensure Solidity and Rust verifiers produce identical results.

## 🧠 How the Indexer Works
1.	**Ingest**
- ERC‑8004 Reputation NewFeedback → (client → agentWallet) edge with contextId=tag1, level=quantize(score), only if tag2=keccak256("trustnet:v1").
- TrustGraph EdgeRated → (rater → target) edge with explicit level.
2.	**Latest‑wins**
- Per (rater, target, context), keep the latest event by (block, txIndex, logIndex).
3.	**Build SMM**
- Map (rater, target, context) → K, store V=uint8(level+2), create graphRoot, bump epoch, publish to RootRegistry.
4.	**Proofs**
- For (O,T,ctx), pick best hinge Y, assemble proofs for O→Y, Y→T, and O→T (membership or non‑membership).

**Trust model (MVP)**: trust‑minimized, reproducible. We publish a Root Manifest (block window, contracts, quantizer), so anyone can recompute the root over public logs.

## 🔒 Security & Integrity
- **Anchored observers** — gates use allow‑listed observers or councils (k‑of‑n).
- **Direct veto** — an O→T = −2 cancels positive paths.
- **Context binding** — all proofs must share the same contextId.
- **Reorgs** — indexer waits N confirmations; epochs strictly increase.

## 🙏 Acknowledgements

**Thanks to the ERC‑8004 community and early test users who helped shape TrustNet’s MVP.**
