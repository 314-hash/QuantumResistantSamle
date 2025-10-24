 # 🧠 Quantum-Resistant Solidity Contracts Suite

This repository provides **five example Solidity contracts** designed to demonstrate *post-quantum–resistant* design patterns for Ethereum-like (EVM) blockchains.  
Each contract illustrates a distinct approach — from pure hash-based Lamport signatures to hybrid architectures and off-chain attestation bridges — all intended to mitigate risks posed by future quantum adversaries.

> ⚠️ **Disclaimer:**  
> These contracts are **educational prototypes**, not audited production code.  
> True post-quantum cryptography (PQC) on-chain is computationally expensive.  
> Always seek formal audit and optimization before any mainnet use.

---

## 🧩 Overview

| Contract | Description | PQ Resistance Mechanism |
|-----------|--------------|--------------------------|
| `LamportOneTimeWallet.sol` | Minimal Lamport one-time signature wallet. | Pure hash-based Lamport signatures. |
| `MerkleLamportWallet.sol` | Many Lamport keys aggregated under a Merkle root. | Hash-based, Merkle-authenticated key tree. |
| `HybridMultiSig.sol` | Requires both ECDSA and post-quantum commitment proofs. | Hybrid ECDSA + PQ preimage reveal. |
| `KeyRotationPolicy.sol` | Time-delayed key rotation with guardians and freeze. | Short key lifespan reduces exposure. |
| `OffChainAttestationBridge.sol` | Off-chain PQ verification with on-chain attestation. | Post-quantum verification performed off-chain. |

---

 
