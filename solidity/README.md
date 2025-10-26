# TrustNet Smart Contracts

Smart contracts for the TrustNet reputation layer on ERC-8004.

## Overview

TrustNet provides verifiable, explainable trust-to-act decisions for AI agents using:
- **Observer-relative** trust scoring (no global reputation)
- **Context-isolated** ratings (payments, code-exec, writes, defi-exec)
- **2-hop proofs** with Sparse Merkle Maps
- **Explainable** decisions showing which edges contributed

See [WHITEPAPER.md](../WHITEPAPER.md) for full specification.

---

## Contracts

### TrustGraph.sol

**Events-only contract** for recording trust edges.

```solidity
// Rate an agent or curator
trustGraph.rateEdge(
    targetAddress,
    +2,  // level: -2 (distrust) to +2 (trust)
    TrustNetContexts.PAYMENTS
);

// Batch rating
trustGraph.rateEdgeBatch(
    [agent1, agent2, agent3],
    [+2, +1, -1],
    [PAYMENTS_CTX, PAYMENTS_CTX, CODE_EXEC_CTX]
);
```

**Key Features:**
- No storage, only events (minimal gas ~21k)
- Latest-wins semantics (enforced by indexer)
- Input validation (level ∈ [-2, +2])
- Batch operations for gas efficiency

**Events:**
```solidity
event EdgeRated(
    address indexed rater,
    address indexed target,
    int8 level,
    bytes32 indexed contextId
);
```

---

### TrustNetContexts.sol

**Library of canonical context identifiers** for capability namespaces.

```solidity
// Standard contexts
TrustNetContexts.GLOBAL       // General trust
TrustNetContexts.PAYMENTS     // Payment capabilities
TrustNetContexts.CODE_EXEC    // Code execution
TrustNetContexts.WRITES       // Data write access
TrustNetContexts.DEFI_EXEC    // DeFi operations

// Custom contexts
bytes32 customCtx = TrustNetContexts.computeContextId("api-access", "v1");

// Utility functions
bool canonical = TrustNetContexts.isCanonical(contextId);
string memory name = TrustNetContexts.getContextName(contextId);
```

**Why contexts?** Prevents privilege escalation - an agent trusted for payments shouldn't automatically be trusted for code execution.

---

## Trust Levels

| Level | Meaning | Use Case |
|:-----:|---------|----------|
| **+2** | Strong trust | Highly vetted agents, core team members |
| **+1** | Mild trust | Approved agents, known curators |
| **0** | Neutral | Default, unknown agents |
| **-1** | Mild distrust | Flagged for review, suspicious behavior |
| **-2** | Strong distrust | Banned, compromised, veto override |

---

## Usage Examples

### 1. Observer Rates a Curator

```solidity
// FinOps trusts CFO highly for payment decisions
trustGraph.rateEdge(
    cfoAddress,
    +2,  // strong trust
    TrustNetContexts.PAYMENTS
);
```

### 2. Curator Rates an Agent

```solidity
// CFO trusts PayBot moderately for payments
trustGraph.rateEdge(
    payBotAddress,
    +1,  // mild trust
    TrustNetContexts.PAYMENTS
);
```

### 3. Observer Overrides (Direct Veto)

```solidity
// SecOps distrusts a compromised agent
trustGraph.rateEdge(
    suspiciousAgentAddress,
    -2,  // strong distrust (veto)
    TrustNetContexts.CODE_EXEC
);
```

### 4. Context Isolation

```solidity
// Agent trusted for payments
trustGraph.rateEdge(agent, +2, TrustNetContexts.PAYMENTS);

// Same agent NOT trusted for code execution
// (different context = independent rating)
trustGraph.rateEdge(agent, -1, TrustNetContexts.CODE_EXEC);
```

### 5. Batch Rating by Curator

```solidity
address[] memory agents = new address[](3);
agents[0] = agent1;
agents[1] = agent2;
agents[2] = agent3;

int8[] memory levels = new int8[](3);
levels[0] = +2;
levels[1] = +1;
levels[2] = -1;

bytes32[] memory contexts = new bytes32[](3);
contexts[0] = TrustNetContexts.PAYMENTS;
contexts[1] = TrustNetContexts.PAYMENTS;
contexts[2] = TrustNetContexts.CODE_EXEC;

trustGraph.rateEdgeBatch(agents, levels, contexts);
```

---

## Gas Costs

| Operation | Gas Cost (approx) |
|-----------|-------------------|
| `rateEdge` (first in tx) | ~21,000 |
| `rateEdge` (subsequent) | ~5,000 |
| `rateEdgeBatch` (3 edges) | ~30,000 |

---

## Canonical Context IDs

Computed as `keccak256("trustnet:ctx:{name}:v1")`:

```
GLOBAL     = 0x430faa5635b6f437d8b5a2d66333fe4fbcf75602232a76b67e94fd4a3275169b
PAYMENTS   = 0x195c31d552212fd148934033b94b89c00b603e2b73e757a2b7684b4cc9602147
CODE_EXEC  = 0x5efe84ba1b51e4f09cf7666eca4d0685fcccf1ee1f5c051bfd1b40c537b4565b
WRITES     = 0xa4d767d43a1aa6ce314b2c1df834966b812e18b0b99fcce9faf1591c0a6f2674
DEFI_EXEC  = 0x3372ad16565f09e46bfdcd8668e8ddb764599c1e6088d92a088c17ecb464ad65
```

---

## Integration with ERC-8004

Off-chain indexers can ingest both:

1. **TrustGraph EdgeRated events** (curator/override ratings)
2. **ERC-8004 NewFeedback events** (agent→client interactions)

When processing ERC-8004 feedback:
```solidity
// Only ingest if tagged for TrustNet
if (tag2 == keccak256("trustnet:v1")) {
    // Map score (0-100) to level (-2 to +2)
    // Use tag1 as contextId
    // Use client as rater, agentWallet as target
}
```

Quantization mapping (from whitepaper §3.2):
- `80-100` → `+2`
- `60-79`  → `+1`
- `40-59`  → `0`
- `20-39`  → `-1`
- `0-19`   → `-2`

---

## Security Considerations

1. **No access control** - anyone can rate anyone (open participation)
   - Gatekeepers choose which observers they trust
   - Direct overrides by observers always respected

2. **No on-chain scoring** - this contract only emits events
   - Scores computed off-chain by indexer
   - Verified on-chain by TwoHop library (separate contract)

3. **Context binding** - always scope ratings to appropriate contexts
   - Don't use GLOBAL for sensitive capabilities
   - Prefer specific contexts (PAYMENTS, CODE_EXEC, etc.)

4. **Latest-wins** - subsequent ratings override previous ones
   - Indexers use (block, txIndex, logIndex) for ordering
   - No deletion, only updates (set to 0 for neutral)

---

## Development

### Compile with Foundry
```bash
forge build
```

### Compile with Hardhat
```bash
npx hardhat compile
```

### Deploy with Foundry
```bash
# Deploy to local network
forge create TrustGraph.sol:TrustGraph

# Deploy to Sepolia testnet
forge create TrustGraph.sol:TrustGraph \
  --rpc-url $SEPOLIA_RPC_URL \
  --private-key $PRIVATE_KEY \
  --verify
```

### Deploy with Hardhat
```javascript
const TrustGraph = await ethers.getContractFactory("TrustGraph");
const trustGraph = await TrustGraph.deploy();
await trustGraph.deployed();
```

---

## License

MIT - see [LICENSE](../LICENSE) for details.

## Related Contracts (TODO)

- **RootRegistry** - Stores Merkle roots for proof verification
- **TwoHop** - Verifies 2-hop proofs and computes scores
- **SparseMerkleMap** - Merkle proof verification library

## References

- [ERC-8004 Specification](https://eips.ethereum.org/EIPS/eip-8004)
- [TrustNet Whitepaper](../WHITEPAPER.md)
- [Sparse Merkle Trees](https://docs.iden3.io/publications/pdfs/Merkle-Tree.pdf)
