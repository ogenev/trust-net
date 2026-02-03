//! TrustNet offline verifier (Spec v0.6).
//!
//! Verifies:
//! - root authenticity via publisher signature (server mode)
//! - Sparse Merkle proofs for DT / DE / ET edges
//! - score + decision consistency with v0.6 evidence gating

use anyhow::Context;
use serde::{Deserialize, Serialize};
use trustnet_core::{
    hashing::compute_edge_key, hashing::compute_root_signature_hash, ContextId, LeafValueV1, Level,
    PrincipalId, B256,
};

fn parse_hex_bytes(s: &str) -> anyhow::Result<Vec<u8>> {
    let s = s.strip_prefix("0x").unwrap_or(s);
    Ok(hex::decode(s)?)
}

fn parse_b256(s: &str) -> anyhow::Result<B256> {
    Ok(s.parse::<B256>()?)
}

/// `/v1/root` response (subset used by verifier).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RootResponseV1 {
    pub epoch: u64,
    #[serde(rename = "graphRoot")]
    pub graph_root: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub manifest: Option<serde_json::Value>,
    #[serde(rename = "manifestHash")]
    pub manifest_hash: Option<String>,
    #[serde(rename = "publisherSig")]
    pub publisher_sig: Option<String>,
}

/// Leaf value object in JSON proofs / why sections.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LeafValueJson {
    pub level: i8,
    #[serde(rename = "updatedAt")]
    pub updated_at: u64,
    #[serde(rename = "evidenceHash")]
    pub evidence_hash: String,
}

impl LeafValueJson {
    pub fn to_leaf_value_v1(&self) -> anyhow::Result<LeafValueV1> {
        Ok(LeafValueV1 {
            level: Level::new(self.level)?,
            updated_at_u64: self.updated_at,
            evidence_hash: parse_b256(&self.evidence_hash)?,
        })
    }
}

/// Canonical JSON proof format (uncompressed).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SmmProofV1Json {
    #[serde(rename = "type")]
    pub ty: String,
    #[serde(rename = "edgeKey")]
    pub edge_key: String,
    #[serde(rename = "contextId")]
    pub context_id: Option<String>,
    pub rater: Option<String>,
    pub target: Option<String>,
    #[serde(rename = "isMembership")]
    pub is_membership: bool,
    #[serde(rename = "leafValue")]
    pub leaf_value: Option<LeafValueJson>,
    pub siblings: Vec<String>,
    pub format: String,
}

/// Decision bundle response (Spec v0.4 shape).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DecisionBundleV1Json {
    #[serde(rename = "type")]
    pub ty: String,
    pub epoch: u64,
    #[serde(rename = "graphRoot")]
    pub graph_root: String,
    #[serde(rename = "manifestHash")]
    pub manifest_hash: String,
    pub decider: String,
    pub target: String,
    #[serde(rename = "contextId")]
    pub context_id: String,
    pub decision: String,
    pub score: i8,
    pub thresholds: ThresholdsJson,
    pub endorser: Option<String>,
    pub why: WhyJson,
    pub constraints: ConstraintsJson,
    pub proofs: ProofsJson,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThresholdsJson {
    pub allow: i8,
    pub ask: i8,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConstraintsJson {
    #[serde(rename = "ttlSeconds")]
    pub ttl_seconds: u64,
    #[serde(rename = "requireEvidenceForPositiveET")]
    pub require_evidence_for_positive_et: bool,
    #[serde(rename = "requireEvidenceForPositiveDT")]
    pub require_evidence_for_positive_dt: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WhyJson {
    #[serde(rename = "edgeDE")]
    pub edge_de: LeafValueJson,
    #[serde(rename = "edgeET")]
    pub edge_et: LeafValueJson,
    #[serde(rename = "edgeDT")]
    pub edge_dt: LeafValueJson,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProofsJson {
    #[serde(rename = "DE")]
    pub de: Option<SmmProofV1Json>,
    #[serde(rename = "ET")]
    pub et: Option<SmmProofV1Json>,
    #[serde(rename = "DT")]
    pub dt: SmmProofV1Json,
}

/// Signed action receipt (gateway side).
///
/// This is a self-contained audit artifact that includes:
/// - the root bundle
/// - the decision bundle (including proofs)
/// - tool call hashes
/// - an optional receipt signature
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ActionReceiptUnsignedV1 {
    #[serde(rename = "type")]
    pub ty: String,
    #[serde(rename = "createdAt")]
    pub created_at: String,
    pub tool: String,
    #[serde(rename = "argsHash")]
    pub args_hash: String,
    #[serde(rename = "resultHash")]
    pub result_hash: String,
    pub root: serde_json::Value,
    #[serde(rename = "decisionBundle")]
    pub decision_bundle: serde_json::Value,
    #[serde(rename = "policyManifestHash", skip_serializing_if = "Option::is_none")]
    pub policy_manifest_hash: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ActionReceiptV1 {
    #[serde(flatten)]
    pub unsigned: ActionReceiptUnsignedV1,
    pub signer: String,
    pub signature: String,
}

/// Verify root signature, returning the recovered publisher address.
pub fn verify_root_signature(
    root: &RootResponseV1,
    expected_publisher: Option<trustnet_core::Address>,
) -> anyhow::Result<trustnet_core::Address> {
    let graph_root = parse_b256(&root.graph_root)?;
    let manifest_hash = root
        .manifest_hash
        .as_deref()
        .context("root.manifestHash missing")?;
    let manifest_hash = parse_b256(manifest_hash)?;

    let publisher_sig = root
        .publisher_sig
        .as_deref()
        .context("root.publisherSig missing")?;
    let sig_bytes = parse_hex_bytes(publisher_sig)?;

    let sig = alloy_primitives::PrimitiveSignature::from_raw(&sig_bytes)
        .map_err(|e| anyhow::anyhow!("invalid publisherSig: {}", e))?;

    let digest = compute_root_signature_hash(root.epoch, &graph_root, &manifest_hash);
    let recovered = sig
        .recover_address_from_prehash(&digest)
        .map_err(|e| anyhow::anyhow!("failed to recover publisher address: {}", e))?;

    if let Some(expected) = expected_publisher {
        anyhow::ensure!(
            recovered == expected,
            "publisher signature mismatch: recovered={}, expected={}",
            recovered,
            expected
        );
    }

    Ok(recovered)
}

fn verify_smm_proof_against_root(
    proof: &SmmProofV1Json,
    root: &B256,
) -> anyhow::Result<LeafValueV1> {
    anyhow::ensure!(
        proof.ty == "trustnet.smmProof.v1",
        "unsupported proof type: {}",
        proof.ty
    );
    anyhow::ensure!(
        proof.format == "uncompressed",
        "unsupported proof format: {}",
        proof.format
    );
    let edge_key = parse_b256(&proof.edge_key)?;
    anyhow::ensure!(
        proof.siblings.len() == 256,
        "proof siblings must have 256 entries"
    );

    let siblings: Vec<B256> = proof
        .siblings
        .iter()
        .map(|s| parse_b256(s))
        .collect::<anyhow::Result<_>>()?;

    let leaf_value = if proof.is_membership {
        let lv = proof
            .leaf_value
            .as_ref()
            .context("membership proof missing leafValue")?
            .to_leaf_value_v1()?;
        lv.encode().to_vec()
    } else {
        Vec::new()
    };

    let smm_proof = trustnet_smm::SmmProof {
        key: edge_key,
        leaf_value: leaf_value.clone(),
        siblings,
        is_membership: proof.is_membership,
    };

    anyhow::ensure!(
        smm_proof.verify(*root),
        "invalid merkle proof for edgeKey={}",
        proof.edge_key
    );

    if proof.is_membership {
        LeafValueV1::decode(&leaf_value)
            .map_err(|e| anyhow::anyhow!("invalid leafValue encoding: {}", e))
    } else {
        Ok(LeafValueV1::default_neutral())
    }
}

fn verify_edge_key_binding(proof: &SmmProofV1Json) -> anyhow::Result<()> {
    let Some(rater) = proof.rater.as_deref() else {
        return Ok(());
    };
    let Some(target) = proof.target.as_deref() else {
        return Ok(());
    };
    let Some(context_id) = proof.context_id.as_deref() else {
        return Ok(());
    };

    let rater = rater
        .parse::<PrincipalId>()
        .context("invalid proof.rater")?;
    let target = target
        .parse::<PrincipalId>()
        .context("invalid proof.target")?;
    let context_id = context_id
        .parse::<ContextId>()
        .context("invalid proof.contextId")?;

    let expected = compute_edge_key(&rater, &target, &context_id);
    let got = parse_b256(&proof.edge_key)?;

    anyhow::ensure!(expected == got, "edgeKey mismatch for proof");
    Ok(())
}

fn verify_manifest_hash(root: &RootResponseV1) -> anyhow::Result<()> {
    let Some(manifest) = root.manifest.as_ref() else {
        return Ok(());
    };
    let manifest_hash = root
        .manifest_hash
        .as_deref()
        .context("root.manifestHash missing")?;
    let manifest_hash = parse_b256(manifest_hash)?;
    let canonical = serde_jcs::to_vec(manifest).context("failed to canonicalize manifest")?;
    let computed = trustnet_core::hashing::keccak256(&canonical);
    anyhow::ensure!(
        computed == manifest_hash,
        "manifestHash mismatch (root.manifest does not match manifestHash)"
    );
    Ok(())
}

/// Verify a decision bundle against a root response (server/chain mode).
pub fn verify_decision_bundle(
    root: &RootResponseV1,
    bundle: &DecisionBundleV1Json,
    expected_publisher: Option<trustnet_core::Address>,
) -> anyhow::Result<()> {
    let recovered = verify_root_signature(root, expected_publisher)?;
    verify_manifest_hash(root)?;

    anyhow::ensure!(
        bundle.ty == "trustnet.decisionBundle.v1",
        "decision bundle type mismatch: {}",
        bundle.ty
    );

    // Bind bundle to root.
    anyhow::ensure!(
        bundle.epoch == root.epoch,
        "epoch mismatch (bundle={}, root={})",
        bundle.epoch,
        root.epoch
    );
    anyhow::ensure!(bundle.graph_root == root.graph_root, "graphRoot mismatch");
    if let Some(root_mh) = root.manifest_hash.as_deref() {
        anyhow::ensure!(bundle.manifest_hash == root_mh, "manifestHash mismatch");
    }

    let graph_root = parse_b256(&bundle.graph_root)?;

    // Verify proofs and edgeKey bindings (when proof includes rater/target/contextId).
    verify_edge_key_binding(&bundle.proofs.dt)?;
    let dt = verify_smm_proof_against_root(&bundle.proofs.dt, &graph_root)?;

    let (de, et, endorser) = match (
        bundle.endorser.as_deref(),
        &bundle.proofs.de,
        &bundle.proofs.et,
    ) {
        (Some(endorser), Some(de), Some(et)) => {
            verify_edge_key_binding(de)?;
            verify_edge_key_binding(et)?;
            let de_lv = verify_smm_proof_against_root(de, &graph_root)?;
            let et_lv = verify_smm_proof_against_root(et, &graph_root)?;
            let endorser = endorser
                .parse::<PrincipalId>()
                .context("invalid bundle.endorser")?;
            (de_lv, et_lv, Some(endorser))
        }
        (None, None, None) => (
            LeafValueV1::default_neutral(),
            LeafValueV1::default_neutral(),
            None,
        ),
        (Some(_), _, _) => {
            anyhow::bail!("endorser present but DE/ET proofs missing");
        }
        (None, Some(_), _) | (None, _, Some(_)) => {
            anyhow::bail!("DE/ET proofs present but endorser missing");
        }
    };

    // Verify "why" matches decoded proof values.
    let why_dt = bundle.why.edge_dt.to_leaf_value_v1()?;
    let why_de = bundle.why.edge_de.to_leaf_value_v1()?;
    let why_et = bundle.why.edge_et.to_leaf_value_v1()?;

    anyhow::ensure!(why_dt == dt, "why.edgeDT does not match DT proof leafValue");
    anyhow::ensure!(why_de == de, "why.edgeDE does not match DE proof leafValue");
    anyhow::ensure!(why_et == et, "why.edgeET does not match ET proof leafValue");

    // Verify score + decision consistency (v0.6 evidence gating).
    let thresholds =
        trustnet_engine::Thresholds::new(bundle.thresholds.allow, bundle.thresholds.ask)
            .map_err(|e| anyhow::anyhow!("invalid thresholds: {}", e))?;

    let evidence_policy = trustnet_engine::EvidencePolicy {
        require_positive_et_evidence: bundle.constraints.require_evidence_for_positive_et,
        require_positive_dt_evidence: bundle.constraints.require_evidence_for_positive_dt,
    };
    let dt_has_evidence = dt.evidence_hash != B256::ZERO;
    let candidates = endorser
        .map(|endorser| {
            vec![trustnet_engine::CandidateEvidence {
                endorser,
                level_de: de.level,
                level_et: et.level,
                et_has_evidence: et.evidence_hash != B256::ZERO,
            }]
        })
        .unwrap_or_default();

    let result = trustnet_engine::decide_with_evidence(
        thresholds,
        evidence_policy,
        dt.level,
        dt_has_evidence,
        &candidates,
    );

    anyhow::ensure!(
        result.score == bundle.score,
        "score mismatch (computed={}, bundle={})",
        result.score,
        bundle.score
    );
    anyhow::ensure!(
        result.decision.as_str() == bundle.decision,
        "decision mismatch (computed={}, bundle={})",
        result.decision.as_str(),
        bundle.decision
    );

    let bundle_endorser = bundle.endorser.as_deref();
    match (endorser, result.endorser) {
        (Some(parsed), Some(computed)) => {
            anyhow::ensure!(
                parsed == computed,
                "endorser mismatch (bundle={}, computed=0x{})",
                bundle_endorser.unwrap_or("<missing>"),
                hex::encode(computed.as_bytes())
            );
        }
        (Some(_), None) => {
            anyhow::bail!("endorser present but decision does not select it");
        }
        (None, Some(_)) => {
            anyhow::bail!("decision selected an endorser but bundle.endorser is missing");
        }
        (None, None) => {}
    }

    // If we reached here, everything verifies.
    let _ = recovered;
    Ok(())
}

/// Sign an action receipt using EIP-191, returning the signer address and signature.
pub fn sign_action_receipt_v1(
    unsigned: ActionReceiptUnsignedV1,
    private_key_bytes: &[u8; 32],
) -> anyhow::Result<ActionReceiptV1> {
    use alloy_primitives::eip191_hash_message;
    use k256::ecdsa::SigningKey;

    let signing_key = SigningKey::from_bytes(private_key_bytes.into())
        .map_err(|e| anyhow::anyhow!("invalid secp256k1 private key: {}", e))?;

    let canonical = serde_jcs::to_vec(&unsigned)?;
    let digest = eip191_hash_message(&canonical);
    let (sig, recid) = signing_key
        .sign_prehash_recoverable(digest.as_slice())
        .map_err(|e| anyhow::anyhow!("failed to sign receipt: {}", e))?;

    let signature = alloy_primitives::PrimitiveSignature::from((sig, recid));
    let signer = alloy_primitives::Address::from_public_key(signing_key.verifying_key());

    Ok(ActionReceiptV1 {
        unsigned,
        signer: format!("0x{}", hex::encode(signer.as_slice())),
        signature: format!("0x{}", hex::encode(signature.as_bytes())),
    })
}

/// Verify an action receipt's EIP-191 signature and embedded decision bundle.
pub fn verify_action_receipt_v1(
    receipt: &ActionReceiptV1,
    expected_publisher: Option<trustnet_core::Address>,
    expected_signer: Option<trustnet_core::Address>,
) -> anyhow::Result<trustnet_core::Address> {
    // Verify embedded decision bundle (root sig + merkle proofs + score/decision).
    let root: RootResponseV1 =
        serde_json::from_value(receipt.unsigned.root.clone()).context("invalid receipt.root")?;
    let bundle: DecisionBundleV1Json =
        serde_json::from_value(receipt.unsigned.decision_bundle.clone())
            .context("invalid receipt.decisionBundle")?;
    verify_decision_bundle(&root, &bundle, expected_publisher)?;

    // Verify receipt signature.
    let canonical = serde_jcs::to_vec(&receipt.unsigned)?;
    let sig_bytes = parse_hex_bytes(&receipt.signature)?;
    let sig = alloy_primitives::PrimitiveSignature::from_raw(&sig_bytes)
        .map_err(|e| anyhow::anyhow!("invalid receipt signature bytes: {}", e))?;

    let recovered = sig
        .recover_address_from_msg(&canonical)
        .map_err(|e| anyhow::anyhow!("failed to recover receipt signer: {}", e))?;

    let claimed = receipt
        .signer
        .parse::<trustnet_core::Address>()
        .context("invalid receipt.signer")?;
    anyhow::ensure!(
        recovered == claimed,
        "receipt signer mismatch (recovered={}, claimed={})",
        recovered,
        claimed
    );

    if let Some(expected) = expected_signer {
        anyhow::ensure!(
            recovered == expected,
            "receipt signer mismatch (recovered={}, expected={})",
            recovered,
            expected
        );
    }

    Ok(recovered)
}

/// Generate a small v0.4 vector bundle for cross-language hashing verification.
pub fn generate_vectors_v0_4() -> serde_json::Value {
    use trustnet_core::hashing::{compute_leaf_hash, keccak256};
    use trustnet_smm::SmmBuilder;

    // Use fixed EVM addresses for vectors.
    let mut rater_bytes = [0u8; 20];
    rater_bytes[19] = 1;
    let rater_addr = trustnet_core::Address::from_slice(&rater_bytes);

    let mut target_bytes = [0u8; 20];
    target_bytes[19] = 2;
    let target_addr = trustnet_core::Address::from_slice(&target_bytes);

    let rater_pid = PrincipalId::from_evm_address(rater_addr);
    let target_pid = PrincipalId::from_evm_address(target_addr);
    let context = ContextId::from(trustnet_core::CTX_GLOBAL);

    let edge_key = compute_edge_key(&rater_pid, &target_pid, &context);
    let leaf_v = LeafValueV1 {
        level: Level::strong_positive(),
        updated_at_u64: 123,
        evidence_hash: B256::ZERO,
    };
    let leaf_bytes = leaf_v.encode().to_vec();
    let leaf_hash = compute_leaf_hash(&edge_key, &leaf_bytes);

    // Tiny tree with one leaf.
    let mut builder = SmmBuilder::new();
    builder
        .insert(edge_key, leaf_bytes.clone())
        .expect("insert");
    let smm = builder.build();
    let root = smm.root();
    let proof = smm.prove(edge_key).expect("prove");

    serde_json::json!({
        "specVersion": "trustnet-spec-0.6",
        "principalId": {
            "raterAddress": format!("0x{}", hex::encode(rater_addr.as_slice())),
            "raterPrincipalId": format!("0x{}", hex::encode(rater_pid.as_bytes())),
            "targetAddress": format!("0x{}", hex::encode(target_addr.as_slice())),
            "targetPrincipalId": format!("0x{}", hex::encode(target_pid.as_bytes()))
        },
        "edgeKey": format!("0x{}", hex::encode(edge_key.as_slice())),
        "leafValueV1": {
            "level": leaf_v.level.value(),
            "updatedAt": leaf_v.updated_at_u64,
            "evidenceHash": format!("0x{}", hex::encode(leaf_v.evidence_hash.as_slice()))
        },
        "leafValueBytes": format!("0x{}", hex::encode(&leaf_bytes)),
        "leafHash": format!("0x{}", hex::encode(leaf_hash.as_slice())),
        "graphRoot": format!("0x{}", hex::encode(root.as_slice())),
        "membershipProof": {
            "edgeKey": format!("0x{}", hex::encode(proof.key.as_slice())),
            "isMembership": proof.is_membership,
            "leafValueBytes": format!("0x{}", hex::encode(&proof.leaf_value)),
            "siblings": proof.siblings.iter().map(|s| format!("0x{}", hex::encode(s.as_slice()))).collect::<Vec<_>>()
        },
        "hashes": {
            "tagTrustnetV1": format!("0x{}", hex::encode(trustnet_core::TAG_TRUSTNET_V1.as_slice())),
            "contextRegistryHash": format!("0x{}", hex::encode(keccak256(br#"[\"trustnet:ctx:global:v1\",\"trustnet:ctx:payments:v1\",\"trustnet:ctx:code-exec:v1\",\"trustnet:ctx:writes:v1\",\"trustnet:ctx:messaging:v1\"]"#).as_slice()))
        }
    })
}
