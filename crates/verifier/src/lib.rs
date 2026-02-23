//! TrustNet offline verifier (v1.1 spec).
//!
//! Verifies:
//! - root authenticity via publisher signature (server mode)
//! - Sparse Merkle proofs for DT / DE / ET edges
//! - score consistency with TrustNet v1.1 rule

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

fn parse_bitmap_256(s: &str) -> anyhow::Result<[u8; 32]> {
    let bytes = parse_hex_bytes(s)?;
    anyhow::ensure!(
        bytes.len() == 32,
        "invalid bitmap length: expected 32 bytes, got {}",
        bytes.len()
    );
    let mut bitmap = [0u8; 32];
    bitmap.copy_from_slice(&bytes);
    Ok(bitmap)
}

fn bitmap_bit_is_set(bitmap: &[u8; 32], idx: usize) -> bool {
    let byte_index = 31 - (idx / 8);
    (bitmap[byte_index] & (1 << (idx % 8))) != 0
}

fn smm_default_hashes() -> [B256; 257] {
    let empty = trustnet_smm::SmmBuilder::new().build();
    *empty.default_hashes()
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
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub event: Option<serde_json::Value>,
    #[serde(
        rename = "feedbackURI",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub feedback_uri: Option<String>,
    #[serde(
        rename = "feedbackHash",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub feedback_hash: Option<String>,
}

impl LeafValueJson {
    pub fn to_leaf_value_v1(&self) -> anyhow::Result<LeafValueV1> {
        Ok(LeafValueV1 {
            level: Level::new(self.level)?,
        })
    }
}

/// Canonical JSON proof format.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProofLeafJson {
    #[serde(rename = "K")]
    pub k: String,
    #[serde(rename = "V")]
    pub v: u8,
}

/// Canonical JSON proof format.
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
    pub leaf: Option<ProofLeafJson>,
    #[serde(rename = "isAbsent")]
    pub is_absent: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bitmap: Option<String>,
    pub siblings: Vec<String>,
    pub format: String,
}

/// Score proof payload from `/v1/score`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScoreProofV1Json {
    #[serde(rename = "graphRoot")]
    pub graph_root: String,
    #[serde(rename = "manifestHash")]
    pub manifest_hash: String,
    pub decider: String,
    pub target: String,
    #[serde(rename = "contextTag")]
    pub context_tag: String,
    #[serde(rename = "contextId")]
    pub context_id: String,
    pub endorser: Option<String>,
    pub proofs: ProofsJson,
}

/// Score response shape returned by `/v1/score/:decider/:target`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScoreBundleV1Json {
    pub score: i8,
    pub epoch: u64,
    pub why: WhyJson,
    pub proof: ScoreProofV1Json,
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
/// - the score bundle (including proofs)
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
    #[serde(rename = "scoreBundle")]
    pub score_bundle: serde_json::Value,
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
    let edge_key = parse_b256(&proof.edge_key)?;
    let is_membership = !proof.is_absent;
    let siblings: Vec<B256> = match proof.format.as_str() {
        "uncompressed" => {
            anyhow::ensure!(
                proof.siblings.len() == 256,
                "proof siblings must have 256 entries"
            );
            proof
                .siblings
                .iter()
                .map(|s| parse_b256(s))
                .collect::<anyhow::Result<_>>()?
        }
        "bitmap" => {
            let bitmap_hex = proof
                .bitmap
                .as_deref()
                .context("bitmap proof missing bitmap field")?;
            let bitmap = parse_bitmap_256(bitmap_hex)?;
            let default_hashes = smm_default_hashes();
            let mut packed_iter = proof.siblings.iter();
            let mut expanded = vec![B256::ZERO; 256];

            for i in 0..256 {
                let sibling = if bitmap_bit_is_set(&bitmap, i) {
                    let packed = packed_iter.next().with_context(|| {
                        format!("bitmap set bit {} but packed sibling missing", i)
                    })?;
                    parse_b256(packed)?
                } else {
                    default_hashes[i]
                };
                expanded[255 - i] = sibling;
            }

            anyhow::ensure!(
                packed_iter.next().is_none(),
                "bitmap proof has extra packed siblings"
            );
            expanded
        }
        other => anyhow::bail!("unsupported proof format: {}", other),
    };

    let leaf_value = if is_membership {
        let leaf = proof
            .leaf
            .as_ref()
            .context("membership proof missing leaf")?;
        let leaf_key = parse_b256(&leaf.k)?;
        anyhow::ensure!(leaf_key == edge_key, "leaf.K does not match proof.edgeKey");
        let level =
            Level::from_smm_value(leaf.v).map_err(|e| anyhow::anyhow!("invalid leaf.V: {}", e))?;
        LeafValueV1 { level }.encode().to_vec()
    } else {
        anyhow::ensure!(proof.leaf.is_none(), "absence proof must not include leaf");
        Vec::new()
    };

    let smm_proof = trustnet_smm::SmmProof {
        key: edge_key,
        leaf_value: leaf_value.clone(),
        siblings,
        is_membership,
    };

    anyhow::ensure!(
        smm_proof.verify(*root),
        "invalid merkle proof for edgeKey={}",
        proof.edge_key
    );

    if is_membership {
        LeafValueV1::decode(&leaf_value)
            .map_err(|e| anyhow::anyhow!("invalid leafValue encoding: {}", e))
    } else {
        Ok(LeafValueV1::default_neutral())
    }
}

fn verify_expected_edge_binding(
    proof: &SmmProofV1Json,
    expected_rater: &PrincipalId,
    expected_target: &PrincipalId,
    expected_context: &ContextId,
) -> anyhow::Result<()> {
    if let Some(rater) = proof.rater.as_deref() {
        let got = rater
            .parse::<PrincipalId>()
            .context("invalid proof.rater")?;
        anyhow::ensure!(got == *expected_rater, "proof.rater mismatch");
    }

    if let Some(target) = proof.target.as_deref() {
        let got = target
            .parse::<PrincipalId>()
            .context("invalid proof.target")?;
        anyhow::ensure!(got == *expected_target, "proof.target mismatch");
    }

    if let Some(context_id) = proof.context_id.as_deref() {
        let got = context_id
            .parse::<ContextId>()
            .context("invalid proof.contextId")?;
        anyhow::ensure!(got == *expected_context, "proof.contextId mismatch");
    }

    let expected = compute_edge_key(expected_rater, expected_target, expected_context);
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

fn score_v1_1(level_dt: Level, level_de: Level, level_et: Level) -> i8 {
    let l_dt = i16::from(level_dt.value());
    let l_de_pos = i16::from(level_de.value().max(0));
    let l_et = i16::from(level_et.value());
    let numerator = (2 * l_dt) + (l_de_pos * l_et);
    (numerator / 2).clamp(-2, 2) as i8
}

/// Verify a `/v1/score` payload against a `/v1/root` response.
pub fn verify_score_bundle(
    root: &RootResponseV1,
    bundle: &ScoreBundleV1Json,
    expected_publisher: Option<trustnet_core::Address>,
) -> anyhow::Result<()> {
    let _recovered = verify_root_signature(root, expected_publisher)?;
    verify_manifest_hash(root)?;

    // Bind bundle to root.
    anyhow::ensure!(
        bundle.epoch == root.epoch,
        "epoch mismatch (bundle={}, root={})",
        bundle.epoch,
        root.epoch
    );
    anyhow::ensure!(
        bundle.proof.graph_root == root.graph_root,
        "graphRoot mismatch"
    );
    if let Some(root_mh) = root.manifest_hash.as_deref() {
        anyhow::ensure!(
            bundle.proof.manifest_hash == root_mh,
            "manifestHash mismatch"
        );
    }

    let bundle_decider = bundle
        .proof
        .decider
        .parse::<PrincipalId>()
        .context("invalid bundle.proof.decider")?;
    let bundle_target = bundle
        .proof
        .target
        .parse::<PrincipalId>()
        .context("invalid bundle.proof.target")?;
    let bundle_context = bundle
        .proof
        .context_id
        .parse::<ContextId>()
        .context("invalid bundle.proof.contextId")?;

    let context_from_tag = trustnet_core::context_id_from_tag_v1(&bundle.proof.context_tag)
        .ok_or_else(|| anyhow::anyhow!("invalid bundle.proof.contextTag"))?;
    anyhow::ensure!(
        *bundle_context.inner() == context_from_tag,
        "contextId/contextTag mismatch in score proof"
    );

    let graph_root = parse_b256(&bundle.proof.graph_root)?;

    // DT must bind to (decider, target, context).
    verify_expected_edge_binding(
        &bundle.proof.proofs.dt,
        &bundle_decider,
        &bundle_target,
        &bundle_context,
    )?;
    let dt = verify_smm_proof_against_root(&bundle.proof.proofs.dt, &graph_root)?;

    let (de, et, endorser) = match (
        bundle.proof.endorser.as_deref(),
        &bundle.proof.proofs.de,
        &bundle.proof.proofs.et,
    ) {
        (Some(endorser), Some(de), Some(et)) => {
            let endorser = endorser
                .parse::<PrincipalId>()
                .context("invalid bundle.endorser")?;
            verify_expected_edge_binding(de, &bundle_decider, &endorser, &bundle_context)?;
            verify_expected_edge_binding(et, &endorser, &bundle_target, &bundle_context)?;

            anyhow::ensure!(
                !de.is_absent,
                "DE proof must be membership when endorser is present"
            );
            anyhow::ensure!(
                !et.is_absent,
                "ET proof must be membership when endorser is present"
            );

            let de_lv = verify_smm_proof_against_root(de, &graph_root)?;
            let et_lv = verify_smm_proof_against_root(et, &graph_root)?;
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

    // Verify score consistency with TrustNet v1.1 formula.
    let computed_score = score_v1_1(dt.level, de.level, et.level);
    anyhow::ensure!(
        computed_score == bundle.score,
        "score mismatch (computed={}, bundle={})",
        computed_score,
        bundle.score
    );

    if endorser.is_some() {
        let baseline = score_v1_1(dt.level, Level::neutral(), Level::neutral());
        anyhow::ensure!(
            computed_score > baseline,
            "endorser present but does not improve score over direct edge"
        );
    }

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

/// Verify an action receipt's EIP-191 signature and embedded score bundle.
pub fn verify_action_receipt_v1(
    receipt: &ActionReceiptV1,
    expected_publisher: Option<trustnet_core::Address>,
    expected_signer: Option<trustnet_core::Address>,
) -> anyhow::Result<trustnet_core::Address> {
    // Verify embedded score bundle (root sig + merkle proofs + score).
    let root: RootResponseV1 =
        serde_json::from_value(receipt.unsigned.root.clone()).context("invalid receipt.root")?;
    let bundle: ScoreBundleV1Json = serde_json::from_value(receipt.unsigned.score_bundle.clone())
        .context("invalid receipt.scoreBundle")?;
    verify_score_bundle(&root, &bundle, expected_publisher)?;

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

/// Generate a small v1.1 vector bundle for cross-language hashing verification.
pub fn generate_vectors_v1_1() -> serde_json::Value {
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
    let context = ContextId::from(trustnet_core::CTX_CODE_EXEC);

    let edge_key = compute_edge_key(&rater_pid, &target_pid, &context);
    let leaf_v = LeafValueV1 {
        level: Level::strong_positive(),
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
    let default_hashes = SmmBuilder::new().build().default_hashes().to_owned();

    let mut bitmap = [0u8; 32];
    let mut packed_siblings = Vec::new();
    for (i, default_sibling) in default_hashes.iter().enumerate().take(256) {
        let depth = 255 - i;
        let sibling = proof.siblings[depth];
        if sibling != *default_sibling {
            let byte_index = 31 - (i / 8);
            bitmap[byte_index] |= 1 << (i % 8);
            packed_siblings.push(format!("0x{}", hex::encode(sibling.as_slice())));
        }
    }

    let context_strings: Vec<&str> = trustnet_core::CANONICAL_CONTEXTS_V1
        .iter()
        .map(|(name, _)| *name)
        .collect();
    let context_registry_hash = keccak256(
        &serde_jcs::to_vec(&context_strings).expect("JCS serialization for context registry hash"),
    );

    serde_json::json!({
        "version": "trustnet-v1.1",
        "principalId": {
            "raterAddress": format!("0x{}", hex::encode(rater_addr.as_slice())),
            "raterPrincipalId": format!("0x{}", hex::encode(rater_pid.as_bytes())),
            "targetAddress": format!("0x{}", hex::encode(target_addr.as_slice())),
            "targetPrincipalId": format!("0x{}", hex::encode(target_pid.as_bytes()))
        },
        "edgeKey": format!("0x{}", hex::encode(edge_key.as_slice())),
        "leafValueV1": {
            "level": leaf_v.level.value(),
            "V": leaf_v.encode()[0]
        },
        "leafValueBytes": format!("0x{}", hex::encode(&leaf_bytes)),
        "leafHash": format!("0x{}", hex::encode(leaf_hash.as_slice())),
        "graphRoot": format!("0x{}", hex::encode(root.as_slice())),
        "membershipProof": {
            "edgeKey": format!("0x{}", hex::encode(proof.key.as_slice())),
            "leaf": {
                "K": format!("0x{}", hex::encode(proof.key.as_slice())),
                "V": leaf_v.encode()[0]
            },
            "isAbsent": false,
            "bitmap": format!("0x{}", hex::encode(bitmap)),
            "siblings": packed_siblings
        },
        "hashes": {
            "tagTrustnetV1": format!("0x{}", hex::encode(trustnet_core::TAG_TRUSTNET_V1.as_slice())),
            "contextRegistryHash": format!("0x{}", hex::encode(context_registry_hash.as_slice())),
            "smmHashEmpty": format!("0x{}", hex::encode(trustnet_core::hashing::compute_empty_hash().as_slice()))
        }
    })
}

/// Deprecated alias for older callers.
pub fn generate_vectors_v0_6() -> serde_json::Value {
    generate_vectors_v1_1()
}

/// Deprecated alias for older callers.
pub fn generate_vectors_v0_4() -> serde_json::Value {
    generate_vectors_v1_1()
}
