use alloy_primitives::{Address, PrimitiveSignature, B256};
use trustnet_core::{
    hashing::{compute_edge_key, compute_root_signature_hash, keccak256},
    ContextId, LeafValueV1, Level, PrincipalId,
};
use trustnet_smm::SmmBuilder;

fn hex_b256(v: &B256) -> String {
    format!("0x{}", hex::encode(v.as_slice()))
}

fn hex_32(bytes: &[u8; 32]) -> String {
    format!("0x{}", hex::encode(bytes))
}

#[test]
fn action_receipt_roundtrip_verifies() -> anyhow::Result<()> {
    // Publisher key (root authenticity).
    let publisher_key = [0x11u8; 32];
    let publisher_signing_key = k256::ecdsa::SigningKey::from_bytes((&publisher_key).into())?;
    let publisher_addr = Address::from_public_key(publisher_signing_key.verifying_key());

    // Receipt signer key (gateway).
    let receipt_key = [0x22u8; 32];
    let receipt_signing_key = k256::ecdsa::SigningKey::from_bytes((&receipt_key).into())?;
    let receipt_signer_addr = Address::from_public_key(receipt_signing_key.verifying_key());

    // Principals (EVM address => PrincipalId bytes32).
    let mut decider_bytes = [0u8; 20];
    decider_bytes[19] = 0x01;
    let decider_addr = Address::from_slice(&decider_bytes);

    let mut target_bytes = [0u8; 20];
    target_bytes[19] = 0x02;
    let target_addr = Address::from_slice(&target_bytes);

    let decider = PrincipalId::from_evm_address(decider_addr);
    let target = PrincipalId::from_evm_address(target_addr);
    let context_id = ContextId::from(trustnet_core::CTX_GLOBAL);

    // Build a tiny SMM with only DT present (direct allow).
    let dt_level = Level::strong_positive();
    let dt_leaf = LeafValueV1 {
        level: dt_level,
        updated_at_u64: 123,
        evidence_hash: B256::ZERO,
    };
    let dt_key = compute_edge_key(&decider, &target, &context_id);
    let dt_leaf_bytes = dt_leaf.encode().to_vec();

    let mut builder = SmmBuilder::new();
    builder.insert(dt_key, dt_leaf_bytes.clone())?;
    let smm = builder.build();
    let graph_root = smm.root();
    let dt_proof = smm.prove(dt_key)?;

    // Root signature (server-mode authenticity).
    let epoch = 1u64;
    let manifest_hash = keccak256(b"test-manifest");
    let digest = compute_root_signature_hash(epoch, &graph_root, &manifest_hash);
    let (sig, recid) = publisher_signing_key.sign_prehash_recoverable(digest.as_slice())?;
    let sig = PrimitiveSignature::from((sig, recid));

    let root_json = serde_json::json!({
        "epoch": epoch,
        "graphRoot": hex_b256(&graph_root),
        "manifestHash": hex_b256(&manifest_hash),
        "publisherSig": format!("0x{}", hex::encode(sig.as_bytes()))
    });

    let dt_proof_json = trustnet_verifier::SmmProofV1Json {
        ty: "trustnet.smmProof.v1".to_string(),
        edge_key: hex_b256(&dt_proof.key),
        context_id: Some(hex_b256(context_id.inner())),
        rater: Some(hex_32(decider.as_bytes())),
        target: Some(hex_32(target.as_bytes())),
        is_membership: true,
        leaf_value: Some(trustnet_verifier::LeafValueJson {
            level: dt_leaf.level.value(),
            updated_at: dt_leaf.updated_at_u64,
            evidence_hash: hex_b256(&dt_leaf.evidence_hash),
            evidence_verified: None,
        }),
        siblings: dt_proof.siblings.iter().map(hex_b256).collect(),
        format: "uncompressed".to_string(),
    };

    let decision_json = trustnet_verifier::DecisionBundleV1Json {
        ty: "trustnet.decisionBundle.v1".to_string(),
        epoch,
        graph_root: hex_b256(&graph_root),
        manifest_hash: hex_b256(&manifest_hash),
        decider: hex_32(decider.as_bytes()),
        target: hex_32(target.as_bytes()),
        context_id: hex_b256(context_id.inner()),
        decision: "allow".to_string(),
        score: 2,
        thresholds: trustnet_verifier::ThresholdsJson { allow: 2, ask: 1 },
        endorser: None,
        why: trustnet_verifier::WhyJson {
            edge_de: trustnet_verifier::LeafValueJson {
                level: 0,
                updated_at: 0,
                evidence_hash: hex_b256(&B256::ZERO),
                evidence_verified: None,
            },
            edge_et: trustnet_verifier::LeafValueJson {
                level: 0,
                updated_at: 0,
                evidence_hash: hex_b256(&B256::ZERO),
                evidence_verified: None,
            },
            edge_dt: trustnet_verifier::LeafValueJson {
                level: dt_leaf.level.value(),
                updated_at: dt_leaf.updated_at_u64,
                evidence_hash: hex_b256(&dt_leaf.evidence_hash),
                evidence_verified: None,
            },
        },
        constraints: trustnet_verifier::ConstraintsJson {
            ttl_seconds: 3600,
            require_evidence_for_positive_et: false,
            require_evidence_for_positive_dt: false,
        },
        proofs: trustnet_verifier::ProofsJson {
            de: None,
            et: None,
            dt: dt_proof_json,
        },
    };

    // Build and sign receipt.
    let unsigned = trustnet_verifier::ActionReceiptUnsignedV1 {
        ty: "trustnet.actionReceipt.v1".to_string(),
        created_at: chrono::Utc::now().to_rfc3339(),
        tool: "test.tool".to_string(),
        args_hash: hex_b256(&keccak256(b"args")),
        result_hash: hex_b256(&keccak256(b"result")),
        root: root_json,
        decision_bundle: serde_json::to_value(&decision_json)?,
        policy_manifest_hash: None,
    };

    let receipt = trustnet_verifier::sign_action_receipt_v1(unsigned, &receipt_key)?;

    // Full verification: embedded bundle + receipt signature.
    trustnet_verifier::verify_action_receipt_v1(
        &receipt,
        Some(publisher_addr),
        Some(receipt_signer_addr),
    )?;

    Ok(())
}
