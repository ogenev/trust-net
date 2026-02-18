use std::path::PathBuf;

#[test]
fn vectors_match_committed_file() {
    let generated = trustnet_verifier::generate_vectors_v0_6();

    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../docs/Test_Vectors_v0.7.json");
    let bytes = std::fs::read(&path).expect("read committed vectors file");
    let committed: serde_json::Value =
        serde_json::from_slice(&bytes).expect("parse committed vectors JSON");

    assert_eq!(
        generated,
        committed,
        "Generated vectors differ from {}",
        path.display()
    );
}
