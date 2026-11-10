#![cfg(feature = "cli")]
//! Owner-media integration; ordinary test runs never need proprietary fixtures.
#[test]
fn disc_141_150_matches_125_probe_gap_paths() {
    let required = ["BF2_PATCH141", "BF2_ISO", "BF2_PATCH150", "BF2_INSTALLED", "BF2_PROBE_READER", "BF2_GAP_REPORT"];
    if required.iter().any(|key| std::env::var_os(key).is_none()) {
        eprintln!("SKIP BF2 owner-media acceptance: set {}", required.join(", "));
        return;
    }
    let status = std::process::Command::new("python3")
        .arg(concat!(env!("CARGO_MANIFEST_DIR"), "/tools/verify_bf2.py"))
        .arg("--rtptool").arg(env!("CARGO_BIN_EXE_rtptool"))
        .status().expect("run the OpenBF2 reader acceptance harness");
    assert!(status.success(), "BF2 acceptance failed; see scratch logs");

    // Exercise history selection against a real, independently compared chain.
    let scratch = std::env::var_os("BF2_RTP_SCRATCH").map(std::path::PathBuf::from)
        .unwrap_or_else(|| std::env::temp_dir().join("rtptool-bf2"));
    let run = std::fs::read_to_string(scratch.join("latest-run.txt")).unwrap();
    let run = std::path::Path::new(run.trim());
    let patch = rtptool::parse(std::fs::read(run.join("bf2.rtp")).unwrap()).unwrap();
    let rel = "admin/standard_admin/autobalance.py";
    let record = patch.records.iter().find(|r| r.filename.replace('\\', "/").eq_ignore_ascii_case(rel)).unwrap();
    assert_eq!(record.children.len(), 5);
    let disc = std::fs::read(run.join("disc").join(rel)).unwrap();
    let expected = std::fs::read(run.join("stage").join(rel)).unwrap();
    let mut intermediate = disc;
    for (index, step) in record.children.iter().enumerate() {
        let final_data = rtptool::apply_record(&patch, record, Some(&intermediate)).unwrap().unwrap();
        assert_eq!(final_data, expected, "real chain suffix starting at step {index}");
        intermediate = rtptool::apply_record(&patch, step, Some(&intermediate)).unwrap().unwrap();
    }
    assert_eq!(intermediate, expected);
    assert_eq!(rtptool::apply_record(&patch, record, Some(&expected)).unwrap().unwrap(), expected);
}
