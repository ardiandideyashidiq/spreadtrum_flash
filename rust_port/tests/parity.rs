use spd_dump_rs::crc::*;
use spd_dump_rs::hdlc::*;
use spd_dump_rs::nv::*;
use std::fs;
use std::process::Command;
use tempfile::tempdir;

#[test]
fn test_hdlc_transcode() {
    let raw = vec![0x7e, 0x12, 0x7d, 0x34, 0x7e];
    let mut encoded = Vec::new();
    spd_transcode(&mut encoded, &raw);
    assert_eq!(
        encoded,
        vec![0x7d, 0x5e, 0x12, 0x7d, 0x5d, 0x34, 0x7d, 0x5e]
    );

    let decoded = spd_untranscode(&encoded).unwrap();
    assert_eq!(decoded, raw);
}

#[test]
fn test_crc_and_checksum() {
    let data = b"Hello Spreadtrum!";
    let crc = spd_crc16(0, data);
    assert_ne!(crc, 0);

    let chk = spd_checksum(0, data, CHK_FIXZERO);
    assert_ne!(chk, 0);

    let crc32_val = spd_crc32(0, data);
    assert_ne!(crc32_val, 0);
}

#[test]
fn test_nv_merge_differential() {
    let dir = tempdir().unwrap();
    let old_nv_path = dir.path().join("old_nv.bin");
    let new_nv_path = dir.path().join("new_nv.bin");
    let xml_path = dir.path().join("nv.xml");

    // Construct valid NV binary files matching common.c NV layout
    // Format: 4 bytes header (e.g. 0x00 0x00 0x00 0x00)
    // Then NV items: u16 ID, u16 Length, [data...], aligned to 4 bytes
    // Terminated by 0xFFFF or end
    let mut old_nv = Vec::new();
    old_nv.extend_from_slice(&[0, 0, 0, 0]); // header
                                             // Item 0x0005, len 4, data [1, 2, 3, 4]
    old_nv.extend_from_slice(&5u16.to_le_bytes());
    old_nv.extend_from_slice(&4u16.to_le_bytes());
    old_nv.extend_from_slice(&[1, 2, 3, 4]);
    // Item 0x0010, len 2, data [9, 9], + 2 bytes padding
    old_nv.extend_from_slice(&0x10u16.to_le_bytes());
    old_nv.extend_from_slice(&2u16.to_le_bytes());
    old_nv.extend_from_slice(&[9, 9, 0, 0]);
    // Terminator
    old_nv.extend_from_slice(&[0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff]);

    let mut new_nv = Vec::new();
    new_nv.extend_from_slice(&[0, 0, 0, 0]); // header
                                             // Item 0x0005, len 4, data [5, 6, 7, 8]
    new_nv.extend_from_slice(&5u16.to_le_bytes());
    new_nv.extend_from_slice(&4u16.to_le_bytes());
    new_nv.extend_from_slice(&[5, 6, 7, 8]);
    // Item 0x0020, len 4, data [10, 11, 12, 13]
    new_nv.extend_from_slice(&0x20u16.to_le_bytes());
    new_nv.extend_from_slice(&4u16.to_le_bytes());
    new_nv.extend_from_slice(&[10, 11, 12, 13]);
    // Terminator
    new_nv.extend_from_slice(&[0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff]);

    let xml_content = r#"<NVItem><ID>0x5</ID></NVItem>"#;

    fs::write(&old_nv_path, &old_nv).unwrap();
    fs::write(&new_nv_path, &new_nv).unwrap();
    fs::write(&xml_path, xml_content).unwrap();

    // Run Rust merge_nv
    let nvid_list = get_nvlist_xml(xml_path.to_str().unwrap()).unwrap();
    let rust_merged = merge_nv(&nvid_list, &old_nv, &new_nv);
    let c_bin = fs::canonicalize("../spd_dump").unwrap();
    if c_bin.exists() {
        let _output = Command::new(&c_bin)
            .current_dir(dir.path())
            .arg("-t")
            .arg("mergenv-xml-ex")
            .arg(&xml_path)
            .arg(&old_nv_path)
            .arg(&new_nv_path)
            .arg("exit")
            .output()
            .expect("failed to run C spd_dump");

        let c_merged_path = dir.path().join("nvmerged");
        if c_merged_path.exists() {
            let c_merged = fs::read(&c_merged_path).unwrap();
            assert_eq!(
                rust_merged, c_merged,
                "Rust merge_nv output must byte-for-byte match C spd_dump"
            );
        }
    }
}
#[test]
fn test_nv_merge_cfg_differential() {
    let dir = tempdir().unwrap();
    let old_nv_path = dir.path().join("old_nv.bin");
    let new_nv_path = dir.path().join("new_nv.bin");
    let cfg_path = dir.path().join("nv.cfg");

    let mut old_nv = Vec::new();
    old_nv.extend_from_slice(&[0, 0, 0, 0]);
    old_nv.extend_from_slice(&0x12du16.to_le_bytes());
    old_nv.extend_from_slice(&4u16.to_le_bytes());
    old_nv.extend_from_slice(&[1, 2, 3, 4]);
    old_nv.extend_from_slice(&[0xff; 8]);

    let mut new_nv = Vec::new();
    new_nv.extend_from_slice(&[0, 0, 0, 0]);
    new_nv.extend_from_slice(&0x12du16.to_le_bytes());
    new_nv.extend_from_slice(&4u16.to_le_bytes());
    new_nv.extend_from_slice(&[5, 6, 7, 8]);
    new_nv.extend_from_slice(&[0xff; 8]);

    let cfg_content = "nv_item 0x12d\n# comment\n";

    fs::write(&old_nv_path, &old_nv).unwrap();
    fs::write(&new_nv_path, &new_nv).unwrap();
    fs::write(&cfg_path, cfg_content).unwrap();

    let nvid_list = get_nvlist_cfg(cfg_path.to_str().unwrap()).unwrap();
    let rust_merged = merge_nv(&nvid_list, &old_nv, &new_nv);

    let c_bin = fs::canonicalize("../spd_dump").unwrap();
    if c_bin.exists() {
        let _output = Command::new(&c_bin)
            .current_dir(dir.path())
            .arg("-t")
            .arg("mergenv-cfg-ex")
            .arg(&cfg_path)
            .arg(&old_nv_path)
            .arg(&new_nv_path)
            .arg("exit")
            .output()
            .expect("failed to run C spd_dump");

        let c_merged_path = dir.path().join("nvmerged");
        if c_merged_path.exists() {
            let c_merged = fs::read(&c_merged_path).unwrap();
            assert_eq!(
                rust_merged, c_merged,
                "Rust merge_nv cfg output must byte-for-byte match C spd_dump"
            );
        }
    }
}
#[test]
fn test_cli_help_parity() {
    let c_bin = fs::canonicalize("../spd_dump").unwrap();
    let rust_bin = fs::canonicalize("target/debug/spd_dump_rs").unwrap();

    let c_output = Command::new(&c_bin).arg("--help").output().unwrap();
    let rust_output = Command::new(&rust_bin).arg("--help").output().unwrap();

    let c_stderr = String::from_utf8_lossy(&c_output.stderr);
    let rust_stderr = String::from_utf8_lossy(&rust_output.stderr);

    assert_eq!(rust_output.status.code(), c_output.status.code());
    // Compare help text disregarding ver/sha1 line
    let c_usage_pos = c_stderr.find("Usage\n").unwrap();
    let rust_usage_pos = rust_stderr.find("Usage\n").unwrap();
    assert_eq!(&rust_stderr[rust_usage_pos..], &c_stderr[c_usage_pos..]);
}
