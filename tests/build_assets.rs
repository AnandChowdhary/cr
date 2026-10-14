//! Guard the build's integrity boundary and its network-free override.

#[path = "../build/assets.rs"]
mod assets;

use std::{fs, path::Path};

use assets::{HTMX_ASSETS, HTMX_VERSION, prepare};

const SCRIPT: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/third-party/htmx-4.0.0.min.js"));
const LICENSE: &[u8] = include_bytes!(concat!(
    env!("OUT_DIR"),
    "/third-party/htmx-4.0.0.LICENSE.txt"
));

fn fixture(directory: &Path) {
    for (asset, bytes) in HTMX_ASSETS.into_iter().zip([SCRIPT, LICENSE]) {
        fs::write(directory.join(asset.filename), bytes).unwrap();
    }
}

#[test]
fn offline_assets_are_verified_and_copied_verbatim() {
    let source = tempfile::tempdir().unwrap();
    let output = tempfile::tempdir().unwrap();
    fixture(source.path());
    for asset in HTMX_ASSETS {
        assert!(asset.filename.contains(HTMX_VERSION));
        prepare(asset, output.path(), Some(source.path())).unwrap();
        assert_eq!(
            fs::read(output.path().join(asset.filename)).unwrap(),
            fs::read(source.path().join(asset.filename)).unwrap()
        );
    }
    // A later build reuses verified files, even with the network unavailable.
    for asset in HTMX_ASSETS {
        let unavailable = assets::Asset {
            url: "https://127.0.0.1:1/unavailable",
            ..asset
        };
        prepare(unavailable, output.path(), None).unwrap();
    }
}

#[test]
fn an_explicit_offline_directory_cannot_fall_back_to_cache_or_network() {
    let source = tempfile::tempdir().unwrap();
    let output = tempfile::tempdir().unwrap();
    fixture(output.path());
    for asset in HTMX_ASSETS {
        // Missing files fail even when a valid cached copy exists.
        assert!(prepare(asset, output.path(), Some(source.path())).is_err());
        fs::write(source.path().join(asset.filename), b"tampered").unwrap();
        let error = prepare(asset, output.path(), Some(source.path())).unwrap_err();
        assert!(error.to_string().contains("refusing to embed"));
    }
    // Neither a missing script nor a corrupt license can replace good output.
    assert_eq!(
        fs::read(output.path().join(HTMX_ASSETS[0].filename)).unwrap(),
        SCRIPT
    );
    assert_eq!(
        fs::read(output.path().join(HTMX_ASSETS[1].filename)).unwrap(),
        LICENSE
    );
}

#[test]
fn a_corrupt_build_cache_is_rejected() {
    let output = tempfile::tempdir().unwrap();
    for asset in HTMX_ASSETS {
        fs::write(output.path().join(asset.filename), b"tampered").unwrap();
        let error = prepare(asset, output.path(), None).unwrap_err();
        assert!(error.to_string().contains("refusing to embed"));
    }
}
