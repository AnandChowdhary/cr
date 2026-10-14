//! Build-time third-party assets. Pins stay in Git; upstream bytes do not.

use std::{fs, path::Path, time::Duration};

use anyhow::{Context, Result, bail};
use sha2::{Digest, Sha256};

pub const HTMX_VERSION: &str = "4.0.0";

#[derive(Clone, Copy, Debug)]
pub struct Asset {
    pub filename: &'static str,
    pub url: &'static str,
    pub sha256: &'static str,
}

// These match dist/htmx.min.js and LICENSE in htmx.org's published npm package.
// An upstream replacement must fail verification, even at the same version URL.
pub const HTMX_ASSETS: [Asset; 2] = [
    Asset {
        filename: "htmx-4.0.0.min.js",
        url: "https://unpkg.com/htmx.org@4.0.0/dist/htmx.min.js",
        sha256: "e484d9171a9db30a39c8f16e3d709d4137f3211c659f8e6125816635033d593f",
    },
    Asset {
        filename: "htmx-4.0.0.LICENSE.txt",
        url: "https://unpkg.com/htmx.org@4.0.0/LICENSE",
        sha256: "d3d2456f76414f2456104660ebd65aff1c04cd7966b942bdabd63f3cdb316a38",
    },
];

/// Use an explicit offline directory, a verified build cache, or HTTPS, in that
/// order. An explicit directory is authoritative: a missing or corrupt file
/// fails the build instead of silently falling back to the network or cache.
pub fn prepare(asset: Asset, output: &Path, source: Option<&Path>) -> Result<()> {
    let destination = output.join(asset.filename);
    let bytes = if let Some(source) = source {
        let path = source.join(asset.filename);
        fs::read(&path).with_context(|| format!("reading asset from {}", path.display()))?
    } else if destination.try_exists()? {
        fs::read(&destination)?
    } else {
        download(asset).context(
            "fetching build assets; for offline builds, set CR_ASSET_DIR to a directory containing the pinned htmx script and license (see docs/installation.md)",
        )?
    };

    let actual: String = Sha256::digest(&bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    if actual != asset.sha256 {
        bail!(
            "{} has SHA-256 {actual}, expected {}; refusing to embed an unverified asset",
            asset.filename,
            asset.sha256
        );
    }

    // Never leave a partial file in the cache after an interrupted build. Do
    // not rewrite identical bytes: Cargo watches the cached files for changes.
    if fs::read(&destination).ok().as_deref() != Some(bytes.as_slice()) {
        fs::create_dir_all(output)?;
        let temporary = destination.with_extension("download");
        fs::write(&temporary, bytes)?;
        fs::rename(temporary, destination)?;
    }
    Ok(())
}

fn download(asset: Asset) -> Result<Vec<u8>> {
    let agent: ureq::Agent = ureq::Agent::config_builder()
        .timeout_global(Some(Duration::from_secs(30)))
        .https_only(true)
        .build()
        .into();
    agent
        .get(asset.url)
        .call()
        .with_context(|| format!("downloading {}", asset.url))?
        .body_mut()
        .with_config()
        .limit(1024 * 1024)
        .read_to_vec()
        .with_context(|| format!("reading {}", asset.url))
}
