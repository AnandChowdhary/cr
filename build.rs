#[path = "build/assets.rs"]
mod assets;

fn main() -> anyhow::Result<()> {
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed=build/assets.rs");
    println!("cargo:rerun-if-env-changed=CR_ASSET_DIR");

    let output = std::path::PathBuf::from(std::env::var_os("OUT_DIR").unwrap());
    let source = std::env::var_os("CR_ASSET_DIR").map(std::path::PathBuf::from);
    let directory = output.join("third-party");
    for asset in assets::HTMX_ASSETS {
        let input = source.as_deref().unwrap_or(&directory).join(asset.filename);
        println!("cargo:rerun-if-changed={}", input.display());
        assets::prepare(asset, &directory, source.as_deref())?;
    }
    println!("cargo:rustc-env=CR_HTMX_VERSION={}", assets::HTMX_VERSION);
    Ok(())
}
