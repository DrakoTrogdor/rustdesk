fn main() {
    #[cfg(windows)]
    {
        use std::io::Write;
        // SullTec: stamp the portable launcher's Windows version resource with the SullTec
        // product version (full string SEMVER+BUILD.DATETIME.COMMIT) baked in by
        // Build-Release.ps1, so the outer sulltec-remote-portable.exe reports the same product
        // version as the inner client instead of winres' default (the packer crate's 1.4.x).
        println!("cargo:rerun-if-env-changed=SULLTEC_CLIENT_VERSION");
        let mut res = winres::WindowsResource::new();
        res.set_icon("../../res/icon.ico")
            .set_language(winapi::um::winnt::MAKELANGID(
                winapi::um::winnt::LANG_ENGLISH,
                winapi::um::winnt::SUBLANG_ENGLISH_US,
            ))
            .set_manifest_file("../../res/manifest.xml");
        if let Ok(full) = std::env::var("SULLTEC_CLIENT_VERSION") {
            let full = full.trim();
            if !full.is_empty() {
                // String fields (shown in Explorer -> Details) carry the full version verbatim.
                res.set("ProductVersion", full);
                res.set("FileVersion", full);
                // The numeric VS_FIXEDFILEINFO must be four u16s (a.b.c.d); derive it from the
                // SemVer core + BUILD counter: MAJOR.MINOR.PATCH.BUILD.
                if let Some(packed) = sulltec_numeric_version(full) {
                    res.set_version_info(winres::VersionInfo::PRODUCTVERSION, packed);
                    res.set_version_info(winres::VersionInfo::FILEVERSION, packed);
                }
            }
        }
        match res.compile() {
            Err(e) => {
                write!(std::io::stderr(), "{}", e).unwrap();
                std::process::exit(1);
            }
            Ok(_) => {}
        }
    }
}

/// Pack `MAJOR.MINOR.PATCH+BUILD.DATETIME.COMMIT` into a winres numeric version
/// (`MAJOR<<48 | MINOR<<32 | PATCH<<16 | BUILD`), each field clamped to u16. Returns None if
/// the SemVer core is malformed (then winres keeps its CARGO_PKG_VERSION default).
#[cfg(windows)]
fn sulltec_numeric_version(full: &str) -> Option<u64> {
    let (core, meta) = full.split_once('+').unwrap_or((full, ""));
    let mut core_parts = core.split('.');
    let major: u16 = core_parts.next()?.parse().ok()?;
    let minor: u16 = core_parts.next()?.parse().ok()?;
    let patch: u16 = core_parts.next()?.parse().ok()?;
    // meta = BUILD.DATETIME.COMMIT; BUILD is the leading segment, e.g. "001".
    let build: u16 = meta.split('.').next().unwrap_or("0").parse().unwrap_or(0);
    Some(((major as u64) << 48) | ((minor as u64) << 32) | ((patch as u64) << 16) | build as u64)
}
