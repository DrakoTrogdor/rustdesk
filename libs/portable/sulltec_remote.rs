//! SullTec names and version in the portable launcher's Windows version resource.
#![cfg(windows)]

const BRANDING: &str = include_str!("../../flutter/windows/runner/sulltec_branding.h");

pub fn stamp_version_resource(res: &mut winres::WindowsResource) {
    println!("cargo:rerun-if-env-changed=SULLTEC_CLIENT_VERSION");
    let product = branding("ST_PRODUCT_NAME");
    let company = branding("ST_COMPANY_NAME");
    let copyright = format!("Copyright © 2026 {company}. All rights reserved.");
    res.set("ProductName", product)
        .set("FileDescription", product)
        .set("OriginalFilename", "sulltecremote-portable.exe")
        .set("CompanyName", company)
        .set("LegalCopyright", &copyright);
    if let Ok(full) = std::env::var("SULLTEC_CLIENT_VERSION") {
        let full = full.trim();
        if !full.is_empty() {
            res.set("ProductVersion", full);
            res.set("FileVersion", full);
            if let Some(packed) = numeric_version(full) {
                res.set_version_info(winres::VersionInfo::PRODUCTVERSION, packed);
                res.set_version_info(winres::VersionInfo::FILEVERSION, packed);
            }
        }
    }
}

fn branding(name: &str) -> &'static str {
    BRANDING
        .lines()
        .find_map(|line| {
            line.trim()
                .strip_prefix("#define ")?
                .strip_prefix(name)?
                .strip_prefix(char::is_whitespace)?
                .trim()
                .strip_prefix('"')?
                .strip_suffix('"')
        })
        .unwrap_or_else(|| panic!("{name} is not defined in sulltec_branding.h"))
}

fn numeric_version(full: &str) -> Option<u64> {
    let (core, meta) = full.split_once('+').unwrap_or((full, ""));
    let mut core_parts = core.split('.');
    let major: u16 = core_parts.next()?.parse().ok()?;
    let minor: u16 = core_parts.next()?.parse().ok()?;
    let patch: u16 = core_parts.next()?.parse().ok()?;
    let build: u16 = meta.split('.').next().unwrap_or("0").parse().unwrap_or(0);
    Some(((major as u64) << 48) | ((minor as u64) << 32) | ((patch as u64) << 16) | build as u64)
}
