#![cfg(windows)]

use hbb_common::log;
use std::{
    os::windows::{
        ffi::OsStrExt,
        fs::{MetadataExt, OpenOptionsExt},
        process::CommandExt,
    },
    path::{Path, PathBuf},
};
use windows::{
    core::{PCWSTR, PWSTR},
    Win32::{
        Foundation::{LocalFree, HLOCAL},
        Security::{
            AclSizeInformation,
            Authorization::{ConvertSidToStringSidW, GetNamedSecurityInfoW, SE_FILE_OBJECT},
            GetAce, GetAclInformation, GetSecurityDescriptorControl, ACCESS_ALLOWED_ACE,
            ACE_HEADER, ACL, ACL_SIZE_INFORMATION, DACL_SECURITY_INFORMATION,
            OWNER_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR, PSID, SE_DACL_PROTECTED,
        },
    },
};

const SYSTEM: &str = "S-1-5-18";
const ADMINISTRATORS: &str = "S-1-5-32-544";
const FILE_ATTRIBUTE_DIRECTORY: u32 = 0x10;
const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x400;
const FILE_READ_ATTRIBUTES: u32 = 0x80;
const FILE_SHARE_READ_WRITE: u32 = 0x3;
const FILE_FLAG_BACKUP_SEMANTICS: u32 = 0x0200_0000;
const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;
const ACCESS_ALLOWED_ACE_TYPE: u8 = 0;
const ACCESS_DENIED_ACE_TYPE: u8 = 1;
const OBJECT_AND_CONTAINER_INHERIT: u8 = 0x3;

struct Ace {
    kind: u8,
    flags: u8,
    sid: Option<String>,
}

struct Security {
    owner: Option<String>,
    protected: bool,
    dacl: Option<Vec<Ace>>,
}

fn trusted(sid: Option<&str>) -> bool {
    matches!(sid, Some(SYSTEM) | Some(ADMINISTRATORS))
}

pub(crate) fn ensure(name: &str) -> Result<PathBuf, String> {
    if !crate::platform::is_root() {
        return Err(format!("{name}: not running as SYSTEM"));
    }
    let base = std::env::var_os("ProgramData").ok_or("ProgramData is not set")?;
    let parent = PathBuf::from(base).join(hbb_common::config::APP_NAME.read().unwrap().clone());
    std::fs::create_dir_all(&parent).map_err(|e| format!("{}: {e}", parent.display()))?;
    let parent_meta = std::fs::symlink_metadata(&parent).map_err(|e| format!("{}: {e}", parent.display()))?;
    if parent_meta.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
        return Err(format!("{} is a link", parent.display()));
    }
    let parent_owner = read_security(&parent)?.owner;
    if !trusted(parent_owner.as_deref()) {
        return Err(format!(
            "{} is owned by {}, not SYSTEM or Administrators",
            parent.display(),
            parent_owner.unwrap_or_default()
        ));
    }

    let dir = parent.join(name);
    if let Ok(meta) = std::fs::symlink_metadata(&dir) {
        let attrs = meta.file_attributes();
        if attrs & FILE_ATTRIBUTE_REPARSE_POINT != 0 || attrs & FILE_ATTRIBUTE_DIRECTORY == 0 {
            let removed = match attrs & FILE_ATTRIBUTE_DIRECTORY != 0 {
                true => std::fs::remove_dir(&dir),
                false => std::fs::remove_file(&dir),
            };
            removed.map_err(|e| format!("{}: {e}", dir.display()))?;
        }
    }
    match std::fs::create_dir(&dir) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
        Err(e) => return Err(format!("{}: {e}", dir.display())),
    }

    let pin = std::fs::OpenOptions::new()
        .access_mode(FILE_READ_ATTRIBUTES)
        .share_mode(FILE_SHARE_READ_WRITE)
        .custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT)
        .open(&dir)
        .map_err(|e| format!("{}: {e}", dir.display()))?;
    let attrs = pin
        .metadata()
        .map_err(|e| format!("{}: {e}", dir.display()))?
        .file_attributes();
    if attrs & FILE_ATTRIBUTE_REPARSE_POINT != 0 || attrs & FILE_ATTRIBUTE_DIRECTORY == 0 {
        return Err(format!("{} is not a plain directory", dir.display()));
    }
    let found = read_security(&dir)?;
    if !locked(&found) {
        lock_down(&dir, &found);
        if !locked(&read_security(&dir)?) {
            return Err(format!("{}: could not restrict to SYSTEM and Administrators", dir.display()));
        }
        log::info!("{} restricted to SYSTEM and Administrators", dir.display());
    }
    drop(pin);
    Ok(dir)
}

pub(crate) fn is_admin_owned_file(path: &Path) -> bool {
    let Ok(meta) = std::fs::symlink_metadata(path) else {
        return false;
    };
    meta.is_file()
        && meta.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT == 0
        && read_security(path).is_ok_and(|s| trusted(s.owner.as_deref()))
}

fn locked(sec: &Security) -> bool {
    let Some(aces) = &sec.dacl else {
        return false;
    };
    trusted(sec.owner.as_deref())
        && sec.protected
        && aces.iter().all(|a| trusted(a.sid.as_deref()))
        && aces.iter().any(|a| {
            a.kind == ACCESS_ALLOWED_ACE_TYPE
                && a.flags & OBJECT_AND_CONTAINER_INHERIT == OBJECT_AND_CONTAINER_INHERIT
                && a.sid.as_deref() == Some(SYSTEM)
        })
}

fn lock_down(dir: &Path, found: &Security) {
    let target = dir.display().to_string();
    icacls(&[&target, "/setowner", "*S-1-5-18", "/Q"]);
    icacls(&[&target, "/inheritance:r", "/Q"]);
    let mut sids: Vec<&str> = found
        .dacl
        .iter()
        .flatten()
        .filter_map(|a| a.sid.as_deref())
        .collect();
    sids.sort_unstable();
    sids.dedup();
    for sid in sids {
        icacls(&[&target, "/remove", &format!("*{sid}"), "/Q"]);
    }
    icacls(&[&target, "/grant:r", "*S-1-5-18:(OI)(CI)F", "*S-1-5-32-544:(OI)(CI)F", "/Q"]);
}

fn icacls(args: &[&str]) {
    const CREATE_NO_WINDOW: u32 = 0x0800_0000;
    let exe = std::env::var("SystemRoot")
        .map(|r| format!("{r}\\System32\\icacls.exe"))
        .unwrap_or_else(|_| "icacls.exe".to_string());
    let _ = std::process::Command::new(exe)
        .args(args)
        .creation_flags(CREATE_NO_WINDOW)
        .stdin(std::process::Stdio::null())
        .output();
}

fn read_security(path: &Path) -> Result<Security, String> {
    let wide: Vec<u16> = path.as_os_str().encode_wide().chain(Some(0)).collect();
    let mut owner = PSID::default();
    let mut dacl: *mut ACL = std::ptr::null_mut();
    let mut sd = PSECURITY_DESCRIPTOR::default();
    let rc = unsafe {
        GetNamedSecurityInfoW(
            PCWSTR::from_raw(wide.as_ptr()),
            SE_FILE_OBJECT,
            OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
            Some(&mut owner),
            None,
            Some(&mut dacl),
            None,
            &mut sd,
        )
    };
    if rc.0 != 0 {
        return Err(format!("{}: reading its security failed (win32 error {})", path.display(), rc.0));
    }
    let mut control: u16 = 0;
    let mut revision: u32 = 0;
    let protected = unsafe { GetSecurityDescriptorControl(sd, &mut control, &mut revision) }.is_ok()
        && control & SE_DACL_PROTECTED.0 != 0;
    let security = Security {
        owner: sid_string(owner),
        protected,
        dacl: (!dacl.is_null()).then(|| read_aces(dacl)),
    };
    unsafe {
        let _ = LocalFree(Some(HLOCAL(sd.0)));
    }
    Ok(security)
}

fn read_aces(dacl: *mut ACL) -> Vec<Ace> {
    let unreadable = || Ace { kind: u8::MAX, flags: 0, sid: None };
    let mut info = ACL_SIZE_INFORMATION::default();
    let read = unsafe {
        GetAclInformation(
            dacl,
            &mut info as *mut _ as *mut std::ffi::c_void,
            std::mem::size_of::<ACL_SIZE_INFORMATION>() as u32,
            AclSizeInformation,
        )
    };
    if read.is_err() {
        return vec![unreadable()];
    }
    let mut aces = Vec::with_capacity(info.AceCount as usize);
    for index in 0..info.AceCount {
        let mut ace: *mut std::ffi::c_void = std::ptr::null_mut();
        if unsafe { GetAce(dacl, index, &mut ace) }.is_err() || ace.is_null() {
            aces.push(unreadable());
            continue;
        }
        let header = unsafe { &*(ace as *const ACE_HEADER) };
        let sid = match header.AceType {
            ACCESS_ALLOWED_ACE_TYPE | ACCESS_DENIED_ACE_TYPE => {
                let body = unsafe { &*(ace as *const ACCESS_ALLOWED_ACE) };
                sid_string(PSID((&body.SidStart as *const u32) as *mut std::ffi::c_void))
            }
            _ => None,
        };
        aces.push(Ace { kind: header.AceType, flags: header.AceFlags, sid });
    }
    aces
}

fn sid_string(sid: PSID) -> Option<String> {
    if sid.0.is_null() {
        return None;
    }
    let mut text = PWSTR::null();
    unsafe { ConvertSidToStringSidW(sid, &mut text) }.ok()?;
    if text.is_null() {
        return None;
    }
    let value = unsafe { text.to_string() }.ok();
    unsafe {
        let _ = LocalFree(Some(HLOCAL(text.0 as *mut std::ffi::c_void)));
    }
    value
}
