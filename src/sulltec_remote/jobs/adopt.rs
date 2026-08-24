//! Holding on to a job's process once nothing is waiting on it — because the client that started it
//! stopped, or because the bound it was given elapsed and this device stopped waiting.

use super::*;

/// ⚠ Once a process exits and its last handle closes, the kernel discards the exit code. Holding
/// this handle is the only way to read it afterwards.
#[cfg(windows)]
struct Adopted {
    job_id: String,
    handle: isize,
    exited: Option<u32>,
}

#[cfg(windows)]
impl Drop for Adopted {
    fn drop(&mut self) {
        use windows::Win32::Foundation::{CloseHandle, HANDLE};
        unsafe {
            let _ = CloseHandle(HANDLE(self.handle as *mut core::ffi::c_void));
        }
    }
}

#[cfg(windows)]
static ADOPTED: std::sync::Mutex<Vec<Adopted>> = std::sync::Mutex::new(Vec::new());

#[cfg(windows)]
const ADOPTED_MAX: usize = 32;

#[cfg(windows)]
pub(super) fn any_adopted() -> bool {
    ADOPTED
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .iter()
        .any(|a| a.exited.is_none())
}

#[cfg(not(windows))]
pub(super) fn any_adopted() -> bool {
    false
}

#[allow(dead_code)]
pub(super) enum ChildVerdict {
    Running,
    Exited(u32),
    None,
}

/// A caller that must not race reads the token off the handle it already holds: a second
/// `OpenProcess` leaves a window between the check and the act, and a kernel handle pins the process
/// object so once one is open the identity cannot change underneath it.
#[cfg(windows)]
fn created_on(h: windows::Win32::Foundation::HANDLE) -> Option<u64> {
    use windows::Win32::Foundation::FILETIME;
    use windows::Win32::System::Threading::GetProcessTimes;
    let mut created = FILETIME::default();
    let mut exited = FILETIME::default();
    let mut kernel = FILETIME::default();
    let mut user = FILETIME::default();
    let got = unsafe { GetProcessTimes(h, &mut created, &mut exited, &mut kernel, &mut user) }.is_ok();
    match got {
        true => Some(((created.dwHighDateTime as u64) << 32) | created.dwLowDateTime as u64),
        false => None,
    }
}

/// Raw FILETIME ticks. With the PID this names one process for the life of the machine — a PID is
/// reused, but never at the same hundred-nanosecond tick.
#[cfg(windows)]
fn creation_token(pid: u32) -> Option<u64> {
    use windows::Win32::Foundation::CloseHandle;
    use windows::Win32::System::Threading::{OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION};
    unsafe {
        let h = match OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid) {
            Ok(h) => h,
            Err(_) => return None,
        };
        let got = created_on(h);
        let _ = CloseHandle(h);
        got
    }
}

/// ⚠ Deliberately not [`settle_child`]: that one pushes into [`ADOPTED`] and evicts the oldest entry
/// when the cap is reached, closing the handle a real adoption is holding an exit code in.
///
/// The WAIT is what makes it an answer rather than a guess. A process that has exited stays openable
/// by pid for as long as anything holds a handle on it — this file holds exactly such handles — so
/// `OpenProcess` succeeding is not the same fact as the process running.
#[cfg(windows)]
pub(super) fn alive(pid: u32, created: u64) -> bool {
    use windows::Win32::Foundation::{CloseHandle, WAIT_TIMEOUT};
    use windows::Win32::System::Threading::{
        OpenProcess, WaitForSingleObject, PROCESS_QUERY_LIMITED_INFORMATION, PROCESS_SYNCHRONIZE,
    };
    unsafe {
        let Ok(h) = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_SYNCHRONIZE, false, pid) else {
            return false;
        };
        let live = created_on(h) == Some(created) && WaitForSingleObject(h, 0) == WAIT_TIMEOUT;
        let _ = CloseHandle(h);
        live
    }
}

#[cfg(not(windows))]
pub(super) fn alive(_pid: u32, _created: u64) -> bool {
    false
}

#[cfg(windows)]
pub(super) fn unix_of_token(created: u64) -> i64 {
    (created / 10_000_000) as i64 - 11_644_473_600
}

#[allow(dead_code)]
pub(super) enum KillVerdict {
    Terminated,
    Reused,
    Gone,
    Refused,
}

/// ⚠ A FRESH handle, never the one [`ADOPTED`] holds: that one is opened without
/// `PROCESS_TERMINATE`, and no duplicate of a handle can carry access its source lacks — a kill
/// reaching for the held handle would be refused and would report a live process as one this device
/// may not touch.
///
/// ⚠ ONE PROCESS. `TerminateProcess` does not reach descendants and runs no `finally` block, so a
/// script's own children keep going and a wrapper that was going to write a completion marker never
/// writes one.
#[cfg(windows)]
pub(super) fn terminate(pid: u32, created: u64) -> KillVerdict {
    use windows::Win32::Foundation::{CloseHandle, WAIT_TIMEOUT};
    use windows::Win32::System::Threading::{
        OpenProcess, TerminateProcess, WaitForSingleObject, PROCESS_QUERY_LIMITED_INFORMATION, PROCESS_SYNCHRONIZE,
        PROCESS_TERMINATE,
    };
    unsafe {
        let Ok(h) = OpenProcess(
            PROCESS_TERMINATE | PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_SYNCHRONIZE,
            false,
            pid,
        ) else {
            return KillVerdict::Gone;
        };
        let verdict = if created_on(h) != Some(created) {
            KillVerdict::Reused
        } else if WaitForSingleObject(h, 0) != WAIT_TIMEOUT {
            KillVerdict::Gone
        } else if TerminateProcess(h, 1).is_ok() {
            KillVerdict::Terminated
        } else {
            KillVerdict::Refused
        };
        let _ = CloseHandle(h);
        verdict
    }
}

#[cfg(not(windows))]
pub(super) fn terminate(_pid: u32, _created: u64) -> KillVerdict {
    KillVerdict::Refused
}

#[cfg(windows)]
pub(super) fn hold(job_id: &str) -> bool {
    use windows::Win32::Foundation::CloseHandle;
    use windows::Win32::System::Threading::{OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION, PROCESS_SYNCHRONIZE};
    let Some((pid, created)) = seen_child(job_id) else {
        return false;
    };
    let mut held = ADOPTED.lock().unwrap_or_else(|e| e.into_inner());
    if held.iter().any(|a| a.job_id == job_id) {
        return true;
    }
    unsafe {
        let Ok(h) = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_SYNCHRONIZE, false, pid) else {
            return false;
        };
        if created_on(h) != Some(created) {
            let _ = CloseHandle(h);
            return false;
        }
        if held.len() >= ADOPTED_MAX {
            held.remove(0);
        }
        held.push(Adopted { job_id: job_id.to_owned(), handle: h.0 as isize, exited: None });
    }
    true
}

#[cfg(not(windows))]
pub(super) fn hold(_job_id: &str) -> bool {
    false
}

#[cfg(windows)]
pub(super) fn record_run(job_id: &str, pid: u32, dir: Option<&std::path::Path>) -> bool {
    if job_id.is_empty() {
        return false;
    }
    let created = creation_token(pid);
    let dir = dir.map(|d| d.display().to_string());
    if created.is_none() && dir.is_none() {
        return false;
    }
    mark_job_child(job_id, created.map(|_| pid), created, dir.as_deref());
    created.is_some()
}

#[cfg(not(windows))]
pub(super) fn record_run(_job_id: &str, _pid: u32, _dir: Option<&std::path::Path>) -> bool {
    false
}

#[cfg(windows)]
pub(super) fn record(job_id: &str, pid: u32) -> bool {
    record_run(job_id, pid, None)
}

#[cfg(not(windows))]
pub(super) fn record(_job_id: &str, _pid: u32) -> bool {
    false
}

#[cfg(windows)]
pub(super) fn record_dir(job_id: &str, dir: &std::path::Path) {
    if job_id.is_empty() {
        return;
    }
    mark_job_child(job_id, None, None, Some(&dir.display().to_string()));
}

#[cfg(not(windows))]
pub(super) fn record_dir(_job_id: &str, _dir: &std::path::Path) {}

#[cfg(windows)]
pub(super) fn settle_child(job_id: &str) -> ChildVerdict {
    use windows::Win32::Foundation::{CloseHandle, HANDLE, WAIT_OBJECT_0, WAIT_TIMEOUT};
    use windows::Win32::System::Threading::{
        GetExitCodeProcess, OpenProcess, WaitForSingleObject, PROCESS_QUERY_LIMITED_INFORMATION, PROCESS_SYNCHRONIZE,
    };
    let mut held = ADOPTED.lock().unwrap_or_else(|e| e.into_inner());
    let already = held.iter().position(|a| a.job_id == job_id);
    if let Some(code) = already.and_then(|i| held[i].exited) {
        return ChildVerdict::Exited(code);
    }
    let raw = match already {
        Some(i) => held[i].handle,
        None => {
            let Some((pid, created)) = seen_child(job_id) else {
                return ChildVerdict::None;
            };
            let h = unsafe {
                match OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_SYNCHRONIZE, false, pid) {
                    Ok(h) => h,
                    Err(_) => return ChildVerdict::None,
                }
            };
            if creation_token(pid) != Some(created) {
                unsafe {
                    let _ = CloseHandle(h);
                }
                return ChildVerdict::None;
            }
            if held.len() >= ADOPTED_MAX {
                held.remove(0);
            }
            hbb_common::log::warn!(
                "console job {job_id}: the client restarted while it was running. Re-attached to the \
                 process it had launched (pid {pid})."
            );
            let raw = h.0 as isize;
            held.push(Adopted { job_id: job_id.to_owned(), handle: raw, exited: None });
            raw
        }
    };
    let h = HANDLE(raw as *mut core::ffi::c_void);
    let waited = unsafe { WaitForSingleObject(h, 0) };
    if waited == WAIT_TIMEOUT {
        return ChildVerdict::Running;
    }
    let mut code: u32 = 0;
    let read = unsafe { GetExitCodeProcess(h, &mut code) }.is_ok();
    if !(waited == WAIT_OBJECT_0 && read) {
        if let Some(i) = held.iter().position(|a| a.job_id == job_id) {
            held.remove(i);
        }
        return ChildVerdict::None;
    }
    if let Some(i) = held.iter().position(|a| a.job_id == job_id) {
        held[i].exited = Some(code);
    }
    ChildVerdict::Exited(code)
}

#[cfg(not(windows))]
pub(super) fn settle_child(_job_id: &str) -> ChildVerdict {
    ChildVerdict::None
}
