//! Re-attaching to a job's process after the client that started it stopped.
//!
//! A hosted command runs in a child process with no job object, so a client that is replaced or
//! killed mid-run leaves that process running. The pair (PID, creation time) recorded at spawn is
//! what identifies it afterwards: Windows reuses PIDs freely, and a reused PID would let this device
//! report a stranger's exit code as the job's.

use super::*;

/// A process this device re-attached to, held open for as long as it takes to read its exit code.
///
/// ⚠ The handle is the whole point. Once the process exits and the last handle on it closes, the
/// kernel discards the exit code and nothing can read it again.
///
/// `isize` rather than `HANDLE`, which is a raw pointer and so not `Send`; this set is reached from
/// whichever task services a poll.
#[cfg(windows)]
struct Adopted {
    job_id: String,
    handle: isize,
    /// The code, once read. Kept because reporting it can fail: `post_result` leaves a row
    /// unreported on a transport error so it stays recoverable, and re-reading the code from the
    /// kernel afterwards is only possible while this entry — and its handle — still exist.
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

/// Processes re-attached in this client. `Vec` for the same reason [`JOBS_IN_FLIGHT`] is one:
/// `HashMap::new()` is not const and once_cell is absent from the Windows build.
#[cfg(windows)]
static ADOPTED: std::sync::Mutex<Vec<Adopted>> = std::sync::Mutex::new(Vec::new());

/// Ceiling on the re-attached set. The console only asks about runs it is still waiting on, so this
/// is not reached in normal operation; it is what stops a console that keeps naming ids this device
/// can open from accumulating handles for the life of the process.
#[cfg(windows)]
const ADOPTED_MAX: usize = 32;

/// Whether a re-attached process is still running here.
///
/// An entry that has already been read counts as finished: the process is gone and only its code is
/// being held for delivery.
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

/// What this device can say about a job whose run it is not executing.
///
/// Uncfg'd so the match in `settle_started` compiles on both targets; off Windows only `None` is
/// ever constructed, which is what the allow is for.
#[allow(dead_code)]
pub(super) enum ChildVerdict {
    /// Re-attached and still running. Say nothing; the console keeps waiting, which is correct.
    Running,
    /// Re-attached and now finished. A raw process exit code, which is not a result.
    Exited(u32),
    /// Nothing to re-attach to.
    None,
}

/// The process creation time of `pid`, as a raw FILETIME tick count.
///
/// Paired with the PID this names one process for the life of the machine: Windows reuses PIDs, but
/// cannot reuse one at the same hundred-nanosecond tick.
#[cfg(windows)]
fn creation_token(pid: u32) -> Option<u64> {
    use windows::Win32::Foundation::{CloseHandle, FILETIME};
    use windows::Win32::System::Threading::{GetProcessTimes, OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION};
    unsafe {
        let h = match OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid) {
            Ok(h) => h,
            Err(_) => return None,
        };
        let mut created = FILETIME::default();
        let mut exited = FILETIME::default();
        let mut kernel = FILETIME::default();
        let mut user = FILETIME::default();
        let got = GetProcessTimes(h, &mut created, &mut exited, &mut kernel, &mut user).is_ok();
        let _ = CloseHandle(h);
        match got {
            true => Some(((created.dwHighDateTime as u64) << 32) | created.dwLowDateTime as u64),
            false => None,
        }
    }
}

/// Record the process now running `job_id`, so a later client can find it again.
#[cfg(windows)]
pub(super) fn record(job_id: &str, pid: u32) {
    if job_id.is_empty() {
        return;
    }
    let Some(created) = creation_token(pid) else {
        return;
    };
    mark_job_child(job_id, pid, created);
}

#[cfg(not(windows))]
pub(super) fn record(_job_id: &str, _pid: u32) {}

/// Re-attach to `job_id`'s recorded process if it is still the one that was started, and say where
/// that run stands.
#[cfg(windows)]
pub(super) fn settle_child(job_id: &str) -> ChildVerdict {
    use windows::Win32::Foundation::{CloseHandle, HANDLE, WAIT_OBJECT_0, WAIT_TIMEOUT};
    use windows::Win32::System::Threading::{
        GetExitCodeProcess, OpenProcess, WaitForSingleObject, PROCESS_QUERY_LIMITED_INFORMATION, PROCESS_SYNCHRONIZE,
    };
    let mut held = ADOPTED.lock().unwrap_or_else(|e| e.into_inner());
    let already = held.iter().position(|a| a.job_id == job_id);
    // Already read once. Answer from the record rather than the kernel: the previous answer may not
    // have reached the console, and asking twice is what a retry is.
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
                    // Gone, and its exit code went with the last handle on it.
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
    // Anything that is neither still-waiting nor a clean signal is not something to report a code
    // for; the caller falls through to the abandoned answer.
    if !(waited == WAIT_OBJECT_0 && read) {
        if let Some(i) = held.iter().position(|a| a.job_id == job_id) {
            held.remove(i);
        }
        return ChildVerdict::None;
    }
    // The entry STAYS, holding both the code and the handle it came from, until the cap retires it.
    // Dropping it here would close the handle and let the kernel discard the code, which a failed
    // post would then have no way to ask for again.
    if let Some(i) = held.iter().position(|a| a.job_id == job_id) {
        held[i].exited = Some(code);
    }
    ChildVerdict::Exited(code)
}

#[cfg(not(windows))]
pub(super) fn settle_child(_job_id: &str) -> ChildVerdict {
    ChildVerdict::None
}
