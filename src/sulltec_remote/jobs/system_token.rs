use std::ffi::{OsStr, OsString};
use std::fs::File;
use std::os::windows::ffi::OsStrExt;
use std::os::windows::io::AsRawHandle;
use std::process::{Child, ExitStatus, Stdio};
use windows::core::{PCWSTR, PWSTR};
use windows::Win32::Foundation::{
    CloseHandle, SetHandleInformation, HANDLE, HANDLE_FLAGS, HANDLE_FLAG_INHERIT, WAIT_OBJECT_0, WAIT_TIMEOUT,
};
use windows::Win32::Security::{
    DuplicateTokenEx, GetTokenInformation, IsWellKnownSid, SecurityImpersonation, SetTokenInformation, TokenPrimary,
    TokenSessionId, TokenUser, WinLocalSystemSid, TOKEN_ADJUST_SESSIONID, TOKEN_ASSIGN_PRIMARY, TOKEN_DUPLICATE,
    TOKEN_QUERY, TOKEN_USER,
};
use windows::Win32::System::Services::{
    CloseServiceHandle, OpenSCManagerW, OpenServiceW, QueryServiceStatusEx, SC_MANAGER_CONNECT,
    SC_STATUS_PROCESS_INFO, SERVICE_QUERY_STATUS, SERVICE_STATUS_PROCESS,
};
use windows::Win32::System::Threading::{
    CreateProcessAsUserW, DeleteProcThreadAttributeList, GetCurrentProcess, GetExitCodeProcess,
    InitializeProcThreadAttributeList, OpenProcess, OpenProcessToken, UpdateProcThreadAttribute, WaitForSingleObject,
    CREATE_NO_WINDOW, CREATE_UNICODE_ENVIRONMENT, EXTENDED_STARTUPINFO_PRESENT, LPPROC_THREAD_ATTRIBUTE_LIST,
    PROCESS_INFORMATION, PROCESS_QUERY_LIMITED_INFORMATION, PROC_THREAD_ATTRIBUTE_HANDLE_LIST, STARTF_USESTDHANDLES,
    STARTUPINFOEXW,
};

pub(super) struct TokenChild {
    process: HANDLE,
    pid: u32,
}

impl Drop for TokenChild {
    fn drop(&mut self) {
        unsafe {
            let _ = CloseHandle(self.process);
        }
    }
}

pub(super) enum SystemChild {
    Std(Child),
    Token(TokenChild),
}

impl SystemChild {
    pub(super) fn id(&self) -> u32 {
        match self {
            Self::Std(child) => child.id(),
            Self::Token(child) => child.pid,
        }
    }

    pub(super) fn try_wait(&mut self) -> std::io::Result<Option<ExitStatus>> {
        use std::os::windows::process::ExitStatusExt;
        match self {
            Self::Std(child) => child.try_wait(),
            Self::Token(child) => unsafe {
                match WaitForSingleObject(child.process, 0) {
                    WAIT_OBJECT_0 => {
                        let mut code: u32 = 0;
                        match GetExitCodeProcess(child.process, &mut code) {
                            Ok(()) => Ok(Some(ExitStatus::from_raw(code))),
                            Err(_) => Err(std::io::Error::last_os_error()),
                        }
                    }
                    WAIT_TIMEOUT => Ok(None),
                    _ => Err(std::io::Error::last_os_error()),
                }
            },
        }
    }
}

struct Owned(HANDLE);

impl Drop for Owned {
    fn drop(&mut self) {
        if !self.0.is_invalid() {
            unsafe {
                let _ = CloseHandle(self.0);
            }
        }
    }
}

fn failed(step: &str, e: windows::core::Error) -> String {
    format!("{step} failed: {e}")
}

fn service_pid() -> Result<u32, String> {
    let name: Vec<u16> = OsStr::new(&crate::get_app_name()).encode_wide().chain(Some(0)).collect();
    unsafe {
        let scm = OpenSCManagerW(PCWSTR::null(), PCWSTR::null(), SC_MANAGER_CONNECT)
            .map_err(|e| failed("OpenSCManagerW", e))?;
        let svc = match OpenServiceW(scm, PCWSTR(name.as_ptr()), SERVICE_QUERY_STATUS) {
            Ok(svc) => svc,
            Err(e) => {
                let _ = CloseServiceHandle(scm);
                return Err(failed("OpenServiceW", e));
            }
        };
        let mut status = SERVICE_STATUS_PROCESS::default();
        let mut needed: u32 = 0;
        let queried = {
            let buf = std::slice::from_raw_parts_mut(
                (&mut status as *mut SERVICE_STATUS_PROCESS).cast::<u8>(),
                std::mem::size_of::<SERVICE_STATUS_PROCESS>(),
            );
            QueryServiceStatusEx(svc, SC_STATUS_PROCESS_INFO, Some(buf), &mut needed)
        };
        let _ = CloseServiceHandle(svc);
        let _ = CloseServiceHandle(scm);
        queried.map_err(|e| failed("QueryServiceStatusEx", e))?;
        match status.dwProcessId {
            0 => Err("QueryServiceStatusEx failed: the service reports no process id".to_string()),
            pid => Ok(pid),
        }
    }
}

fn own_session() -> Result<u32, String> {
    unsafe {
        let mut raw = HANDLE::default();
        OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut raw).map_err(|e| failed("OpenProcessToken(self)", e))?;
        let token = Owned(raw);
        let mut session: u32 = 0;
        let mut len: u32 = 0;
        GetTokenInformation(
            token.0,
            TokenSessionId,
            Some((&mut session as *mut u32).cast()),
            std::mem::size_of::<u32>() as u32,
            &mut len,
        )
        .map_err(|e| failed("GetTokenInformation(TokenSessionId)", e))?;
        Ok(session)
    }
}

fn ensure_local_system(token: HANDLE) -> Result<(), String> {
    unsafe {
        let mut len: u32 = 0;
        let _ = GetTokenInformation(token, TokenUser, None, 0, &mut len);
        let mut buf = vec![0usize; (len as usize).div_ceil(std::mem::size_of::<usize>())];
        GetTokenInformation(token, TokenUser, Some(buf.as_mut_ptr().cast()), len, &mut len)
            .map_err(|e| failed("GetTokenInformation(TokenUser)", e))?;
        let user = &*buf.as_ptr().cast::<TOKEN_USER>();
        if IsWellKnownSid(user.User.Sid, WinLocalSystemSid).as_bool() {
            Ok(())
        } else {
            Err("service token is not LocalSystem".to_string())
        }
    }
}

fn service_token() -> Result<Owned, String> {
    let pid = service_pid()?;
    let session = own_session()?;
    unsafe {
        let process =
            Owned(OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid).map_err(|e| failed("OpenProcess", e))?);
        let mut raw = HANDLE::default();
        OpenProcessToken(process.0, TOKEN_DUPLICATE | TOKEN_QUERY, &mut raw)
            .map_err(|e| failed("OpenProcessToken(service)", e))?;
        let token = Owned(raw);
        ensure_local_system(token.0)?;
        let mut dup = HANDLE::default();
        DuplicateTokenEx(
            token.0,
            TOKEN_ASSIGN_PRIMARY | TOKEN_DUPLICATE | TOKEN_QUERY | TOKEN_ADJUST_SESSIONID,
            None,
            SecurityImpersonation,
            TokenPrimary,
            &mut dup,
        )
        .map_err(|e| failed("DuplicateTokenEx", e))?;
        let primary = Owned(dup);
        SetTokenInformation(
            primary.0,
            TokenSessionId,
            (&session as *const u32).cast(),
            std::mem::size_of::<u32>() as u32,
        )
        .map_err(|e| failed("SetTokenInformation(TokenSessionId)", e))?;
        Ok(primary)
    }
}

fn push_arg(line: &mut Vec<u16>, arg: &OsStr, force: bool) {
    const QUOTE: u16 = b'"' as u16;
    const SLASH: u16 = b'\\' as u16;
    let quote = force || arg.is_empty() || arg.encode_wide().any(|c| c == b' ' as u16 || c == b'\t' as u16);
    if quote {
        line.push(QUOTE);
    }
    let mut slashes = 0usize;
    for c in arg.encode_wide() {
        if c == SLASH {
            slashes += 1;
        } else {
            if c == QUOTE {
                line.extend(std::iter::repeat(SLASH).take(slashes + 1));
            }
            slashes = 0;
        }
        line.push(c);
    }
    if quote {
        line.extend(std::iter::repeat(SLASH).take(slashes));
        line.push(QUOTE);
    }
}

fn command_line(program: &str, args: &[OsString]) -> Vec<u16> {
    let mut line = Vec::new();
    push_arg(&mut line, OsStr::new(program), true);
    for arg in args {
        line.push(b' ' as u16);
        push_arg(&mut line, arg, false);
    }
    line.push(0);
    line
}

fn create(token: &Owned, line: &mut [u16], handles: &[HANDLE; 3]) -> Result<TokenChild, String> {
    unsafe {
        let mut size = 0usize;
        let _ = InitializeProcThreadAttributeList(None, 1, None, &mut size);
        let mut storage = vec![0usize; size.div_ceil(std::mem::size_of::<usize>())];
        let list = LPPROC_THREAD_ATTRIBUTE_LIST(storage.as_mut_ptr().cast());
        InitializeProcThreadAttributeList(Some(list), 1, None, &mut size)
            .map_err(|e| failed("InitializeProcThreadAttributeList", e))?;
        let mut si = STARTUPINFOEXW::default();
        si.StartupInfo.cb = std::mem::size_of::<STARTUPINFOEXW>() as u32;
        si.StartupInfo.dwFlags = STARTF_USESTDHANDLES;
        si.StartupInfo.hStdInput = handles[0];
        si.StartupInfo.hStdOutput = handles[1];
        si.StartupInfo.hStdError = handles[2];
        si.lpAttributeList = list;
        let mut pi = PROCESS_INFORMATION::default();
        let created = UpdateProcThreadAttribute(
            list,
            0,
            PROC_THREAD_ATTRIBUTE_HANDLE_LIST as usize,
            Some(handles.as_ptr().cast()),
            std::mem::size_of_val(handles),
            None,
            None,
        )
        .map_err(|e| failed("UpdateProcThreadAttribute", e))
        .and_then(|()| {
            CreateProcessAsUserW(
                Some(token.0),
                PCWSTR::null(),
                Some(PWSTR(line.as_mut_ptr())),
                None,
                None,
                true,
                CREATE_NO_WINDOW | CREATE_UNICODE_ENVIRONMENT | EXTENDED_STARTUPINFO_PRESENT,
                None,
                PCWSTR::null(),
                &si.StartupInfo,
                &mut pi,
            )
            .map_err(|e| failed("CreateProcessAsUserW", e))
        });
        DeleteProcThreadAttributeList(list);
        created?;
        let _ = CloseHandle(pi.hThread);
        Ok(TokenChild { process: pi.hProcess, pid: pi.dwProcessId })
    }
}

fn launch(token: &Owned, program: &str, args: &[OsString], stdout: &File, stderr: &File) -> Result<TokenChild, String> {
    let stdin = std::fs::OpenOptions::new().read(true).open("NUL").map_err(|e| format!("opening NUL failed: {e}"))?;
    let handles = [
        HANDLE(stdin.as_raw_handle()),
        HANDLE(stdout.as_raw_handle()),
        HANDLE(stderr.as_raw_handle()),
    ];
    let mut line = command_line(program, args);
    let launched = handles
        .iter()
        .try_for_each(|h| {
            unsafe { SetHandleInformation(*h, HANDLE_FLAG_INHERIT.0, HANDLE_FLAG_INHERIT) }
                .map_err(|e| failed("SetHandleInformation", e))
        })
        .and_then(|()| create(token, &mut line, &handles));
    for h in handles {
        unsafe {
            let _ = SetHandleInformation(h, HANDLE_FLAG_INHERIT.0, HANDLE_FLAGS(0));
        }
    }
    launched
}

pub(super) fn spawn(
    program: &str,
    args: &[OsString],
    stdout: File,
    stderr: File,
    job_id: &str,
) -> std::io::Result<SystemChild> {
    use std::os::windows::process::CommandExt;
    match service_token().and_then(|token| launch(&token, program, args, &stdout, &stderr)) {
        Ok(child) => Ok(SystemChild::Token(child)),
        Err(e) => {
            hbb_common::log::warn!(
                "console job {job_id}: could not launch with the service's SYSTEM token ({e}); launching with this process's own token"
            );
            std::process::Command::new(program)
                .args(args)
                .creation_flags(CREATE_NO_WINDOW.0)
                .stdin(Stdio::null())
                .stdout(Stdio::from(stdout))
                .stderr(Stdio::from(stderr))
                .spawn()
                .map(SystemChild::Std)
        }
    }
}
