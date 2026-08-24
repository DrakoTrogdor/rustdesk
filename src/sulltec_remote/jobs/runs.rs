use super::*;

const KILL_UNKNOWN: &str = "this device has no record of that job: it was never handed here, or its \
     record has already lapsed. Nothing was killed.";

const KILL_FINISHED: &str = "that job already ran to completion on this device. There is no process \
     to end — whatever the recorded pid answers to now is not this run's.";

const KILL_NO_PROCESS: &str = "that job is a run with no process of its own: this device took it up \
     and started no child for it — a procedure that runs inside the client, or a run-as script whose \
     wrapper never reported a pid. Nothing was killed, and nothing here could kill it.";

const KILL_REUSED: &str = "the recorded pid answers to a DIFFERENT process than the one this job \
     started — Windows reused it. Nothing was killed. This device will not end a process on a pid \
     alone.";

const KILL_GONE: &str = "that job's process has already ended. Nothing was killed; its answer \
     settles on the next poll.";

const KILL_REFUSED: &str = "that job's process is still running and this device was refused \
     permission to end it.";

const KILL_DONE: &str = "the process this job started was terminated. ⚠ ONE PROCESS: anything it had \
     itself launched is still running, and it was given no chance to clean up or to write a \
     completion marker. What it had already changed on this machine stands — a kill ends the \
     process, not the work it had already done. The job's own row settles on this device's next \
     poll: with whatever its own executor can still report where this client was waiting on it, and \
     as a run that was ended where nothing was. ⚠ A RUN-AS script is the exception: nothing here \
     holds a handle on that wrapper, and ending it is what stops it writing the completion marker \
     this device is polling for — so that row settles as ended-on-request only once the run's own \
     bound elapses.";

/// ⚠ The probe is [`adopt::alive`] and never [`adopt::settle_child`]: that one adopts before it asks
/// about liveness, and asking about a whole map would evict a real adoption's handle — taking the
/// exit code with it — and log a client restart that did not happen.
#[cfg(windows)]
pub(super) fn job_runs() -> Value {
    let map: serde_json::Map<String, Value> = serde_json::from_str::<Value>(&LocalConfig::get_option(JOBS_SEEN_OPT))
        .ok()
        .and_then(|v| v.as_object().cloned())
        .unwrap_or_default();
    let in_flight = jobs_in_flight();
    let now = now_secs();
    let mut items: Vec<Value> = Vec::new();
    let mut unprovable: u64 = 0;
    for (job_id, entry) in map.iter() {
        if matches!(seen_entry(entry), Some((_, true, _))) {
            continue;
        }
        let Some((pid, created)) = child_of(entry) else {
            if entry.get("x").is_some() && script::still_running(job_id) {
                unprovable += 1;
            }
            continue;
        };
        if !adopt::alive(pid, created) {
            continue;
        }
        let started_at = adopt::unix_of_token(created);
        let over = entry.get(SEEN_OVER_TIME).and_then(Value::as_i64);
        // ⚠ Read off the STAMP, not off the in-flight set. That set is this client's; a run
        // re-attached to after the client that started it stopped is running either way. The stamp
        // is what says this device stopped waiting on purpose.
        let state = match over.is_some() {
            true => "over_time",
            false => "running",
        };
        let mut row = json!({
            "job_id": job_id,
            "pid": pid,
            "started_at": started_at,
            "elapsed_s": (now - started_at).max(0),
            "state": state,
            "in_flight": in_flight.iter().any(|x| x == job_id),
        });
        if let Some(o) = over {
            row["over_time_at"] = json!(o);
        }
        items.push(row);
    }
    items.sort_by_key(|r| r.get("started_at").and_then(Value::as_i64).unwrap_or(0));
    json!({
        "ok": true,
        "count": items.len(),
        "unprovable": unprovable,
        "collected_at": now,
        "items": items,
    })
}

#[cfg(not(windows))]
pub(super) fn job_runs() -> Value {
    json!({ "ok": false, "error": "Windows-only" })
}

#[cfg(windows)]
pub(super) fn job_kill(params: Option<&str>) -> Value {
    let target = file_pull::json_field_or_raw(params.unwrap_or(""), &["job", "job_id", "id"]);
    let job_id = target.trim();
    if job_id.is_empty() {
        return json!({ "ok": false, "error": "job-kill needs a job id" });
    }
    let Some((_, done, _)) = seen_state(job_id) else {
        return json!({ "ok": false, "error": KILL_UNKNOWN });
    };
    if done {
        return json!({ "ok": false, "error": KILL_FINISHED });
    }
    let Some((pid, created)) = seen_child(job_id) else {
        return json!({ "ok": false, "error": KILL_NO_PROCESS });
    };
    match adopt::terminate(pid, created) {
        adopt::KillVerdict::Terminated => {
            mark_job_stamp(job_id, SEEN_KILLED);
            hbb_common::log::warn!("console job {job_id}: its process (pid {pid}) was ended on request");
            json!({ "ok": true, "pid": pid, "killed": KILL_DONE })
        }
        adopt::KillVerdict::Reused => json!({ "ok": false, "pid": pid, "error": KILL_REUSED }),
        adopt::KillVerdict::Gone => json!({ "ok": false, "pid": pid, "error": KILL_GONE }),
        adopt::KillVerdict::Refused => json!({ "ok": false, "pid": pid, "error": KILL_REFUSED }),
    }
}

#[cfg(not(windows))]
pub(super) fn job_kill(_params: Option<&str>) -> Value {
    json!({ "ok": false, "error": "Windows-only" })
}
