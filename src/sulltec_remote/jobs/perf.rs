use super::*;

/// A short CPU / memory / disk performance sample with the top processes by CPU and by memory
/// (read-only). Uses `sysinfo` without launching PowerShell; a two-pass
/// refresh makes CPU% a real delta. `params` JSON `{top_n:N}` (default 10, max 50) sets how many top
/// processes to return per dimension. Returns
/// `{cpu_pct, mem_total_mb, mem_used_mb, mem_pct, top_cpu:[…], top_mem:[…]}`.
pub(super) fn perf(params: Option<&str>) -> Option<Value> {
    use hbb_common::sysinfo::{System, MINIMUM_CPU_UPDATE_INTERVAL};
    let p: Value = params.and_then(|s| serde_json::from_str(s).ok()).unwrap_or(Value::Null);
    let top_n = p.get("top_n").and_then(|x| x.as_u64()).unwrap_or(10).clamp(1, 50) as usize;

    let mut sys = System::new();
    // First pass seeds per-process + global CPU counters; the second pass (after the minimum
    // interval) turns them into usable percentages.
    sys.refresh_cpu();
    sys.refresh_processes();
    sys.refresh_memory();
    std::thread::sleep(MINIMUM_CPU_UPDATE_INTERVAL);
    sys.refresh_cpu();
    sys.refresh_processes();

    let ncpu = num_cpus::get().max(1) as f32;
    // Global CPU utilisation.
    let cpu_pct = (sys.global_cpu_info().cpu_usage() as f64 * 10.0).round() / 10.0;
    let mem_total = sys.total_memory();
    let mem_used = sys.used_memory();
    let to_mb = |b: u64| (b as f64 / 1024.0 / 1024.0 * 10.0).round() / 10.0;
    let mem_pct = if mem_total > 0 {
        (mem_used as f64 / mem_total as f64 * 1000.0).round() / 10.0
    } else {
        0.0
    };

    // Build the per-process rows once, then sort two ways.
    let procs: Vec<(u32, String, f32, f64)> = sys
        .processes()
        .iter()
        .map(|(pid, p)| {
            (
                pid.as_u32(),
                p.name().to_owned(),
                ((p.cpu_usage() / ncpu) * 10.0).round() / 10.0,
                (p.memory() as f64 / 1024.0 / 1024.0 * 10.0).round() / 10.0,
            )
        })
        .collect();

    let mut by_cpu = procs.clone();
    by_cpu.sort_by(|a, b| b.2.partial_cmp(&a.2).unwrap_or(std::cmp::Ordering::Equal));
    by_cpu.truncate(top_n);
    let mut by_mem = procs;
    by_mem.sort_by(|a, b| b.3.partial_cmp(&a.3).unwrap_or(std::cmp::Ordering::Equal));
    by_mem.truncate(top_n);
    let row = |(pid, name, cpu, mem): &(u32, String, f32, f64)| {
        json!({ "pid": pid, "name": name, "cpu": cpu, "mem_mb": mem })
    };

    Some(json!({
        "cpu_pct": cpu_pct,
        "mem_total_mb": to_mb(mem_total),
        "mem_used_mb": to_mb(mem_used),
        "mem_pct": mem_pct,
        "top_cpu": by_cpu.iter().map(row).collect::<Vec<_>>(),
        "top_mem": by_mem.iter().map(row).collect::<Vec<_>>(),
    }))
}
