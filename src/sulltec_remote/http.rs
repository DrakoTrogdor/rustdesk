//! Consumed by the shared clients `hbbs_http::http_client` builds.

/// Idle, not total: a transfer that keeps progressing never trips it. Set on the ASYNC builder
/// only — `reqwest::blocking::ClientBuilder` has no `read_timeout` in reqwest 0.12.24, so the
/// blocking client is bounded by its connect and total timeouts alone.
pub const API_READ_IDLE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(60);

/// Small latency-sensitive control-plane requests: heartbeats and their like.
pub const API_TIMEOUT_CONTROL: std::time::Duration = std::time::Duration::from_secs(12);

/// Bulk uploads — sysinfo, inventory, snapshots, job results. Idle stalls are bounded separately
/// by [`API_READ_IDLE_TIMEOUT`].
pub const API_TIMEOUT_DATA: std::time::Duration = std::time::Duration::from_secs(180);

#[cfg(test)]
mod idle_timeout_tests {
    use super::API_READ_IDLE_TIMEOUT;
    use crate::hbbs_http::create_http_client_async;
    use hbb_common::tls::TlsType;
    // `tokio` is re-exported through hbb_common rather than declared as a direct dependency.
    use hbb_common::tokio::{self};
    use reqwest::Client as AsyncClient;
    use std::io::{Read, Write};
    use std::net::TcpListener;

    fn spawn_stalling_server() -> u16 {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind stub listener");
        let port = listener.local_addr().expect("stub addr").port();
        std::thread::spawn(move || {
            if let Ok((mut sock, _)) = listener.accept() {
                let mut buf = [0u8; 1024];
                let _ = sock.read(&mut buf);
                // Headers promise 32 bytes that never arrive — the stall this exists to produce.
                let _ = sock.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 32\r\n\r\n");
                let _ = sock.flush();
                std::thread::sleep(std::time::Duration::from_secs(300));
            }
        });
        port
    }

    #[tokio::test]
    async fn a_stalled_response_body_is_abandoned_at_the_idle_timeout() {
        let port = spawn_stalling_server();
        let client = AsyncClient::builder()
            .read_timeout(std::time::Duration::from_secs(2))
            .build()
            .expect("build client");

        let started = std::time::Instant::now();
        let result = client.get(format!("http://127.0.0.1:{port}/")).send().await;
        // Read the body because the server sends headers before stalling.
        let outcome = match result {
            Ok(resp) => resp.text().await.map(|_| ()),
            Err(e) => Err(e),
        };
        let elapsed = started.elapsed();

        assert!(
            outcome.is_err(),
            "a body that never arrives must fail, not hang or return empty"
        );
        // Allow scheduling variance while distinguishing the idle timeout from the total ceiling.
        assert!(
            elapsed >= std::time::Duration::from_millis(1500)
                && elapsed < std::time::Duration::from_secs(20),
            "expected the stall to end near the 2s idle timeout, took {elapsed:?}"
        );
    }

    ///   cargo test --release --lib --features flutter,hwcodec,vram -- --ignored idle_timeout
    #[tokio::test]
    #[ignore = "takes ~60s by design — it waits out the production idle timeout"]
    async fn the_shipped_client_abandons_a_stalled_body() {
        let port = spawn_stalling_server();
        let client = create_http_client_async(TlsType::Plain, false);

        let started = std::time::Instant::now();
        let outcome = match client.get(format!("http://127.0.0.1:{port}/")).send().await {
            Ok(resp) => resp.text().await.map(|_| ()),
            Err(e) => Err(e),
        };
        let elapsed = started.elapsed();

        assert!(
            outcome.is_err(),
            "the shipped client must abandon a stalled body"
        );
        assert!(
            elapsed >= API_READ_IDLE_TIMEOUT.saturating_sub(std::time::Duration::from_secs(10)),
            "ended too early ({elapsed:?}) — something other than the idle timeout cut it"
        );
        assert!(
            elapsed < std::time::Duration::from_secs(120),
            "ran past the idle timeout ({elapsed:?}) — read_timeout is not reaching this client"
        );
    }
}

/// The blocking builder has no idle read timeout, so a download is bounded by connect + total
/// instead; the caller resumes a partial transfer after one. TLS type and certificate policy are
/// read from a cache that PRECEDING API calls populate, so this cannot run first. The returned
/// builder is finished by `configure_http_client!` in `hbbs_http::http_client`.
pub fn download_client_setup(
    url: &str,
) -> (reqwest::blocking::ClientBuilder, hbb_common::tls::TlsType, bool) {
    use hbb_common::config::Config;
    use hbb_common::tls::{get_cached_tls_accept_invalid_cert, get_cached_tls_type, TlsType};

    const CONNECT_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);
    /// Absolute ceiling, so a pathological link cannot wedge the updater thread indefinitely.
    const TOTAL_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30 * 60);

    let proxy_conf = Config::get_socks();
    let tls_url = crate::hbbs_http::get_url_for_tls(url, &proxy_conf);
    let tls_type = get_cached_tls_type(tls_url).unwrap_or(TlsType::Rustls);
    let danger_accept_invalid_cert = get_cached_tls_accept_invalid_cert(tls_url).unwrap_or(false);
    let builder = reqwest::blocking::Client::builder()
        .connect_timeout(CONNECT_TIMEOUT)
        .timeout(TOTAL_TIMEOUT);
    (builder, tls_type, danger_accept_invalid_cert)
}
