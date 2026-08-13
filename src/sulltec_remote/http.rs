//! HTTP timeout policy for the shared clients built by `hbbs_http::http_client`.

/// How long a response body may go with **no bytes arriving** before the request is abandoned.
///
/// This is an idle timeout: a progressing transfer resets it. It applies to every caller of the
/// shared asynchronous client and complements the control- and data-plane total timeouts.
///
/// Set on the ASYNC builder only, because `reqwest::blocking::ClientBuilder` has no `read_timeout`
/// in reqwest 0.12.24. The blocking client retains its connect and total timeouts.
pub const API_READ_IDLE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(60);

/// Total timeout for small, latency-sensitive control-plane requests such as heartbeats.
pub const API_TIMEOUT_CONTROL: std::time::Duration = std::time::Duration::from_secs(12);

/// DATA-plane timeout — bulk uploads: sysinfo, inventory, snapshots, job results.
///
/// This total-duration ceiling covers sysinfo, inventory, snapshots, and job-result uploads. Idle
/// stalls are bounded separately by [`API_READ_IDLE_TIMEOUT`].
pub const API_TIMEOUT_DATA: std::time::Duration = std::time::Duration::from_secs(180);

#[cfg(test)]
mod idle_timeout_tests {
    //! Verifies that shared asynchronous clients abandon stalled response bodies. The stub server
    //! completes the handshake and headers, then stops sending data.

    use super::API_READ_IDLE_TIMEOUT;
    use crate::hbbs_http::create_http_client_async;
    use hbb_common::tls::TlsType;
    // `tokio` is re-exported through hbb_common rather than declared as a direct dependency.
    use hbb_common::tokio::{self};
    use reqwest::Client as AsyncClient;
    use std::io::{Read, Write};
    use std::net::TcpListener;

    /// Send complete response headers, then hold the socket open without sending the promised body.
    fn spawn_stalling_server() -> u16 {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind stub listener");
        let port = listener.local_addr().expect("stub addr").port();
        std::thread::spawn(move || {
            if let Ok((mut sock, _)) = listener.accept() {
                let mut buf = [0u8; 1024];
                let _ = sock.read(&mut buf); // consume the request line + headers
                let _ = sock.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 32\r\n\r\n");
                let _ = sock.flush();
                // Keep the connection idle beyond the tested timeout.
                std::thread::sleep(std::time::Duration::from_secs(300));
            }
        });
        port
    }

    /// Verify the idle-timeout mechanism with a two-second test setting.
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

    /// Verify that `create_http_client_async` applies the production idle timeout. This opt-in test
    /// takes about one minute:
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
        // The request must end near the idle timeout and before the data-plane total timeout.
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

/// Timeouts and TLS selection for the update-package download.
///
/// The blocking reqwest builder has no idle read timeout, so downloads use a short connect timeout
/// and a 30-minute total ceiling. The caller resumes partial transfers after a timeout.
///
/// TLS type and certificate policy come from the cache populated by preceding API calls.
///
/// Returns the builder and TLS values for completion by `configure_http_client!` in
/// `hbbs_http::http_client`.
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
