//! HTTP transport policy the fork sets on upstream's shared clients.
//!
//! The clients themselves are upstream's and are built in `hbbs_http::http_client`, behind a private
//! macro. What lives here is the fork's own timeout policy and the tests that prove it is actually
//! in force — the builder call site stays upstream because that is where the client is constructed.

/// How long a response body may go with **no bytes arriving** before the request is abandoned.
///
/// This is an IDLE timeout, not a duration one — a slow-but-progressing transfer keeps resetting it,
/// so it bounds STALLS without punishing a slow link.
///
/// The per-class total timeouts already in place (12 s control / 180 s data) cannot express that
/// distinction: they kill a transfer for being slow, which is why a large upload over a poor link had
/// to be given a generous ceiling and a genuinely wedged connection then sat there for the whole of
/// it. 60 s is comfortably longer than any legitimate server-side pause on these endpoints and far
/// shorter than the data ceiling it complements — it does not replace either total, it caps the worst
/// case within them.
///
/// It applies to every caller of the shared async client, upstream's included. That breadth is the
/// point — a stall is a stall regardless of which endpoint it happens on — and it is safe in a way a
/// shorter TOTAL timeout would not be, since only a connection delivering nothing at all for a full
/// minute is affected.
///
/// Set on the ASYNC builder only, because `reqwest::blocking::ClientBuilder` has no `read_timeout`
/// (verified against reqwest 0.12.24). The blocking client keeps the connect + total timeouts it
/// already has; the asymmetry is the library's, not a choice.
pub const API_READ_IDLE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(60);

/// CONTROL-plane timeout — small, latency-sensitive requests whose value expires quickly (the
/// heartbeat and its siblings). A beat that takes longer than this has already missed its window, so
/// failing fast and retrying on the next tick is correct.
pub const API_TIMEOUT_CONTROL: std::time::Duration = std::time::Duration::from_secs(12);

/// DATA-plane timeout — bulk uploads: sysinfo, inventory, snapshots, job results.
///
/// This is a *total-duration* timeout, so it kills a slow-but-progressing upload for being slow
/// rather than for being stalled. The previous 12 s was therefore a throughput floor, not a liveness
/// check, and it held only because job results are capped by `store::MAX_JOB_RESULT` — a margin that
/// was never measured. That cap is **256 KiB**, not the 64 KiB the reasoning assumed: it split from
/// `MAX_JOB_PARAMS` and quadrupled in 0.37.1, so the floor being sized against was four times lower
/// than believed. The updater's 24 MB package hit the same failure from the other direction, needing
/// 6.4 Mbit/s sustained to fit its inherited 30 s budget — unreachable on a bandwidth-starved link —
/// until 0.24.1 gave downloads their own client.
///
/// 180 s covers the bulk class comfortably and leaves the control plane above untouched. Stalls are
/// bounded separately by [`API_READ_IDLE_TIMEOUT`], which is the liveness check this duration
/// ceiling cannot express; the two are complementary, and neither replaces the other.
pub const API_TIMEOUT_DATA: std::time::Duration = std::time::Duration::from_secs(180);

#[cfg(test)]
mod idle_timeout_tests {
    //! Does the shared async client actually abandon a STALLED response?
    //!
    //! This is the one guarantee that cannot be checked by reading the code: `read_timeout` is set on
    //! the builder, but whether it reaches a request issued through `create_http_client_async` — and
    //! whether it fires on a *stalled body* rather than only on a dead connect — is a runtime property
    //! of reqwest's configuration, not of ours.
    //!
    //! Both tests run against a stub server that completes the handshake, succeeds at sending headers,
    //! then stops.

    use super::API_READ_IDLE_TIMEOUT;
    use crate::hbbs_http::create_http_client_async;
    use hbb_common::tls::TlsType;
    // `tokio` is re-exported through hbb_common rather than being a direct dependency, so the bare
    // `#[tokio::test]` attribute only resolves once it is brought into scope — same as common.rs.
    use hbb_common::tokio::{self};
    use reqwest::Client as AsyncClient;
    use std::io::{Read, Write};
    use std::net::TcpListener;

    /// Accept one connection, read the request, send a complete set of headers promising a body — and
    /// then never send the body, holding the socket open. That is a stall, not a failure: the client
    /// has a live connection and a valid response in progress, and only an IDLE timeout can end it.
    fn spawn_stalling_server() -> u16 {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind stub listener");
        let port = listener.local_addr().expect("stub addr").port();
        std::thread::spawn(move || {
            if let Ok((mut sock, _)) = listener.accept() {
                let mut buf = [0u8; 1024];
                let _ = sock.read(&mut buf); // consume the request line + headers
                let _ = sock.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 32\r\n\r\n");
                let _ = sock.flush();
                // Hold the connection open, sending nothing. Long enough to outlast any timeout under
                // test; the thread dies with the test process.
                std::thread::sleep(std::time::Duration::from_secs(300));
            }
        });
        port
    }

    /// The mechanism, at a speed a test suite can afford. Builds a client the same way
    /// `create_http_client_async` does and asserts a stalled body is abandoned near the configured
    /// idle timeout rather than hanging — with a 2 s timeout so the test costs 2 s, not 60.
    #[tokio::test]
    async fn a_stalled_response_body_is_abandoned_at_the_idle_timeout() {
        let port = spawn_stalling_server();
        let client = AsyncClient::builder()
            .read_timeout(std::time::Duration::from_secs(2))
            .build()
            .expect("build client");

        let started = std::time::Instant::now();
        let result = client.get(format!("http://127.0.0.1:{port}/")).send().await;
        // The headers arrive, so `send()` may succeed; the stall is in the BODY. Read it to force the
        // idle timeout to be the thing that ends this.
        let outcome = match result {
            Ok(resp) => resp.text().await.map(|_| ()),
            Err(e) => Err(e),
        };
        let elapsed = started.elapsed();

        assert!(
            outcome.is_err(),
            "a body that never arrives must fail, not hang or return empty"
        );
        // Generous bounds: the point is that it ends on the IDLE timeout and not on some far larger
        // total ceiling — being exact about reqwest's scheduling would make this flaky for no gain.
        assert!(
            elapsed >= std::time::Duration::from_millis(1500)
                && elapsed < std::time::Duration::from_secs(20),
            "expected the stall to end near the 2s idle timeout, took {elapsed:?}"
        );
    }

    /// The REAL client, with the REAL constant. Proves the timeout is wired into
    /// `create_http_client_async` itself and not merely available on the builder — which is the part a
    /// reader of the code cannot confirm. Costs a full minute by construction, so it is opt-in:
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
        // Must land near API_READ_IDLE_TIMEOUT (60s) and well inside API_TIMEOUT_DATA (180s) — the
        // failure this would catch is the idle timeout silently not applying, leaving the request to
        // run to the total ceiling instead.
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
/// `reqwest::blocking` applies a 30 s TOTAL timeout by default, and nothing overrode it. A 24 MB
/// package therefore had to sustain ~6.4 Mbit/s or the body read was aborted midway, surfacing as the
/// opaque `error decoding response body` with no URL, status or byte count. On a slow link that is
/// simply unreachable, so those clients could never update, however many times the console pushed.
///
/// Ideally this would bound STALLS rather than duration, but `reqwest::blocking::ClientBuilder` has no
/// `read_timeout` — that exists only on the async builder, where [`API_READ_IDLE_TIMEOUT`] uses it. So
/// instead: a short connect timeout to fail fast on an unreachable host, plus a total ceiling generous
/// enough for a genuinely slow link (24 MB inside 30 min is ~107 kbit/s). That ceiling is only safe
/// because the caller RESUMES — a transfer cut off by it keeps its bytes and the next attempt
/// continues, so the download converges instead of restarting.
///
/// TLS type and cert policy come from the cache the preceding API calls primed, so this does not
/// repeat the probe-and-fallback dance.
///
/// Returns the configured builder plus the two TLS values, because the builder must be finished by
/// `configure_http_client!`, which is private to `hbbs_http::http_client`.
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
