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
