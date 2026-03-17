use super::*;
use crate::config::ProxyConfig;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::pin::Pin;
use std::task::{Context, Poll};
use tokio::io::{duplex, AsyncBufReadExt, BufReader};
use tokio::net::TcpListener;
#[cfg(unix)]
use tokio::net::UnixListener;
use tokio::time::{sleep, timeout, Duration};

#[tokio::test]
async fn bad_client_probe_is_forwarded_verbatim_to_mask_backend() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let backend_addr = listener.local_addr().unwrap();
    let probe = b"GET / HTTP/1.1\r\nHost: front.example\r\n\r\n".to_vec();
    let backend_reply = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK".to_vec();

    let accept_task = tokio::spawn({
        let probe = probe.clone();
        let backend_reply = backend_reply.clone();
        async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut received = vec![0u8; probe.len()];
            stream.read_exact(&mut received).await.unwrap();
            assert_eq!(received, probe);
            stream.write_all(&backend_reply).await.unwrap();
        }
    });

    let mut config = ProxyConfig::default();
    config.general.beobachten = false;
    config.censorship.mask = true;
    config.censorship.mask_host = Some("127.0.0.1".to_string());
    config.censorship.mask_port = backend_addr.port();
    config.censorship.mask_unix_sock = None;
    config.censorship.mask_proxy_protocol = 0;

    let peer: SocketAddr = "203.0.113.10:42424".parse().unwrap();
    let local_addr: SocketAddr = "127.0.0.1:443".parse().unwrap();

    let (client_reader, _client_writer) = duplex(256);
    let (mut client_visible_reader, client_visible_writer) = duplex(2048);

    let beobachten = BeobachtenStore::new();
    handle_bad_client(
        client_reader,
        client_visible_writer,
        &probe,
        peer,
        local_addr,
        &config,
        &beobachten,
    )
    .await;

    let mut observed = vec![0u8; backend_reply.len()];
    client_visible_reader.read_exact(&mut observed).await.unwrap();
    assert_eq!(observed, backend_reply);
    accept_task.await.unwrap();
}

#[tokio::test]
async fn tls_scanner_probe_keeps_http_like_fallback_surface() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let backend_addr = listener.local_addr().unwrap();
    let probe = vec![0x16, 0x03, 0x01, 0x00, 0x10, 0x01, 0x02, 0x03, 0x04];
    let backend_reply = b"HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n".to_vec();

    let accept_task = tokio::spawn({
        let probe = probe.clone();
        let backend_reply = backend_reply.clone();
        async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut received = vec![0u8; probe.len()];
            stream.read_exact(&mut received).await.unwrap();
            assert_eq!(received, probe);
            stream.write_all(&backend_reply).await.unwrap();
        }
    });

    let mut config = ProxyConfig::default();
    config.general.beobachten = true;
    config.general.beobachten_minutes = 1;
    config.censorship.mask = true;
    config.censorship.mask_host = Some("127.0.0.1".to_string());
    config.censorship.mask_port = backend_addr.port();
    config.censorship.mask_unix_sock = None;
    config.censorship.mask_proxy_protocol = 0;

    let peer: SocketAddr = "198.51.100.44:55221".parse().unwrap();
    let local_addr: SocketAddr = "127.0.0.1:443".parse().unwrap();

    let (client_reader, _client_writer) = duplex(256);
    let (mut client_visible_reader, client_visible_writer) = duplex(2048);

    let beobachten = BeobachtenStore::new();
    handle_bad_client(
        client_reader,
        client_visible_writer,
        &probe,
        peer,
        local_addr,
        &config,
        &beobachten,
    )
    .await;

    let mut observed = vec![0u8; backend_reply.len()];
    client_visible_reader.read_exact(&mut observed).await.unwrap();
    assert_eq!(observed, backend_reply);

    let snapshot = beobachten.snapshot_text(Duration::from_secs(60));
    assert!(snapshot.contains("[TLS-scanner]"));
    assert!(snapshot.contains("198.51.100.44-1"));
    accept_task.await.unwrap();
}

#[test]
fn detect_client_type_covers_ssh_port_scanner_and_unknown() {
    assert_eq!(detect_client_type(b"SSH-2.0-OpenSSH_9.7"), "SSH");
    assert_eq!(detect_client_type(b"\x01\x02\x03"), "port-scanner");
    assert_eq!(detect_client_type(b"random-binary-payload"), "unknown");
}

#[test]
fn detect_client_type_len_boundary_9_vs_10_bytes() {
    assert_eq!(detect_client_type(b"123456789"), "port-scanner");
    assert_eq!(detect_client_type(b"1234567890"), "unknown");
}

#[tokio::test]
async fn beobachten_records_scanner_class_when_mask_is_disabled() {
    let mut config = ProxyConfig::default();
    config.general.beobachten = true;
    config.general.beobachten_minutes = 1;
    config.censorship.mask = false;

    let peer: SocketAddr = "203.0.113.99:41234".parse().unwrap();
    let local_addr: SocketAddr = "127.0.0.1:443".parse().unwrap();
    let initial = b"SSH-2.0-probe";

    let (mut client_reader_side, client_reader) = duplex(256);
    let (_client_visible_reader, client_visible_writer) = duplex(256);
    let beobachten = BeobachtenStore::new();

    let task = tokio::spawn(async move {
        handle_bad_client(
            client_reader,
            client_visible_writer,
            initial,
            peer,
            local_addr,
            &config,
            &beobachten,
        )
        .await;
        beobachten
    });

    client_reader_side.write_all(b"noise").await.unwrap();
    drop(client_reader_side);

    let beobachten = timeout(Duration::from_secs(3), task).await.unwrap().unwrap();
    let snapshot = beobachten.snapshot_text(Duration::from_secs(60));
    assert!(snapshot.contains("[SSH]"));
    assert!(snapshot.contains("203.0.113.99-1"));
}

#[tokio::test]
async fn backend_unavailable_falls_back_to_silent_consume() {
    let temp_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let unused_port = temp_listener.local_addr().unwrap().port();
    drop(temp_listener);

    let mut config = ProxyConfig::default();
    config.general.beobachten = false;
    config.censorship.mask = true;
    config.censorship.mask_host = Some("127.0.0.1".to_string());
    config.censorship.mask_port = unused_port;
    config.censorship.mask_unix_sock = None;
    config.censorship.mask_proxy_protocol = 0;

    let peer: SocketAddr = "203.0.113.11:42425".parse().unwrap();
    let local_addr: SocketAddr = "127.0.0.1:443".parse().unwrap();
    let probe = b"GET /probe HTTP/1.1\r\nHost: x\r\n\r\n";

    let (mut client_reader_side, client_reader) = duplex(256);
    let (mut client_visible_reader, client_visible_writer) = duplex(256);
    let beobachten = BeobachtenStore::new();

    let task = tokio::spawn(async move {
        handle_bad_client(
            client_reader,
            client_visible_writer,
            probe,
            peer,
            local_addr,
            &config,
            &beobachten,
        )
        .await;
    });

    client_reader_side.write_all(b"noise").await.unwrap();
    drop(client_reader_side);

    timeout(Duration::from_secs(3), task).await.unwrap().unwrap();

    let mut buf = [0u8; 1];
    let n = timeout(Duration::from_secs(1), client_visible_reader.read(&mut buf))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(n, 0);
}

#[tokio::test]
async fn mask_disabled_consumes_client_data_without_response() {
    let mut config = ProxyConfig::default();
    config.general.beobachten = false;
    config.censorship.mask = false;

    let peer: SocketAddr = "198.51.100.12:45454".parse().unwrap();
    let local_addr: SocketAddr = "127.0.0.1:443".parse().unwrap();
    let initial = b"scanner";

    let (mut client_reader_side, client_reader) = duplex(256);
    let (mut client_visible_reader, client_visible_writer) = duplex(256);
    let beobachten = BeobachtenStore::new();

    let task = tokio::spawn(async move {
        handle_bad_client(
            client_reader,
            client_visible_writer,
            initial,
            peer,
            local_addr,
            &config,
            &beobachten,
        )
        .await;
    });

    client_reader_side.write_all(b"untrusted payload").await.unwrap();
    drop(client_reader_side);

    timeout(Duration::from_secs(3), task).await.unwrap().unwrap();

    let mut buf = [0u8; 1];
    let n = timeout(Duration::from_secs(1), client_visible_reader.read(&mut buf))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(n, 0);
}

#[tokio::test]
async fn proxy_protocol_v1_header_is_sent_before_probe() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let backend_addr = listener.local_addr().unwrap();
    let probe = b"GET / HTTP/1.1\r\nHost: front.example\r\n\r\n".to_vec();
    let backend_reply = b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n".to_vec();

    let accept_task = tokio::spawn({
        let probe = probe.clone();
        let backend_reply = backend_reply.clone();
        async move {
            let (stream, _) = listener.accept().await.unwrap();
            let mut reader = BufReader::new(stream);

            let mut header_line = Vec::new();
            reader.read_until(b'\n', &mut header_line).await.unwrap();
            let header_text = String::from_utf8(header_line.clone()).unwrap();
            assert!(header_text.starts_with("PROXY TCP4 "));
            assert!(header_text.ends_with("\r\n"));

            let mut received_probe = vec![0u8; probe.len()];
            reader.read_exact(&mut received_probe).await.unwrap();
            assert_eq!(received_probe, probe);

            let mut stream = reader.into_inner();
            stream.write_all(&backend_reply).await.unwrap();
        }
    });

    let mut config = ProxyConfig::default();
    config.general.beobachten = false;
    config.censorship.mask = true;
    config.censorship.mask_host = Some("127.0.0.1".to_string());
    config.censorship.mask_port = backend_addr.port();
    config.censorship.mask_unix_sock = None;
    config.censorship.mask_proxy_protocol = 1;

    let peer: SocketAddr = "203.0.113.15:50001".parse().unwrap();
    let local_addr: SocketAddr = "127.0.0.1:443".parse().unwrap();

    let (client_reader, _client_writer) = duplex(256);
    let (mut client_visible_reader, client_visible_writer) = duplex(2048);

    let beobachten = BeobachtenStore::new();
    handle_bad_client(
        client_reader,
        client_visible_writer,
        &probe,
        peer,
        local_addr,
        &config,
        &beobachten,
    )
    .await;

    let mut observed = vec![0u8; backend_reply.len()];
    client_visible_reader.read_exact(&mut observed).await.unwrap();
    assert_eq!(observed, backend_reply);
    accept_task.await.unwrap();
}

#[tokio::test]
async fn proxy_protocol_v2_header_is_sent_before_probe() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let backend_addr = listener.local_addr().unwrap();
    let probe = b"GET / HTTP/1.1\r\nHost: front.example\r\n\r\n".to_vec();
    let backend_reply = b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n".to_vec();

    let accept_task = tokio::spawn({
        let probe = probe.clone();
        let backend_reply = backend_reply.clone();
        async move {
            let (mut stream, _) = listener.accept().await.unwrap();

            let mut sig = [0u8; 12];
            stream.read_exact(&mut sig).await.unwrap();
            assert_eq!(&sig, b"\r\n\r\n\0\r\nQUIT\n");

            let mut fixed = [0u8; 4];
            stream.read_exact(&mut fixed).await.unwrap();
            let addr_len = u16::from_be_bytes([fixed[2], fixed[3]]) as usize;

            let mut addr_block = vec![0u8; addr_len];
            stream.read_exact(&mut addr_block).await.unwrap();

            let mut received_probe = vec![0u8; probe.len()];
            stream.read_exact(&mut received_probe).await.unwrap();
            assert_eq!(received_probe, probe);

            stream.write_all(&backend_reply).await.unwrap();
        }
    });

    let mut config = ProxyConfig::default();
    config.general.beobachten = false;
    config.censorship.mask = true;
    config.censorship.mask_host = Some("127.0.0.1".to_string());
    config.censorship.mask_port = backend_addr.port();
    config.censorship.mask_unix_sock = None;
    config.censorship.mask_proxy_protocol = 2;

    let peer: SocketAddr = "203.0.113.18:50004".parse().unwrap();
    let local_addr: SocketAddr = "127.0.0.1:443".parse().unwrap();

    let (client_reader, _client_writer) = duplex(256);
    let (mut client_visible_reader, client_visible_writer) = duplex(2048);

    let beobachten = BeobachtenStore::new();
    handle_bad_client(
        client_reader,
        client_visible_writer,
        &probe,
        peer,
        local_addr,
        &config,
        &beobachten,
    )
    .await;

    let mut observed = vec![0u8; backend_reply.len()];
    client_visible_reader.read_exact(&mut observed).await.unwrap();
    assert_eq!(observed, backend_reply);
    accept_task.await.unwrap();
}

#[tokio::test]
async fn proxy_protocol_v1_mixed_family_falls_back_to_unknown_header() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let backend_addr = listener.local_addr().unwrap();
    let probe = b"GET /mix HTTP/1.1\r\nHost: front.example\r\n\r\n".to_vec();
    let backend_reply = b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n".to_vec();

    let accept_task = tokio::spawn({
        let probe = probe.clone();
        let backend_reply = backend_reply.clone();
        async move {
            let (stream, _) = listener.accept().await.unwrap();
            let mut reader = BufReader::new(stream);

            let mut header_line = Vec::new();
            reader.read_until(b'\n', &mut header_line).await.unwrap();
            let header_text = String::from_utf8(header_line).unwrap();
            assert_eq!(header_text, "PROXY UNKNOWN\r\n");

            let mut received_probe = vec![0u8; probe.len()];
            reader.read_exact(&mut received_probe).await.unwrap();
            assert_eq!(received_probe, probe);

            let mut stream = reader.into_inner();
            stream.write_all(&backend_reply).await.unwrap();
        }
    });

    let mut config = ProxyConfig::default();
    config.general.beobachten = false;
    config.censorship.mask = true;
    config.censorship.mask_host = Some("127.0.0.1".to_string());
    config.censorship.mask_port = backend_addr.port();
    config.censorship.mask_unix_sock = None;
    config.censorship.mask_proxy_protocol = 1;

    let peer: SocketAddr = "203.0.113.20:50006".parse().unwrap();
    let local_addr: SocketAddr = "[::1]:443".parse().unwrap();

    let (client_reader, _client_writer) = duplex(256);
    let (mut client_visible_reader, client_visible_writer) = duplex(2048);

    let beobachten = BeobachtenStore::new();
    handle_bad_client(
        client_reader,
        client_visible_writer,
        &probe,
        peer,
        local_addr,
        &config,
        &beobachten,
    )
    .await;

    let mut observed = vec![0u8; backend_reply.len()];
    client_visible_reader.read_exact(&mut observed).await.unwrap();
    assert_eq!(observed, backend_reply);
    accept_task.await.unwrap();
}

#[cfg(unix)]
#[tokio::test]
async fn unix_socket_mask_path_forwards_probe_and_response() {
    let sock_path = format!("/tmp/telemt-mask-test-{}-{}.sock", std::process::id(), rand::random::<u64>());
    let _ = std::fs::remove_file(&sock_path);

    let listener = UnixListener::bind(&sock_path).unwrap();
    let probe = b"GET /unix HTTP/1.1\r\nHost: front.example\r\n\r\n".to_vec();
    let backend_reply = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK".to_vec();

    let accept_task = tokio::spawn({
        let probe = probe.clone();
        let backend_reply = backend_reply.clone();
        async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut received = vec![0u8; probe.len()];
            stream.read_exact(&mut received).await.unwrap();
            assert_eq!(received, probe);
            stream.write_all(&backend_reply).await.unwrap();
        }
    });

    let mut config = ProxyConfig::default();
    config.general.beobachten = false;
    config.censorship.mask = true;
    config.censorship.mask_unix_sock = Some(sock_path.clone());
    config.censorship.mask_proxy_protocol = 0;

    let peer: SocketAddr = "203.0.113.30:50010".parse().unwrap();
    let local_addr: SocketAddr = "127.0.0.1:443".parse().unwrap();

    let (client_reader, _client_writer) = duplex(256);
    let (mut client_visible_reader, client_visible_writer) = duplex(2048);

    let beobachten = BeobachtenStore::new();
    handle_bad_client(
        client_reader,
        client_visible_writer,
        &probe,
        peer,
        local_addr,
        &config,
        &beobachten,
    )
    .await;

    let mut observed = vec![0u8; backend_reply.len()];
    client_visible_reader.read_exact(&mut observed).await.unwrap();
    assert_eq!(observed, backend_reply);

    accept_task.await.unwrap();
    let _ = std::fs::remove_file(sock_path);
}

#[tokio::test]
async fn mask_disabled_slowloris_connection_is_closed_by_consume_timeout() {
    let mut config = ProxyConfig::default();
    config.general.beobachten = false;
    config.censorship.mask = false;

    let peer: SocketAddr = "198.51.100.33:45455".parse().unwrap();
    let local_addr: SocketAddr = "127.0.0.1:443".parse().unwrap();

    let (_client_reader_side, client_reader) = duplex(256);
    let (_client_visible_reader, client_visible_writer) = duplex(256);
    let beobachten = BeobachtenStore::new();

    let task = tokio::spawn(async move {
        handle_bad_client(
            client_reader,
            client_visible_writer,
            b"slowloris",
            peer,
            local_addr,
            &config,
            &beobachten,
        )
        .await;
    });

    timeout(Duration::from_secs(1), task).await.unwrap().unwrap();
}

struct PendingWriter;

impl tokio::io::AsyncWrite for PendingWriter {
    fn poll_write(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        _buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        Poll::Pending
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

struct DropTrackedPendingReader {
    dropped: Arc<AtomicBool>,
}

impl tokio::io::AsyncRead for DropTrackedPendingReader {
    fn poll_read(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        _buf: &mut tokio::io::ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        Poll::Pending
    }
}

impl Drop for DropTrackedPendingReader {
    fn drop(&mut self) {
        self.dropped.store(true, Ordering::SeqCst);
    }
}

struct DropTrackedPendingWriter {
    dropped: Arc<AtomicBool>,
}

impl tokio::io::AsyncWrite for DropTrackedPendingWriter {
    fn poll_write(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        _buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        Poll::Pending
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

impl Drop for DropTrackedPendingWriter {
    fn drop(&mut self) {
        self.dropped.store(true, Ordering::SeqCst);
    }
}

#[tokio::test]
async fn proxy_header_write_timeout_returns_false() {
    let mut writer = PendingWriter;
    let ok = write_proxy_header_with_timeout(&mut writer, b"PROXY UNKNOWN\r\n").await;
    assert!(!ok, "Proxy header writes that never complete must time out");
}

#[tokio::test]
async fn relay_to_mask_keeps_backend_to_client_flow_when_client_to_backend_stalls() {
    let (mut client_feed_writer, client_feed_reader) = duplex(64);
    let (mut client_visible_reader, client_visible_writer) = duplex(64);
    let (mut backend_feed_writer, backend_feed_reader) = duplex(64);

    // Make client->mask direction immediately active so the c2m path blocks on PendingWriter.
    client_feed_writer.write_all(b"X").await.unwrap();

    let relay = tokio::spawn(async move {
        relay_to_mask(
            client_feed_reader,
            client_visible_writer,
            backend_feed_reader,
            PendingWriter,
            b"",
        )
        .await;
    });

    // Allow relay tasks to start, then emulate mask backend response.
    sleep(Duration::from_millis(20)).await;
    backend_feed_writer.write_all(b"HTTP/1.1 200 OK\r\n\r\n").await.unwrap();
    backend_feed_writer.shutdown().await.unwrap();

    let mut observed = vec![0u8; 19];
    timeout(Duration::from_secs(1), client_visible_reader.read_exact(&mut observed))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(observed, b"HTTP/1.1 200 OK\r\n\r\n");

    relay.abort();
    let _ = relay.await;
}

#[tokio::test]
async fn relay_to_mask_preserves_backend_response_after_client_half_close() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let backend_addr = listener.local_addr().unwrap();
    let request = b"GET / HTTP/1.1\r\nHost: front.example\r\n\r\n".to_vec();
    let response = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK".to_vec();

    let backend_task = tokio::spawn({
        let request = request.clone();
        let response = response.clone();
        async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut observed_req = vec![0u8; request.len()];
            stream.read_exact(&mut observed_req).await.unwrap();
            assert_eq!(observed_req, request);
            stream.write_all(&response).await.unwrap();
            stream.shutdown().await.unwrap();
        }
    });

    let mut config = ProxyConfig::default();
    config.general.beobachten = false;
    config.censorship.mask = true;
    config.censorship.mask_host = Some("127.0.0.1".to_string());
    config.censorship.mask_port = backend_addr.port();
    config.censorship.mask_unix_sock = None;
    config.censorship.mask_proxy_protocol = 0;

    let peer: SocketAddr = "203.0.113.77:55001".parse().unwrap();
    let local_addr: SocketAddr = "127.0.0.1:443".parse().unwrap();

    let (mut client_write, client_read) = duplex(1024);
    let (mut client_visible_reader, client_visible_writer) = duplex(2048);
    let beobachten = BeobachtenStore::new();

    let fallback_task = tokio::spawn(async move {
        handle_bad_client(
            client_read,
            client_visible_writer,
            &request,
            peer,
            local_addr,
            &config,
            &beobachten,
        )
        .await;
    });

    client_write.shutdown().await.unwrap();

    let mut observed_resp = vec![0u8; response.len()];
    timeout(Duration::from_secs(1), client_visible_reader.read_exact(&mut observed_resp))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(observed_resp, response);

    timeout(Duration::from_secs(1), fallback_task).await.unwrap().unwrap();
    timeout(Duration::from_secs(1), backend_task).await.unwrap().unwrap();
}

#[tokio::test]
async fn relay_to_mask_timeout_cancels_and_drops_all_io_endpoints() {
    let reader_dropped = Arc::new(AtomicBool::new(false));
    let writer_dropped = Arc::new(AtomicBool::new(false));
    let mask_reader_dropped = Arc::new(AtomicBool::new(false));
    let mask_writer_dropped = Arc::new(AtomicBool::new(false));

    let reader = DropTrackedPendingReader {
        dropped: reader_dropped.clone(),
    };
    let writer = DropTrackedPendingWriter {
        dropped: writer_dropped.clone(),
    };
    let mask_read = DropTrackedPendingReader {
        dropped: mask_reader_dropped.clone(),
    };
    let mask_write = DropTrackedPendingWriter {
        dropped: mask_writer_dropped.clone(),
    };

    let timed = timeout(
        Duration::from_millis(40),
        relay_to_mask(reader, writer, mask_read, mask_write, b""),
    )
    .await;

    assert!(timed.is_err(), "stalled relay must be bounded by timeout");

    assert!(reader_dropped.load(Ordering::SeqCst));
    assert!(writer_dropped.load(Ordering::SeqCst));
    assert!(mask_reader_dropped.load(Ordering::SeqCst));
    assert!(mask_writer_dropped.load(Ordering::SeqCst));
}
