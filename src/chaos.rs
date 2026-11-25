use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use rand::{Rng, SeedableRng};
use rand_chacha::ChaCha8Rng;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

#[derive(Clone, Debug)]
pub struct ChaosConfig {
    pub seed: u64,
    pub drop_rate: f64,     // 0.0..=1.0 (probability of abrupt drop / 502)
    pub rate_429: f64,      // 0.0..=1.0 (probability of HTTP 429 injection)
    pub max_jitter_ms: u64, // upper bound for per-request/chunk delay
    pub upstream: String,   // e.g. "127.0.0.1:8080"
}

/// Used by `guardrails chaos` CLI subcommand.
pub async fn start_http_chaos_proxy(listen: SocketAddr, cfg: ChaosConfig) -> anyhow::Result<()> {
    let listener = TcpListener::bind(listen).await?;
    serve_http_chaos_proxy(listener, cfg).await
}

/// Used by `resilience.rs` after binding an ephemeral `127.0.0.1:0` listener.
pub async fn serve_http_chaos_proxy(listener: TcpListener, cfg: ChaosConfig) -> anyhow::Result<()> {
    let counter = Arc::new(AtomicU64::new(0));

    loop {
        let (stream, _) = listener.accept().await?;
        let io = TokioIo::new(stream);
        let cfg = cfg.clone();
        let counter = counter.clone();

        tokio::spawn(async move {
            let service = service_fn(move |req: Request<hyper::body::Incoming>| {
                let cfg = cfg.clone();
                let seq = counter.fetch_add(1, Ordering::Relaxed);

                async move {
                    let mut rng = ChaCha8Rng::seed_from_u64(cfg.seed ^ seq);

                    // 1. Seeded latency jitter
                    if cfg.max_jitter_ms > 0 {
                        let delay = rng.gen_range(0..=cfg.max_jitter_ms);
                        tokio::time::sleep(Duration::from_millis(delay)).await;
                    }

                    // 2. Seeded HTTP 429 injection
                    if rng.gen_bool(cfg.rate_429.clamp(0.0, 1.0)) {
                        return Ok::<_, hyper::Error>(
                            Response::builder()
                                .status(StatusCode::TOO_MANY_REQUESTS)
                                .header("Retry-After", "1")
                                .body(Full::new(Bytes::from("Injected deterministic 429")))
                                .unwrap(),
                        );
                    }

                    // 3. Seeded drop simulation
                    if rng.gen_bool(cfg.drop_rate.clamp(0.0, 1.0)) {
                        return Ok(Response::builder()
                            .status(StatusCode::BAD_GATEWAY)
                            .body(Full::new(Bytes::from("Injected deterministic chaos drop")))
                            .unwrap());
                    }

                    // 4. Forward clean request to upstream
                    forward_http(&cfg.upstream, req).await
                }
            });

            if let Err(err) = http1::Builder::new().serve_connection(io, service).await {
                tracing::debug!("HTTP chaos connection closed: {err}");
            }
        });
    }
}

async fn forward_http(
    upstream: &str,
    req: Request<hyper::body::Incoming>,
) -> Result<Response<Full<Bytes>>, hyper::Error> {
    let Ok(stream) = TcpStream::connect(upstream).await else {
        return Ok(Response::builder()
            .status(StatusCode::BAD_GATEWAY)
            .body(Full::new(Bytes::from("Upstream unreachable")))
            .unwrap());
    };

    let io = TokioIo::new(stream);
    let (mut sender, conn) = hyper::client::conn::http1::handshake(io).await?;
    tokio::spawn(async move {
        if let Err(err) = conn.await {
            tracing::debug!("Upstream connection error: {err}");
        }
    });

    let resp = sender.send_request(req).await?;
    let (parts, body) = resp.into_parts();
    let collected = body.collect().await?.to_bytes();
    Ok(Response::from_parts(parts, Full::new(collected)))
}

/// L4 TCP / WebSocket chaos proxy (drops connections or injects per-chunk jitter).
pub async fn start_tcp_chaos_proxy(listen: SocketAddr, cfg: ChaosConfig) -> anyhow::Result<()> {
    let listener = TcpListener::bind(listen).await?;
    serve_tcp_chaos_proxy(listener, cfg).await
}

pub async fn serve_tcp_chaos_proxy(listener: TcpListener, cfg: ChaosConfig) -> anyhow::Result<()> {
    let counter = Arc::new(AtomicU64::new(0));

    loop {
        let (client, _) = listener.accept().await?;
        let cfg = cfg.clone();
        let seq = counter.fetch_add(1, Ordering::Relaxed);

        tokio::spawn(async move {
            let mut rng = ChaCha8Rng::seed_from_u64(cfg.seed ^ seq);
            if rng.gen_bool(cfg.drop_rate.clamp(0.0, 1.0)) {
                // Immediate deterministic TCP reset / drop
                drop(client);
                return;
            }

            let Ok(upstream) = TcpStream::connect(&cfg.upstream).await else {
                drop(client);
                return;
            };

            let (c_read, c_write) = client.into_split();
            let (u_read, u_write) = upstream.into_split();

            let c_to_u = pump_tcp_with_chaos(
                c_read,
                u_write,
                cfg.seed ^ seq ^ 0xA11C_E001,
                cfg.max_jitter_ms,
                cfg.drop_rate,
            );
            let u_to_c = pump_tcp_with_chaos(
                u_read,
                c_write,
                cfg.seed ^ seq ^ 0xB0B0_0002,
                cfg.max_jitter_ms,
                cfg.drop_rate,
            );

            let _ = tokio::join!(c_to_u, u_to_c);
        });
    }
}

async fn pump_tcp_with_chaos<R, W>(
    mut reader: R,
    mut writer: W,
    seed: u64,
    max_jitter_ms: u64,
    drop_rate: f64,
) where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let mut rng = ChaCha8Rng::seed_from_u64(seed);
    let mut buf = vec![0u8; 8192];

    loop {
        match reader.read(&mut buf).await {
            Ok(0) | Err(_) => break,
            Ok(n) => {
                if max_jitter_ms > 0 {
                    let delay = rng.gen_range(0..=max_jitter_ms);
                    tokio::time::sleep(Duration::from_millis(delay)).await;
                }
                if rng.gen_bool((drop_rate * 0.25).clamp(0.0, 1.0)) {
                    // Mid-stream deterministic drop
                    break;
                }
                if writer.write_all(&buf[..n]).await.is_err() {
                    break;
                }
            }
        }
    }
    let _ = writer.shutdown().await;
}