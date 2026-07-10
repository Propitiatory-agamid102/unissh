//! `unissh-server` binary: load config → init obs → connect the DB + migrations
//! → bring up axum (rustls TLS 1.3 or plain behind a reverse-proxy).

use std::net::SocketAddr;
use std::path::PathBuf;
use unissh_server::{Config, app, build_state, obs, time};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Minimal CLI: [serve|migrate] and --config <path>.
    let args: Vec<String> = std::env::args().collect();
    let mut config_path: Option<PathBuf> = None;
    let mut subcommand: Option<String> = None;
    let mut arg_by: Option<i64> = None;
    let mut arg_to: Option<i64> = None;
    let mut arg_tenant: Option<String> = None;
    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--config" | "-c" => {
                i += 1;
                if i < args.len() {
                    config_path = Some(PathBuf::from(&args[i]));
                }
            }
            "--by" => {
                i += 1;
                arg_by = args.get(i).and_then(|v| v.parse().ok());
            }
            "--to" => {
                i += 1;
                arg_to = args.get(i).and_then(|v| v.parse().ok());
            }
            "--tenant" => {
                i += 1;
                arg_tenant = args.get(i).cloned();
            }
            "migrate" | "serve" | "seq-bump" => subcommand = Some(args[i].clone()),
            other => eprintln!("unknown argument: {other}"),
        }
        i += 1;
    }

    let cfg_path = config_path.or_else(|| Some(PathBuf::from("config.toml")));
    let config =
        Config::load(cfg_path.as_deref()).map_err(|e| anyhow::anyhow!("config load: {e}"))?;

    obs::init_tracing(&config.obs);

    if subcommand.as_deref() == Some("migrate") {
        let store = unissh_server::Store::connect(&config.db).await?;
        store.migrate().await?;
        tracing::info!("migrations applied");
        return Ok(());
    }

    // Anti-rollback runbook (§14.3): after a restore from an old backup, raise
    // next_seq so report_version doesn't fall below client cursors (otherwise
    // a fatal TransportRollback). NEVER lowers it.
    //   seq-bump --by <delta>            (for ALL tenants: next_seq += delta)
    //   seq-bump --tenant <b64> --to <N> (raise a specific one to floor N)
    //   seq-bump --tenant <b64> --by <d> (raise a specific one by delta)
    if subcommand.as_deref() == Some("seq-bump") {
        use base64::Engine;
        let store = unissh_server::Store::connect(&config.db).await?;
        store.migrate().await?;
        let tenants: Vec<Vec<u8>> = match &arg_tenant {
            Some(t) => vec![
                base64::engine::general_purpose::STANDARD
                    .decode(t)
                    .map_err(|_| anyhow::anyhow!("--tenant must be base64"))?,
            ],
            None => store.list_tenant_ids().await?,
        };
        if tenants.is_empty() {
            println!("no tenants found");
            return Ok(());
        }
        for tid in &tenants {
            let (old, new) = if let Some(to) = arg_to {
                store.bump_next_seq_to(tid, to).await?
            } else if let Some(by) = arg_by {
                store.bump_next_seq_by(tid, by).await?
            } else {
                return Err(anyhow::anyhow!(
                    "seq-bump requires --by <delta> or --to <N>"
                ));
            };
            println!(
                "tenant {} : next_seq {} -> {}",
                base64::engine::general_purpose::STANDARD.encode(tid),
                old,
                new
            );
        }
        return Ok(());
    }

    // Whole-DB-snapshot anti-rollback (§16) is now enforced inside
    // `build_state` (below), so that in-process deployments are protected too.

    let metrics = obs::init_metrics();
    let bind: SocketAddr = config
        .server
        .bind
        .parse()
        .map_err(|e| anyhow::anyhow!("invalid server.bind {}: {e}", config.server.bind))?;

    // TLS plan (fail-fast on acme=true; previously it silently served plain HTTP).
    let tls = unissh_server::tls_plan(&config.server).map_err(|e| anyhow::anyhow!(e))?;
    let trust_proxy = config.server.trust_proxy;
    // Fail-closed: do not serve plain HTTP on a non-loopback address without a declared
    // TLS-terminating reverse-proxy (trust_proxy). This combination puts
    // bearer/ops tokens and ciphertext on an open channel. The documented Caddy
    // stack sets trust_proxy=true; a bare open bind is almost always a misconfig —
    // we refuse to come up rather than silently downgrade to cleartext.
    if matches!(tls, unissh_server::TlsPlan::Plain) && !bind.ip().is_loopback() && !trust_proxy {
        return Err(anyhow::anyhow!(
            "refusing to serve plain HTTP on non-loopback {bind} without TLS: set \
             server.tls_cert+tls_key, or server.trust_proxy=true if a reverse proxy \
             terminates TLS in front, or bind to 127.0.0.1"
        ));
    }
    let janitor_interval = config.session.janitor_interval_seconds.max(1);
    let idem_ttl = config.session.idempotency_ttl_seconds.max(0);
    let metrics_bind = config.obs.metrics_bind.clone();
    let has_metrics = metrics.is_some();

    let state = build_state(config, time::system_clock(), metrics).await?;

    // Prometheus /metrics — on a separate internal listener (§5.7/§13), NOT on
    // the public API port.
    if has_metrics {
        if let Ok(maddr) = metrics_bind.parse::<SocketAddr>() {
            let mstate = state.clone();
            tokio::spawn(async move {
                match tokio::net::TcpListener::bind(maddr).await {
                    Ok(l) => {
                        tracing::info!(%maddr, "metrics listening");
                        let _ = axum::serve(
                            l,
                            unissh_server::http::build_metrics_router(mstate).into_make_service(),
                        )
                        .await;
                    }
                    Err(e) => tracing::warn!(error = %e, "metrics listener bind failed"),
                }
            });
        }
    }

    // Background TTL-janitor (§13).
    {
        let st = state.clone();
        tokio::spawn(async move {
            let mut tick = tokio::time::interval(std::time::Duration::from_secs(janitor_interval));
            loop {
                tick.tick().await;
                let now = st.now();
                match st.store.cleanup_expired(now, now - idem_ttl).await {
                    Ok(()) => st
                        .last_janitor_run
                        .store(now, std::sync::atomic::Ordering::Relaxed),
                    Err(e) => tracing::warn!(error = %e, "janitor cleanup failed"),
                }
            }
        });
    }

    let make = app(state).into_make_service_with_connect_info::<SocketAddr>();

    match tls {
        unissh_server::TlsPlan::Rustls { cert, key } => {
            // Install the process-level crypto provider for rustls 0.23 (idempotent).
            let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
            let tls = axum_server::tls_rustls::RustlsConfig::from_pem_file(&cert, &key)
                .await
                .map_err(|e| anyhow::anyhow!("load TLS cert/key: {e}"))?;
            tracing::info!(%bind, "unissh-server listening (rustls TLS 1.3)");
            axum_server::bind_rustls(bind, tls).serve(make).await?;
        }
        unissh_server::TlsPlan::Plain => {
            tracing::warn!(
                %bind, trust_proxy,
                "unissh-server listening (plain HTTP — terminate TLS at a reverse proxy and set trust_proxy=true)"
            );
            axum_server::bind(bind).serve(make).await?;
        }
    }
    Ok(())
}
