use crate::models::{PortReport, ScriptResult, TimingProfile};
use crate::report::LiveReporter;
use crate::services::get_service_name;
use crate::wasm::WasmEngine;
use anyhow::{bail, Context, Result};
use futures::stream::{FuturesUnordered, StreamExt};
use ipnet::IpNet;
use std::collections::{BTreeSet, HashMap};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use tokio::task::JoinSet;
use tokio::io::AsyncWriteExt;
use tokio::net::{lookup_host, TcpStream as TokioTcpStream};
use tokio::sync::{Semaphore, mpsc};
use tokio::time::{timeout, Duration as TokioDuration, Instant};

const MAX_CONCURRENCY: usize = 2_048;
const TARPIT_MIN_SAMPLES: usize = 96;
const TARPIT_OPEN_MIN: usize = 80;
const TARPIT_STREAK_MIN: usize = 64;
const TARPIT_OPEN_RATIO_PERCENT: usize = 85;

pub fn clamp_concurrency(value: usize) -> usize {
    value.min(MAX_CONCURRENCY).max(1)
}

#[derive(Default)]
struct IpScanState {
    samples: AtomicUsize,
    open_hits: AtomicUsize,
    open_streak: AtomicUsize,
    tarpit_detected: AtomicBool,
}

impl IpScanState {
    fn should_abort(&self) -> bool {
        self.tarpit_detected.load(Ordering::Relaxed)
    }

    fn record_result(&self, is_open: bool) -> bool {
        let samples = self.samples.fetch_add(1, Ordering::Relaxed) + 1;

        let open_hits = if is_open {
            self.open_hits.fetch_add(1, Ordering::Relaxed) + 1
        } else {
            self.open_hits.load(Ordering::Relaxed)
        };

        let streak = if is_open {
            self.open_streak.fetch_add(1, Ordering::Relaxed) + 1
        } else {
            self.open_streak.store(0, Ordering::Relaxed);
            0
        };

        if samples < TARPIT_MIN_SAMPLES {
            return false;
        }

        let ratio = open_hits.saturating_mul(100) / samples.max(1);
        let suspicious = open_hits >= TARPIT_OPEN_MIN
            && streak >= TARPIT_STREAK_MIN
            && ratio >= TARPIT_OPEN_RATIO_PERCENT;

        if suspicious {
            return self
                .tarpit_detected
                .compare_exchange(false, true, Ordering::Relaxed, Ordering::Relaxed)
                .is_ok();
        }

        false
    }
}

fn connection_timeout_for_attempt(base_timeout_ms: u64, attempt: u32) -> u64 {
    let multiplier = 1u64 << attempt.min(3);
    let timeout_ms = base_timeout_ms.saturating_mul(multiplier);
    let hard_cap = base_timeout_ms.saturating_mul(6).saturating_add(300);
    timeout_ms.min(hard_cap)
}

fn backoff_delay_ms(ip: IpAddr, port: u16, attempt: u32) -> u64 {
    let base = 40u64;
    let growth = 1u64 << attempt.min(5);
    let jitter = deterministic_jitter(ip, port, attempt, 45);
    base.saturating_mul(growth).saturating_add(jitter).min(1_250)
}

fn deterministic_jitter(ip: IpAddr, port: u16, attempt: u32, max_jitter_ms: u64) -> u64 {
    let mut seed = port as u64 ^ ((attempt as u64) << 16);

    match ip {
        IpAddr::V4(ipv4) => {
            for octet in ipv4.octets() {
                seed = seed.rotate_left(5) ^ (octet as u64);
            }
        }
        IpAddr::V6(ipv6) => {
            for segment in ipv6.segments() {
                seed = seed.rotate_left(3) ^ (segment as u64);
            }
        }
    }

    seed % (max_jitter_ms.max(1))
}

pub async fn resolve_targets(target: &str) -> Result<Vec<IpAddr>> {
    if let Ok(ip) = target.parse::<IpAddr>() {
        return Ok(vec![ip]);
    }

    if target.contains('/') {
        let net: IpNet = target
            .parse()
            .with_context(|| format!("CIDR inválido: '{target}'"))?;

        return Ok(net.hosts().collect());
    }

    if let Some((start_text, end_text)) = target.split_once('-') {
        let start: Ipv4Addr = start_text
            .trim()
            .parse()
            .with_context(|| format!("IP inicial inválida: '{start_text}'"))?;
        let end: Ipv4Addr = end_text
            .trim()
            .parse()
            .with_context(|| format!("IP final inválida: '{end_text}'"))?;

        let start_u32 = u32::from(start);
        let end_u32 = u32::from(end);
        if start_u32 > end_u32 {
            bail!("Rango de IPs inválido: '{}'", target);
        }

        let ips = (start_u32..=end_u32)
            .map(|v| IpAddr::V4(Ipv4Addr::from(v)))
            .collect();

        return Ok(ips);
    }

    let mut resolved = BTreeSet::new();
    for socket in lookup_host((target, 0)).await? {
        resolved.insert(socket.ip());
    }

    Ok(resolved.into_iter().collect())
}

pub async fn measure_rtt(ip: IpAddr) -> Option<TokioDuration> {
    let start = Instant::now();
    let mut attempts = FuturesUnordered::new();

    for port in [80_u16, 443_u16, 22_u16] {
        let addr = SocketAddr::new(ip, port);
        attempts.push(async move {
            timeout(TokioDuration::from_secs(2), TokioTcpStream::connect(addr)).await
        });
    }

    while let Some(result) = attempts.next().await {
        match result {
            Ok(Ok(stream)) => {
                drop(stream);
                return Some(start.elapsed());
            }
            Ok(Err(error)) if error.kind() == std::io::ErrorKind::ConnectionRefused => {
                return Some(start.elapsed());
            }
            _ => {}
        }
    }

    None
}

pub async fn scan_targets(
    targets: &[IpAddr],
    ports: &[u16],
    hostname: Option<&str>,
    timing: TimingProfile,
    reporter: &LiveReporter,
    wasm_engine: Option<Arc<WasmEngine>>,
) -> Vec<PortReport> {
    let worker_count = clamp_concurrency(timing.concurrency);
    let total_checks = targets.len().saturating_mul(ports.len());

    let mut rtt_tasks = FuturesUnordered::new();
    for &ip in targets {
        rtt_tasks.push(async move { (ip, measure_rtt(ip).await) });
    }

    let mut timeout_by_ip = HashMap::with_capacity(targets.len());
    while let Some((ip, rtt)) = rtt_tasks.next().await {
        let timeout_ms = match rtt {
            Some(rtt) => {
                let dynamic_timeout = (rtt.as_millis() as u64)
                    .saturating_mul(3)
                    .saturating_div(2)
                    .saturating_add(20);
                let timeout_cap = timing.timeout_ms.saturating_mul(8).max(1_200);
                let adjusted_timeout = dynamic_timeout
                    .max(timing.timeout_ms)
                    .min(timeout_cap);
                reporter.println(format!(
                    "[i] Latencia a {ip}: {}ms (timeout {}ms)",
                    rtt.as_millis(),
                    adjusted_timeout
                ));
                adjusted_timeout
            }
            None => timing.timeout_ms,
        };

        timeout_by_ip.insert(ip, timeout_ms);
    }

    let mut jobs = Vec::with_capacity(total_checks);
    for &ip in targets {
        for &port in ports {
            jobs.push((ip, port));
        }
    }

    let job_cursor = Arc::new(AtomicUsize::new(0));
    let timeout_by_ip = Arc::new(timeout_by_ip);
    let ip_states: Arc<HashMap<IpAddr, Arc<IpScanState>>> = Arc::new(
        targets
            .iter()
            .copied()
            .map(|ip| (ip, Arc::new(IpScanState::default())))
            .collect(),
    );

    let channel_capacity = worker_count.saturating_mul(4).max(128);
    let (tx, mut rx) = mpsc::channel::<(IpAddr, u16, bool)>(channel_capacity);
    let jobs = Arc::new(jobs);

    let mut workers = FuturesUnordered::new();
    for _ in 0..worker_count {
        let tx = tx.clone();
        let job_cursor = Arc::clone(&job_cursor);
        let jobs = Arc::clone(&jobs);
        let timeout_by_ip = Arc::clone(&timeout_by_ip);
        let ip_states = Arc::clone(&ip_states);
        let retries = timing.retries;
        let reporter = reporter.clone();

        workers.push(tokio::spawn(async move {
            loop {
                let idx = job_cursor.fetch_add(1, Ordering::Relaxed);
                if idx >= jobs.len() {
                    break;
                }

                let (ip, port) = jobs[idx];
                let ip_state = match ip_states.get(&ip) {
                    Some(state) => Arc::clone(state),
                    None => continue,
                };

                if ip_state.should_abort() {
                    let _ = tx.send((ip, port, false)).await;
                    continue;
                }

                let timeout_ms = timeout_by_ip.get(&ip).copied().unwrap_or(timing.timeout_ms);
                let addr = SocketAddr::new(ip, port);
                let mut is_open = false;

                for attempt in 0..=retries {
                    if ip_state.should_abort() {
                        break;
                    }

                    let current_timeout = connection_timeout_for_attempt(timeout_ms, attempt);

                    let result = timeout(
                        TokioDuration::from_millis(current_timeout),
                        TokioTcpStream::connect(addr),
                    )
                    .await;

                    if let Ok(Ok(mut stream)) = result {
                        let is_self_connect = match (stream.local_addr(), stream.peer_addr()) {
                            (Ok(local), Ok(peer)) => local == peer,
                            _ => false,
                        };

                        let _ = stream.shutdown().await;

                        if !is_self_connect {
                            is_open = true;
                            break;
                        }
                    }

                    if attempt < retries {
                        let sleep_ms = backoff_delay_ms(ip, port, attempt);
                        tokio::time::sleep(TokioDuration::from_millis(sleep_ms)).await;
                    }
                }

                let tarpit_now = ip_state.record_result(is_open);
                if tarpit_now {
                    reporter.warn(format!(
                        "[!] Posible TCP tarpitting detectado en {ip}; abortando puertos restantes para este host."
                    ));
                }

                if tx.send((ip, port, is_open)).await.is_err() {
                    break;
                }
            }
        }));
    }

    drop(tx);

    let mut reports = Vec::new();
    let mut found_count: usize = 0;
    let mut closed_count: usize = 0;
    let mut script_jobs = JoinSet::new();
    let scan_hostname = hostname.map(|value| value.to_string());
    let script_semaphore = std::sync::Arc::new(Semaphore::new(15));

    while let Some((ip, port, is_open)) = rx.recv().await {
        if is_open {
            found_count += 1;
            let detection_index = found_count;

            if let Some(engine) = &wasm_engine {
                let permit = script_semaphore
                    .clone()
                    .acquire_owned()
                    .await
                    .expect("script semaphore closed");
                let reporter_clone = reporter.clone();
                let engine = Arc::clone(engine);
                let pb = reporter.add_scanning_spinner(ip, port);
                let scan_hostname = scan_hostname.clone();

                script_jobs.spawn(async move {
                    let script_results = match tokio::task::spawn_blocking(move || {
                        engine.run_scripts(ip, port, scan_hostname.as_deref())
                    })
                    .await
                    {
                        Ok(Ok(results)) => results,
                        Ok(Err(error)) => vec![ScriptResult {
                            script: "wasm-engine".to_string(),
                            status: "error".to_string(),
                            details: format!("{error:#}"),
                        }],
                        Err(error) => vec![ScriptResult {
                            script: "wasm-worker".to_string(),
                            status: "error".to_string(),
                            details: format!("{error}"),
                        }],
                    };

                    reporter_clone.finish_spinner(pb, detection_index, ip, port, &script_results);
                    drop(permit);

                    PortReport {
                        ip,
                        port,
                        state: "open",
                        service_name: get_service_name(port),
                        scripts: script_results,
                    }
                });
            } else {
                reporter.on_open(detection_index, ip, port);
                reports.push(PortReport {
                    ip,
                    port,
                    state: "open",
                    service_name: get_service_name(port),
                    scripts: Vec::new(),
                });
            }
        } else {
            closed_count += 1;
            reporter.on_closed(found_count + closed_count, ip, port);
        }
    }

    while let Some(joined) = workers.next().await {
        if let Err(error) = joined {
            reporter.warn(format!("[!] Worker de escaneo abortado: {error}"));
        }
    }

    while let Some(job_result) = script_jobs.join_next().await {
        match job_result {
            Ok(report) => reports.push(report),
            Err(error) => reporter.warn(format!("[!] Worker de scripts abortado: {error}")),
        }
    }

    reporter.summary(found_count, closed_count, total_checks);

    reports.sort_by_key(|item| (item.ip, item.port));
    reports
}
