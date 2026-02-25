use crate::models::{OpenPort, TimingProfile};
use crate::report::LiveReporter;
use anyhow::{bail, Context, Result};
use futures::stream::{FuturesUnordered, StreamExt};
use ipnet::IpNet;
use std::collections::{BTreeSet, HashMap};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use tokio::net::{lookup_host, TcpStream as TokioTcpStream};
use tokio::sync::Semaphore;
use tokio::time::{timeout, Duration as TokioDuration, Instant};

const MAX_CONCURRENCY: usize = 2_048;

pub fn clamp_concurrency(value: usize) -> usize {
    value.min(MAX_CONCURRENCY).max(1)
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
    timing: TimingProfile,
    reporter: &LiveReporter,
) -> Vec<OpenPort> {
    let semaphore = Arc::new(Semaphore::new(clamp_concurrency(timing.concurrency)));
    let mut tasks = FuturesUnordered::new();
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
                let adjusted_timeout = dynamic_timeout.max(timing.timeout_ms);
                println!(
                    "[i] Latencia a {ip}: {}ms (timeout {}ms)",
                    rtt.as_millis(),
                    adjusted_timeout
                );
                adjusted_timeout
            }
            None => timing.timeout_ms,
        };

        timeout_by_ip.insert(ip, timeout_ms);
    }

    for &ip in targets {
        let ip_timeout_ms = timeout_by_ip.get(&ip).copied().unwrap_or(timing.timeout_ms);

        for &port in ports {
            let semaphore = Arc::clone(&semaphore);
            let timeout_ms = ip_timeout_ms;
            let retries = timing.retries;

            tasks.push(tokio::spawn(async move {
                let permit = match semaphore.acquire_owned().await {
                    Ok(permit) => permit,
                    Err(_) => return (ip, port, false),
                };

                let addr = SocketAddr::new(ip, port);
                let mut is_open = false;

                for attempt in 0..=retries {
                    let result = timeout(
                        TokioDuration::from_millis(timeout_ms),
                        TokioTcpStream::connect(addr),
                    )
                    .await;

                    match result {
                        Ok(Ok(stream)) => {
                            let is_self_connect = match (stream.local_addr(), stream.peer_addr()) {
                                (Ok(local), Ok(peer)) => local == peer,
                                _ => false,
                            };

                            if !is_self_connect {
                                is_open = true;
                                break;
                            }
                        }
                        _ => {}
                    }

                    if attempt < retries {
                        tokio::time::sleep(TokioDuration::from_millis(50)).await;
                    }
                }

                drop(permit);

                (ip, port, is_open)
            }));
        }
    }

    let mut open_ports = Vec::new();
    let mut found_count: usize = 0;
    let mut closed_count: usize = 0;

    while let Some(joined) = tasks.next().await {
        if let Ok((ip, port, is_open)) = joined {
            if is_open {
                found_count += 1;
                reporter.on_open(found_count, ip, port);
                open_ports.push(OpenPort { ip, port });
            } else {
                closed_count += 1;
                reporter.on_closed(found_count + closed_count, ip, port);
            }
        }
    }

    reporter.summary(found_count, closed_count, total_checks);

    open_ports.sort_by_key(|item| (item.ip, item.port));
    open_ports
}
