use crate::models::{OpenPort, TimingProfile};
use crate::report::LiveReporter;
use anyhow::{bail, Context, Result};
use futures::stream::{FuturesUnordered, StreamExt};
use ipnet::IpNet;
use std::collections::BTreeSet;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use tokio::net::{lookup_host, TcpStream as TokioTcpStream};
use tokio::sync::Semaphore;
use tokio::time::{timeout, Duration as TokioDuration};

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

pub async fn scan_targets(
    targets: &[IpAddr],
    ports: &[u16],
    timing: TimingProfile,
    reporter: &LiveReporter,
) -> Vec<OpenPort> {
    let semaphore = Arc::new(Semaphore::new(clamp_concurrency(timing.concurrency)));
    let mut tasks = FuturesUnordered::new();
    let total_checks = targets.len().saturating_mul(ports.len());

    for &ip in targets {
        for &port in ports {
            let semaphore = Arc::clone(&semaphore);
            let timeout_ms = timing.timeout_ms;

            tasks.push(tokio::spawn(async move {
                let permit = match semaphore.acquire_owned().await {
                    Ok(permit) => permit,
                    Err(_) => return (ip, port, false),
                };

                let addr = SocketAddr::new(ip, port);
                let result = timeout(
                    TokioDuration::from_millis(timeout_ms),
                    TokioTcpStream::connect(addr),
                )
                .await;

                drop(permit);

                match result {
                    Ok(Ok(stream)) => {
                        let is_self_connect = match (stream.local_addr(), stream.peer_addr()) {
                            (Ok(local), Ok(peer)) => local == peer,
                            _ => false,
                        };

                        if is_self_connect {
                            (ip, port, false)
                        } else {
                            (ip, port, true)
                        }
                    }
                    _ => (ip, port, false),
                }
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
