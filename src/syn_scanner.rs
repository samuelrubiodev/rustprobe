use crate::services::get_service_name;
use crate::report::LiveReporter;
use anyhow::{bail, Context, Result};
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::tcp::{ipv4_checksum, MutableTcpPacket, TcpFlags, TcpOption, TcpPacket};
use pnet::transport::{
    tcp_packet_iter, transport_channel, TransportChannelType::Layer4, TransportProtocol::Ipv4,
};
use std::collections::HashSet;
use crate::models::{PortReport, TimingProfile};
use std::net::{IpAddr, Ipv4Addr, UdpSocket};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::time::{sleep, Duration};

pub async fn run_syn_scan(
    targets: &[IpAddr],
    ports: &[u16],
    timing: TimingProfile,
    reporter: &LiveReporter,
) -> Result<Vec<PortReport>> {
    if !has_raw_socket_privileges() {
        bail!(
            "El escaneo SYN (-sS) requiere privilegios de Administrador o Root para usar Raw Sockets"
        );
    }

    let ipv4_targets: Vec<Ipv4Addr> = targets
        .iter()
        .filter_map(|ip| match ip {
            IpAddr::V4(v4) => Some(*v4),
            IpAddr::V6(_) => None,
        })
        .collect();

    if ipv4_targets.is_empty() {
        bail!("El escaneo SYN actualmente solo soporta objetivos IPv4");
    }

    if ports.is_empty() {
        return Ok(Vec::new());
    }

    let protocol = Layer4(Ipv4(IpNextHeaderProtocols::Tcp));
    let (mut tx, mut rx) =
        transport_channel(65_536, protocol).context("No se pudo crear canal de transporte TCP")?;

    let src_port = 40_000 + (std::process::id() % 20_000) as u16;

    let stop_radar = Arc::new(AtomicBool::new(false));
    let open_hits: Arc<Mutex<Vec<(Ipv4Addr, u16)>>> = Arc::new(Mutex::new(Vec::new()));

    let radar_stop = Arc::clone(&stop_radar);
    let radar_hits = Arc::clone(&open_hits);
    let radar_handle = std::thread::spawn(move || {
        let mut packet_iter = tcp_packet_iter(&mut rx);

        while !radar_stop.load(Ordering::Relaxed) {
            match packet_iter.next() {
                Ok((tcp_packet, source_addr)) => {
                    let flags = tcp_packet.get_flags();
                    let is_syn_ack = (flags & (TcpFlags::SYN | TcpFlags::ACK))
                        == (TcpFlags::SYN | TcpFlags::ACK);

                    if is_syn_ack && tcp_packet.get_destination() == src_port {
                        let source_ip = match source_addr {
                            IpAddr::V4(v4) => v4,
                            IpAddr::V6(_) => continue,
                        };

                        if let Ok(mut guard) = radar_hits.lock() {
                            guard.push((source_ip, tcp_packet.get_source()));
                        }
                    }
                }
                Err(error) => match error.kind() {
                    std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut => continue,
                    _ => continue,
                },
            }
        }
    });

    let burst_size = timing.concurrency.clamp(32, 256);
    let max_retries = timing.retries.max(1);
    let mut sent_count: usize = 0;

    for &dst_ip in &ipv4_targets {
        let Some(src_ip) = get_source_ip(dst_ip) else {
            continue;
        };

        for &dst_port in ports {
            for _attempt in 0..=max_retries {
                let mut packet_buf = [0u8; 20];
                let packet_len =
                    build_syn_packet(src_ip, dst_ip, src_port, dst_port, &mut packet_buf);

                if let Some(packet) = TcpPacket::new(&packet_buf[..packet_len]) {
                    let _ = tx.send_to(packet, IpAddr::V4(dst_ip));
                }

                sent_count += 1;
                if sent_count % burst_size == 0 {
                    sleep(Duration::from_millis(1)).await;
                }

                if timing.concurrency <= 64 {
                    sleep(Duration::from_micros(500)).await;
                }
            }
        }
    }

    let drain_ms = timing
        .timeout_ms
        .saturating_mul(max_retries as u64 + 1)
        .max(2_000)
        .min(8_000);
    sleep(Duration::from_millis(drain_ms)).await;
    stop_radar.store(true, Ordering::Relaxed);

    let _ = std::net::TcpStream::connect((Ipv4Addr::LOCALHOST, 9));
    let _ = radar_handle.join();

    let hits = open_hits
        .lock()
        .map(|guard| guard.clone())
        .unwrap_or_default();
    let open_set: HashSet<(Ipv4Addr, u16)> = hits.into_iter().collect();

    let mut reports = Vec::new();
    for &ip in &ipv4_targets {
        for &port in ports {
            if open_set.contains(&(ip, port)) {
                reports.push(PortReport {
                    ip: IpAddr::V4(ip),
                    port,
                    state: "open",
                    service_name: get_service_name(port),
                    scripts: Vec::new(),
                });
            }
        }
    }

    reports.sort_by_key(|r| (r.ip, r.port));
    for (index, report) in reports.iter().enumerate() {
        reporter.on_open(index + 1, report.ip, report.port);
    }

    Ok(reports)
}

fn get_source_ip(target: Ipv4Addr) -> Option<Ipv4Addr> {
    let socket = UdpSocket::bind("0.0.0.0:0").ok()?;
    socket.connect((target, 80)).ok()?;

    match socket.local_addr().ok()?.ip() {
        IpAddr::V4(ipv4) => Some(ipv4),
        IpAddr::V6(_) => None,
    }
}

fn build_syn_packet(
    src_ip: Ipv4Addr,
    dst_ip: Ipv4Addr,
    src_port: u16,
    dst_port: u16,
    packet_buf: &mut [u8],
) -> usize {
    let mut tcp_packet = MutableTcpPacket::new(packet_buf).expect("buffer TCP inválido");
    let sequence = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.subsec_nanos())
        .unwrap_or(0);

    tcp_packet.set_source(src_port);
    tcp_packet.set_destination(dst_port);
    tcp_packet.set_sequence(sequence);
    tcp_packet.set_data_offset(5);
    tcp_packet.set_flags(TcpFlags::SYN);
    tcp_packet.set_window(1024);
    tcp_packet.set_urgent_ptr(0);
    tcp_packet.set_options(&[] as &[TcpOption]);
    tcp_packet.set_checksum(0);

    let checksum = ipv4_checksum(&tcp_packet.to_immutable(), &src_ip, &dst_ip);
    tcp_packet.set_checksum(checksum);

    (tcp_packet.get_data_offset() as usize) * 4
}

fn has_raw_socket_privileges() -> bool {
    #[cfg(unix)]
    {
        nix::unistd::Uid::effective().is_root()
    }

    #[cfg(windows)]
    {
        is_windows_admin().unwrap_or(false)
    }

    #[cfg(not(any(unix, windows)))]
    {
        false
    }
}

#[cfg(windows)]
fn is_windows_admin() -> Option<bool> {
    use std::process::Command;

    let output = Command::new("powershell")
        .args([
            "-NoProfile",
            "-Command",
            "[bool]([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)",
        ])
        .output()
        .ok()?;

    if !output.status.success() {
        return None;
    }

    let stdout = String::from_utf8(output.stdout).ok()?;
    Some(stdout.trim().eq_ignore_ascii_case("true"))
}
