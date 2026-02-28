use crate::models::{PortReport, TimingProfile};
use crate::report::LiveReporter;
use crate::services::get_service_name;
use anyhow::{bail, Context, Result};
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::tcp::{ipv4_checksum, MutableTcpPacket, TcpFlags, TcpOption, TcpPacket};
use pnet::transport::{
    tcp_packet_iter, transport_channel, TransportChannelType::Layer4, TransportProtocol::Ipv4,
};
use std::collections::HashSet;
use std::net::{IpAddr, Ipv4Addr, UdpSocket};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tokio::time::sleep;

// 4 MB RX ring so a burst of SYN-ACKs never overflows the kernel buffer.
const RX_BUFFER_BYTES: usize = 4 * 1024 * 1024;

// ── Public entry point ────────────────────────────────────────────────────────

pub async fn run_syn_scan(
    targets: &[IpAddr],
    ports: &[u16],
    timing: TimingProfile,
    reporter: &LiveReporter,
) -> Result<Vec<PortReport>> {
    if !has_raw_socket_privileges() {
        bail!(
            "El escaneo SYN (-sS) requiere privilegios de Administrador o Root \
             para usar Raw Sockets"
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

    // ── Timing (derived entirely from TimingProfile) ───────────────────────────
    //
    // After the very last SYN we must wait at least timing.timeout_ms before
    // calling a port "closed/filtered".  That is what the user chose when
    // selecting T1..T5 — we respect it unconditionally (no local cap).
    let grace_ms: u64 = timing.timeout_ms;

    // Quiet window for the final drain: stop when silent for this long.
    let quiet_ms: u64 = (timing.timeout_ms / 5).clamp(50, 1_000);

    // Hard cap for the final drain (should never fire in practice).
    let final_cap_ms: u64 = timing.timeout_ms.saturating_mul(3).max(1_000);

    // ── Inter-packet gap for WAN scans ─────────────────────────────────────
    //
    // On LAN (RFC1918/loopback) we blast at wire speed — no WAF, no NAT
    // throttle, and the hypervisor NIC can absorb the burst.
    //
    // On WAN we spread the full send phase across 20% of timeout_ms so that
    // stateful firewalls and WAFs see a realistic packet rate instead of a
    // 100 kpps burst that instantly triggers a block.
    //   T3 (800 ms), 8 000 ports → 160 000 µs / 8 000 = 20 µs/pkt = 50 kpps
    //   T5 (120 ms), 8 000 ports →  24 000 µs / 8 000 =  3 µs/pkt (capped at 1)
    //   T1 (2500ms), 8 000 ports → 500 000 µs / 8 000 = 62 µs/pkt = 16 kpps
    let all_local = ipv4_targets.iter().all(|ip| is_rfc1918(*ip));
    let total_syns_per_pass = (ipv4_targets.len() * ports.len()).max(1);
    let ipt_us: u64 = if all_local {
        0 // wire speed on LAN
    } else {
        let budget_us = (timing.timeout_ms * 1_000) / 5; // 20% of timeout
        (budget_us / total_syns_per_pass as u64).max(1)
    };

    // ── Wire-speed send with ENOBUFS back-off ────────────────────────────────
    //
    // `throttle_us` starts at 0.  On ENOBUFS it doubles (floor 1 ms, cap 50 ms).
    // Each clean send sheds 2% until it returns to 0.
    // When non-zero it overrides ipt_us (congestion takes priority).
    let mut throttle_us: u64 = 0;

    // ── Transport channel ─────────────────────────────────────────────────────
    let protocol = Layer4(Ipv4(IpNextHeaderProtocols::Tcp));
    let (mut tx, mut rx) = transport_channel(RX_BUFFER_BYTES, protocol)
        .context("No se pudo crear canal de transporte TCP (¿privilegios insuficientes?)")?;

    // ── Fixed source port ─────────────────────────────────────────────────────
    //
    // Every SYN in this session shares the same source port so the NAT/firewall
    // keeps a single conntrack entry and routes all SYN-ACKs back to us.
    // Derived from PID × subsecond nanos to avoid collisions between
    // concurrent scanner instances without needing a `rand` dependency.
    let src_port: u16 = {
        let pid   = std::process::id() as u64;
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.subsec_nanos() as u64)
            .unwrap_or(0xDEAD_BEEF);
        let mixed = pid ^ nanos ^ (pid.wrapping_shl(13)) ^ (nanos.wrapping_shr(7));
        32_768_u16 + (mixed % 28_232) as u16
    };

    // ── Radar thread ──────────────────────────────────────────────────────────
    //
    // Spawned BEFORE the first SYN leaves so we never miss an early reply.
    // Forwards every (src_ip, src_port) tuple of SYN-ACK packets aimed at
    // our source port through an mpsc channel to the main thread.
    // Exits cleanly when the channel receiver is dropped at end of scope.
    let valid_targets: HashSet<Ipv4Addr> = ipv4_targets.iter().cloned().collect();
    let (hit_tx, hit_rx) = std::sync::mpsc::channel::<(Ipv4Addr, u16)>();

    std::thread::spawn(move || {
        let mut iter = tcp_packet_iter(&mut rx);
        loop {
            match iter.next() {
                Ok((pkt, src_addr)) => {
                    let flags = pkt.get_flags();
                    let is_syn_ack = (flags & (TcpFlags::SYN | TcpFlags::ACK))
                        == (TcpFlags::SYN | TcpFlags::ACK);
                    if is_syn_ack && pkt.get_destination() == src_port {
                        if let IpAddr::V4(v4) = src_addr {
                            if valid_targets.contains(&v4) {
                                if hit_tx.send((v4, pkt.get_source())).is_err() {
                                    break; // receiver dropped → main is done
                                }
                            }
                        }
                    }
                }
                Err(e) => {
                    use std::io::ErrorKind::*;
                    match e.kind() {
                        Interrupted | WouldBlock | TimedOut => continue,
                        _ => break, // fatal socket error
                    }
                }
            }
        }
    });

    // ── Source IP cache ───────────────────────────────────────────────────────
    //
    // Resolve once per target using a connected UDP socket (no traffic sent).
    // Targets that cannot be routed are skipped with a visible warning.
    let src_ips: Vec<Option<Ipv4Addr>> = ipv4_targets
        .iter()
        .map(|&dst| match get_source_ip(dst) {
            Some(ip) if ip.is_unspecified() => {
                eprintln!("[SYN] WARN: no route to {dst}, skipping");
                None
            }
            None => {
                eprintln!("[SYN] WARN: could not determine source IP for {dst}, skipping");
                None
            }
            ok => ok,
        })
        .collect();

    if src_ips.iter().all(|s| s.is_none()) {
        bail!("No se pudo determinar la IP de origen para ningún objetivo. ¿Hay ruta de red?");
    }

    // ── Send loop ─────────────────────────────────────────────────────────────
    //
    // `num_passes` = user's retry count + 1 initial pass.
    // Multiple passes improve reliability on lossy paths: a SYN dropped in
    // pass 1 gets a second chance in pass 2 without re-creating the channel.
    let num_passes = timing.retries as usize + 1;
    let mut buf = [0u8; 24]; // 20-byte TCP base + 4-byte MSS option
    let mut open_set: HashSet<(Ipv4Addr, u16)> = HashSet::new();
    let mut hits_reported: usize = 0;

    for _pass in 0..num_passes {
        for (idx, &dst_ip) in ipv4_targets.iter().enumerate() {
            let Some(src_ip) = src_ips[idx] else { continue; };

            for &dst_port in ports {
                build_syn_packet(src_ip, dst_ip, src_port, dst_port, &mut buf);

                // Normal inter-packet pacing (WAN only; 0 on LAN).
                // ENOBUFS throttle overrides when active.
                let sleep_us = if throttle_us > 0 {
                    let t = throttle_us;
                    throttle_us = throttle_us.saturating_sub(throttle_us / 50 + 1);
                    t
                } else {
                    ipt_us
                };
                if sleep_us > 0 {
                    std::thread::sleep(Duration::from_micros(sleep_us));
                }

                // Send; back off on ENOBUFS (kernel TX queue full).
                let mut retries_left = 8u8;
                loop {
                    let pkt = TcpPacket::new(&buf).expect("buffer TCP inválido");
                    match tx.send_to(pkt, IpAddr::V4(dst_ip)) {
                        Ok(_) => break,
                        Err(e)
                            if e.raw_os_error() == Some(enobufs_code())
                                && retries_left > 0 =>
                        {
                            retries_left -= 1;
                            // Multiplicative back-off: double throttle (floor 1 ms,
                            // cap 50 ms = 20 pps).  Let the kernel TX queue drain
                            // for exactly that long before retrying.
                            throttle_us = (throttle_us.max(1_000) * 2).min(50_000);
                            std::thread::sleep(Duration::from_micros(throttle_us));
                        }
                        Err(_) => break, // unrecoverable; skip this port
                    }
                }
            }
        }

        // Non-blocking flush: drain everything already queued in the channel
        // without any waiting.  All real waiting happens in the grace sleep
        // below.  This keeps passes back-to-back (no stalling between waves).
        while let Ok(hit) = hit_rx.try_recv() {
            if open_set.insert(hit) {
                hits_reported += 1;
                reporter.on_open(hits_reported, IpAddr::V4(hit.0), hit.1);
            }
        }
    }

    // ── Grace period ──────────────────────────────────────────────────────────
    //
    // Async sleep (tokio) frees the worker thread while the radar keeps
    // receiving.  Gives in-flight SYN-ACKs time to arrive before the final drain.
    sleep(Duration::from_millis(grace_ms)).await;

    drain_channel(
        &hit_rx,
        &mut open_set,
        quiet_ms,
        final_cap_ms,
        reporter,
        &mut hits_reported,
    );
    // Dropping hit_rx closes the channel → radar thread exits cleanly.

    // ── Build report ──────────────────────────────────────────────────────────
    let mut reports: Vec<PortReport> = Vec::new();
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
    Ok(reports)
}

// ── Private helpers ───────────────────────────────────────────────────────────

/// Receive hits until quiet for `quiet_ms` OR `max_ms` total have elapsed.
/// Deduplicates and calls `reporter.on_open` for each genuinely new port.
fn drain_channel(
    rx: &std::sync::mpsc::Receiver<(Ipv4Addr, u16)>,
    set: &mut HashSet<(Ipv4Addr, u16)>,
    quiet_ms: u64,
    max_ms: u64,
    reporter: &LiveReporter,
    counter: &mut usize,
) {
    use std::sync::mpsc::RecvTimeoutError;
    let hard  = Instant::now() + Duration::from_millis(max_ms);
    let mut quiet = Instant::now() + Duration::from_millis(quiet_ms);

    loop {
        let now = Instant::now();
        if now >= hard { break; }
        let timeout = quiet.min(hard).saturating_duration_since(now);
        match rx.recv_timeout(timeout) {
            Ok(hit) => {
                if set.insert(hit) {
                    *counter += 1;
                    reporter.on_open(*counter, IpAddr::V4(hit.0), hit.1);
                }
                quiet = Instant::now() + Duration::from_millis(quiet_ms);
            }
            Err(RecvTimeoutError::Timeout)      => break,
            Err(RecvTimeoutError::Disconnected)  => break,
        }
    }
}

/// Build a SYN packet into `buf` (24 bytes = 20-byte TCP header + 4-byte MSS).
///
/// MSS 1460 (Ethernet standard) is included so the packet looks identical to
/// one emitted by a real OS kernel.  WAFs and stateful firewalls routinely
/// drop option-less SYNs as scanner fingerprints.
fn build_syn_packet(
    src_ip: Ipv4Addr,
    dst_ip: Ipv4Addr,
    src_port: u16,
    dst_port: u16,
    buf: &mut [u8; 24],
) {
    buf.fill(0);
    let mut pkt = MutableTcpPacket::new(buf).expect("buffer TCP inválido");
    // Randomise the sequence number per packet to reduce fingerprinting.
    let seq = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.subsec_nanos())
        .unwrap_or(0);
    let mss = TcpOption::mss(1460);
    pkt.set_source(src_port);
    pkt.set_destination(dst_port);
    pkt.set_sequence(seq);
    pkt.set_acknowledgement(0);
    pkt.set_data_offset(6); // 6 × 4 = 24 bytes
    pkt.set_reserved(0);
    pkt.set_flags(TcpFlags::SYN);
    pkt.set_window(64_240); // standard Linux advertised window
    pkt.set_urgent_ptr(0);
    pkt.set_options(&[mss]);
    pkt.set_checksum(0); // must be zero before ipv4_checksum
    let cs = ipv4_checksum(&pkt.to_immutable(), &src_ip, &dst_ip);
    pkt.set_checksum(cs);
}

/// Returns the source IP the OS routing table would use to reach `target`.
/// A connected UDP socket is used — zero bytes are actually transmitted.
fn get_source_ip(target: Ipv4Addr) -> Option<Ipv4Addr> {
    let sock = UdpSocket::bind("0.0.0.0:0").ok()?;
    sock.connect((target, 80)).ok()?;
    match sock.local_addr().ok()?.ip() {
        IpAddr::V4(v4) => Some(v4),
        IpAddr::V6(_) => None,
    }
}

/// True if `ip` is an RFC 1918 private address, loopback, or link-local.
/// Used to detect local-network scans and apply more aggressive timing.
fn is_rfc1918(ip: Ipv4Addr) -> bool {
    let o = ip.octets();
    matches!(
        o,
        [10, ..]
            | [172, 16..=31, ..]
            | [192, 168, ..]
            | [127, ..]
            | [169, 254, ..]
    )
}

/// Platform ENOBUFS error code (kernel TX queue full).
#[inline]
fn enobufs_code() -> i32 {
    if cfg!(unix) { 105 } else if cfg!(windows) { 10055 } else { -1 }
}

// ── Privilege checks ──────────────────────────────────────────────────────────

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
    let out = Command::new("powershell")
        .args([
            "-NoProfile",
            "-Command",
            "[bool]([Security.Principal.WindowsPrincipal] \
             [Security.Principal.WindowsIdentity]::GetCurrent())\
             .IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)",
        ])
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    Some(
        String::from_utf8(out.stdout)
            .ok()?
            .trim()
            .eq_ignore_ascii_case("true"),
    )
}
