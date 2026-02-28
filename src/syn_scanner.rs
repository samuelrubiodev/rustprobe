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

    // ── Topology detection ────────────────────────────────────────────────────
    //
    // Whether all targets sit on the local network (RFC 1918 / loopback)
    // determines the RTT estimate.  Local NICs respond in <5 ms; a WAN hop
    // through a NAT + firewall can be 100–300 ms.  Every timeout we derive
    // below is proportional to this estimate, so the scan is neither lazy on
    // LAN nor impatient on the Internet.
    let all_local = ipv4_targets.iter().all(|ip| is_rfc1918(*ip));

    // Conservative RTT estimate.
    //   Local  → 5 ms  (covers any VM hypervisor jitter)
    //   Remote → half of timing.timeout_ms, floor 50 ms
    let rtt_ms: u64 = if all_local {
        5
    } else {
        (timing.timeout_ms / 2).max(50)
    };

    // How long to sleep after the LAST SYN before starting the final drain.
    // 3× RTT gives even the slowest in-flight SYN-ACK time to arrive.
    let grace_ms: u64 = rtt_ms.saturating_mul(3).max(if all_local { 50 } else { 300 });

    // Quiet window: if no new hit arrives within this time the drain is done.
    let quiet_ms: u64 = rtt_ms.max(30);

    // Hard cap for the inter-pass drain (prevents it stalling on a retry loop).
    let pass_cap_ms: u64 = rtt_ms.saturating_mul(4).max(200);

    // Hard cap for the final drain.
    let final_cap_ms: u64 = rtt_ms.saturating_mul(8).max(500);

    // ── AIMD rate control ─────────────────────────────────────────────────────
    //
    // We pace sends using a deadline-per-packet model rather than burst+sleep.
    // `current_pps` is the live send rate (packets / second).
    //   On ENOBUFS (kernel TX queue full): halve it  (multiplicative decrease).
    //   Every 512 clean sends: nudge it +5% toward target_pps              (additive increase).
    //
    //   This is exactly TCP AIMD: aggressive reaction to congestion, gentle
    //   probe when things are going well.
    let target_pps: u64 = timing.concurrency.max(1) as u64;
    let mut current_pps: u64 = target_pps;
    let mut good_streak: u64 = 0;

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
    // Deadline-based rate limiting: instead of sleep-after-N-packets we
    // track exactly when the next packet should go out.  Sleeping only the
    // delta between now and that deadline gives sub-millisecond pacing
    // accuracy with no accumulation of drift across thousands of ports.
    //
    // Multiple passes (retries) ensure reliability: ports that got a dropped
    // SYN on pass 1 are retried on pass 2, etc.
    let num_passes = timing.retries.max(1) as usize + 1;
    let mut buf = [0u8; 24]; // 20-byte TCP base + 4-byte MSS option
    let mut open_set: HashSet<(Ipv4Addr, u16)> = HashSet::new();
    let mut hits_reported: usize = 0;
    let mut next_send = Instant::now();

    for pass in 0..num_passes {
        for (idx, &dst_ip) in ipv4_targets.iter().enumerate() {
            let Some(src_ip) = src_ips[idx] else { continue; };

            for &dst_port in ports {
                build_syn_packet(src_ip, dst_ip, src_port, dst_port, &mut buf);

                // Wait until the rate-limit deadline before sending.
                let now = Instant::now();
                if now < next_send {
                    std::thread::sleep(next_send - now);
                }

                // Attempt to send; back off with AIMD on kernel congestion.
                let mut retries_left = 8u8;
                loop {
                    let pkt = TcpPacket::new(&buf).expect("buffer TCP inválido");
                    match tx.send_to(pkt, IpAddr::V4(dst_ip)) {
                        Ok(_) => {
                            good_streak += 1;
                            // Additive increase: every 512 clean sends nudge
                            // current_pps 5% closer to the original target.
                            if good_streak % 512 == 0 && current_pps < target_pps {
                                current_pps =
                                    (current_pps + (target_pps / 20).max(1)).min(target_pps);
                            }
                            break;
                        }
                        Err(e)
                            if e.raw_os_error() == Some(enobufs_code())
                                && retries_left > 0 =>
                        {
                            retries_left -= 1;
                            good_streak = 0;
                            // Multiplicative decrease: halve the rate, floor 50 pps.
                            current_pps = (current_pps / 2).max(50);
                            // Sleep one inter-packet interval at the new reduced
                            // rate to let the kernel TX queue drain.
                            std::thread::sleep(Duration::from_micros(
                                (1_000_000 / current_pps).min(20_000),
                            ));
                        }
                        Err(_) => break, // unrecoverable; skip this port
                    }
                }

                // Advance the deadline by one inter-packet interval so the
                // next iteration naturally waits the right amount.
                next_send = Instant::now()
                    + Duration::from_micros(1_000_000 / current_pps.max(1));
            }
        }

        // Drain replies accumulated during this pass before the next wave.
        // On the final pass the grace sleep below will catch stragglers.
        let _ = pass; // suppress unused-variable warning in release mode
        drain_channel(
            &hit_rx,
            &mut open_set,
            quiet_ms,
            pass_cap_ms,
            reporter,
            &mut hits_reported,
        );
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
