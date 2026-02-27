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
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::time::{sleep, Duration};

// ── Tuning constants ────────────────────────────────────────────────────────

/// Kernel RX socket buffer.  64 KB overflows on any real scan; 4 MB is safe.
const RX_BUFFER_BYTES: usize = 4 * 1024 * 1024;

/// Number of SYN packets to send before yielding to the OS network stack.
/// Keeping this ≤ 64 prevents ENOBUFS on most kernels/NICs.
const BURST_SIZE: usize = 64;

/// Pause between bursts (ms).  2 ms lets the NIC queue drain without making
/// an 8 000-port scan noticeably slower (~250 ms overhead total).
const BURST_PAUSE_MS: u64 = 2;

/// Adaptive drain – stop early if no new hit arrives within this window.
/// 200 ms is generous for LAN; remote SYN-ACKs also arrive well within this.
const DRAIN_QUIET_MS: u64 = 200;

/// Hard cap for the drain phase regardless of how frequent the hits are.
/// Keeps the total scan time bounded even on very noisy networks.
const DRAIN_MAX_MS: u64 = 2_000;

/// Max back-off retries when the kernel returns ENOBUFS.
const ENOBUFS_RETRIES: u8 = 5;

// ── Public entry point ──────────────────────────────────────────────────────

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

    // ── 1. Transport channel ────────────────────────────────────────────────
    //
    // Layer4/Ipv4/Tcp: we write/read raw TCP headers; the kernel handles IP.
    // A 4 MB RX buffer handles bursts of SYN-ACKs without loss.
    let protocol = Layer4(Ipv4(IpNextHeaderProtocols::Tcp));
    let (mut tx, mut rx) = transport_channel(RX_BUFFER_BYTES, protocol)
        .context("No se pudo crear canal de transporte TCP (¿privilegios insuficientes?)")?;

    // ── 2. Fixed source port ────────────────────────────────────────────────
    //
    // A stable, non-zero source port is MANDATORY for external scans:
    // the router/NAT must see the same sport in every SYN so it can route
    // the SYN-ACK replies back to us.
    let src_port: u16 = 40_000 + (std::process::id() % 20_000) as u16;

    // ── 3. Spin up the radar BEFORE the first packet leaves ─────────────────
    //
    // pnet 0.34's next() is a blocking call with no built-in timeout.
    // We use an mpsc channel instead:
    //   • radar thread sends every SYN-ACK hit to `hit_tx`
    //   • main thread drains `hit_rx` with recv_timeout(drain_window)
    //   • when main drops `hit_rx` the channel closes; the thread's next
    //     send() returns Err and the thread exits cleanly.
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

                    // Guard 1: reply must carry SYN+ACK.
                    // Guard 2: dport must equal OUR sport – filters other apps.
                    // Guard 3: source IP must be one of our targets.
                    if is_syn_ack && pkt.get_destination() == src_port {
                        if let IpAddr::V4(v4) = src_addr {
                            if valid_targets.contains(&v4) {
                                // Channel closed → main is done → exit thread.
                                if hit_tx.send((v4, pkt.get_source())).is_err() {
                                    break;
                                }
                            }
                        }
                    }
                }
                // Socket error (e.g. EBADF on shutdown) – exit.
                Err(_) => break,
            }
        }
    });

    // ── 4. Cache source IPs once per target ─────────────────────────────────
    let src_ips: Vec<Option<Ipv4Addr>> =
        ipv4_targets.iter().map(|&dst| get_source_ip(dst)).collect();

    // ── 5. Send SYN packets in paced bursts ─────────────────────────────────
    //
    // Retry strategy: full passes instead of N consecutive retries per port.
    // Spreading retries evenly reduces burst pressure and improves coverage.
    let max_retries = timing.retries.max(1) as usize;
    let mut sent_count: usize = 0;
    let mut buf = [0u8; 20]; // reusable 20-byte packet buffer

    // open_set is shared across passes and the inter-pass mini-drain.
    let mut open_set: HashSet<(Ipv4Addr, u16)> = HashSet::new();
    // Counter tracks how many hits have been printed so far (shared across
    // all drain calls so on_open indices are globally sequential).
    let mut hits_reported: usize = 0;

    for attempt in 0..=max_retries {
        for (idx, &dst_ip) in ipv4_targets.iter().enumerate() {
            let Some(src_ip) = src_ips[idx] else {
                continue;
            };

            for &dst_port in ports {
                // Build a fresh SYN into `buf` (fill(0) called inside).
                build_syn_packet(src_ip, dst_ip, src_port, dst_port, &mut buf);

                // Back off on ENOBUFS instead of silently dropping packets.
                let mut enobufs_left = ENOBUFS_RETRIES;
                loop {
                    let pkt = TcpPacket::new(&buf).expect("buffer TCP inválido");
                    match tx.send_to(pkt, IpAddr::V4(dst_ip)) {
                        Ok(_) => break,
                        Err(e)
                            if e.raw_os_error() == Some(enobufs_code())
                                && enobufs_left > 0 =>
                        {
                            enobufs_left -= 1;
                            // Give the kernel 5 ms to drain its send queue.
                            std::thread::sleep(std::time::Duration::from_millis(5));
                        }
                        Err(_) => break, // unrecoverable – skip port
                    }
                }

                sent_count += 1;

                // Pacing: yield after every BURST_SIZE packets so the NIC
                // queue never fills up enough to trigger ENOBUFS silently.
                if sent_count % BURST_SIZE == 0 {
                    sleep(Duration::from_millis(BURST_PAUSE_MS)).await;
                }
            }
        }

        // Between retry passes: run a mini adaptive drain so SYN-ACKs from
        // the current pass are collected before we flood the wire again.
        // Uses the same quiet-window logic as the final drain (200 ms quiet
        // or 500 ms hard cap), but does NOT drop hit_rx – scanning continues.
        if attempt < max_retries {
            drain_adaptive(&hit_rx, &mut open_set, DRAIN_QUIET_MS, 500, reporter, &mut hits_reported);
        }
    }

    // ── 6. Adaptive drain window ────────────────────────────────────────────
    //
    // Collect hits until the flow goes quiet for DRAIN_QUIET_MS or the hard
    // cap DRAIN_MAX_MS is reached.  Dropping hit_rx signals the radar thread.
    drain_adaptive(&hit_rx, &mut open_set, DRAIN_QUIET_MS, DRAIN_MAX_MS, reporter, &mut hits_reported);
    // hit_rx dropped at end of scope → channel closed → radar thread exits.

    // ── 7. Build report ─────────────────────────────────────────────────────
    // Ports were already printed in real-time; just build the return value.
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

// ── Helpers ─────────────────────────────────────────────────────────────────

/// Adaptive drain: collect hits from `rx` until no new hit arrives within
/// `quiet_ms` milliseconds, or `max_ms` milliseconds have elapsed in total.
///
/// Each **new** hit (not a duplicate) is printed immediately via `reporter`.
/// Can be called multiple times sharing the same `rx`, `set`, and `counter`.
fn drain_adaptive(
    rx: &std::sync::mpsc::Receiver<(Ipv4Addr, u16)>,
    set: &mut HashSet<(Ipv4Addr, u16)>,
    quiet_ms: u64,
    max_ms: u64,
    reporter: &LiveReporter,
    counter: &mut usize,
) {
    use std::sync::mpsc::RecvTimeoutError;
    let hard_deadline =
        std::time::Instant::now() + std::time::Duration::from_millis(max_ms);
    let mut quiet_deadline =
        std::time::Instant::now() + std::time::Duration::from_millis(quiet_ms);

    loop {
        let now = std::time::Instant::now();
        if now >= hard_deadline {
            break;
        }
        // Use the sooner of the two deadlines as the recv timeout.
        let timeout = quiet_deadline.min(hard_deadline).saturating_duration_since(now);
        match rx.recv_timeout(timeout) {
            Ok(hit) => {
                // Only report and count genuinely new ports.
                if set.insert(hit) {
                    *counter += 1;
                    reporter.on_open(*counter, IpAddr::V4(hit.0), hit.1);
                }
                // Reset the quiet window – traffic is still flowing.
                quiet_deadline =
                    std::time::Instant::now() + std::time::Duration::from_millis(quiet_ms);
            }
            Err(RecvTimeoutError::Timeout) => {
                // Quiet window expired first: no traffic for quiet_ms.
                break;
            }
            Err(RecvTimeoutError::Disconnected) => break,
        }
    }
}
#[inline]
fn enobufs_code() -> i32 {
    if cfg!(unix) {
        105 // ENOBUFS (Linux)
    } else if cfg!(windows) {
        10055 // WSAENOBUFS
    } else {
        -1
    }
}

/// Determines the local IP the OS would use to reach `target`.
/// Uses a connected UDP socket – no actual packets are sent.
fn get_source_ip(target: Ipv4Addr) -> Option<Ipv4Addr> {
    let sock = UdpSocket::bind("0.0.0.0:0").ok()?;
    sock.connect((target, 80)).ok()?;
    match sock.local_addr().ok()?.ip() {
        IpAddr::V4(v4) => Some(v4),
        IpAddr::V6(_) => None,
    }
}

/// Builds a minimal, correctly-formed SYN TCP packet into `buf`.
///
/// Correctness checklist:
/// - `set_checksum(0)` is called **before** `ipv4_checksum` (the checksum
///   computation treats the checksum field as zero).
/// - `ipv4_checksum` is called **after** every other field has been written.
/// - `src_port` is fixed for the whole scan so NAT returns work.
/// - `window` of 64 240 matches the Linux kernel default – looks normal to
///   stateful firewalls.  A value of 1 024 is suspicious and often filtered.
/// - `data_offset` 5 → 20-byte header, no options → fits exactly in `buf`.
fn build_syn_packet(
    src_ip: Ipv4Addr,
    dst_ip: Ipv4Addr,
    src_port: u16,
    dst_port: u16,
    buf: &mut [u8; 20],
) {
    // Zero out on every call so reusing the buffer is safe.
    buf.fill(0);

    let mut pkt = MutableTcpPacket::new(buf).expect("buffer TCP inválido");

    // Per-packet sequence randomisation looks less scanner-like.
    let seq = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.subsec_nanos())
        .unwrap_or(0);

    pkt.set_source(src_port);
    pkt.set_destination(dst_port);
    pkt.set_sequence(seq);
    pkt.set_acknowledgement(0);
    pkt.set_data_offset(5); // 5 × 4 = 20 bytes, no TCP options
    pkt.set_reserved(0);
    pkt.set_flags(TcpFlags::SYN);
    pkt.set_window(64_240); // realistic Linux default
    pkt.set_urgent_ptr(0);
    pkt.set_options(&[] as &[TcpOption]);
    pkt.set_checksum(0); // MUST be zero before computing the real checksum

    // ipv4_checksum uses a TCP pseudo-header (src/dst IP, proto, TCP length).
    // Call it AFTER all other fields are set.
    let cs = ipv4_checksum(&pkt.to_immutable(), &src_ip, &dst_ip);
    pkt.set_checksum(cs);
}

// ── Privilege checks ─────────────────────────────────────────────────────────

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
