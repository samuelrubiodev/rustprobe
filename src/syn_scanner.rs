use crate::models::{PortReport, TimingProfile};
use anyhow::{bail, Result};
use std::net::IpAddr;

pub async fn run_syn_scan(
    targets: &[IpAddr],
    ports: &[u16],
    timing: TimingProfile,
) -> Result<Vec<PortReport>> {
    if !has_raw_socket_privileges() {
        bail!(
            "El escaneo SYN (-sS) requiere privilegios de Administrador o Root para usar Raw Sockets"
        );
    }

    let _ = (targets, ports, timing);

    // TODO: Implementar motor de escaneo SYN con raw sockets (forge/parsing TCP/IP con pnet).
    Ok(Vec::new())
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
