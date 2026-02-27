use anyhow::{bail, Result};
use std::net::IpAddr;

use crate::models::{PortReport, TimingProfile};

const SYN_PRIVILEGE_ERROR: &str =
    "El escaneo SYN (-sS) requiere privilegios de Administrador o Root para usar Raw Sockets";

pub async fn run_syn_scan(
    targets: &[IpAddr],
    ports: &[u16],
    timing: TimingProfile,
) -> Result<Vec<PortReport>> {
    let _ = (targets, ports, timing);

    if !has_raw_socket_privileges() {
        bail!(SYN_PRIVILEGE_ERROR);
    }

    // TODO: Implementar el motor Stealth SYN Scan con raw sockets (pnet).
    Ok(Vec::new())
}

fn has_raw_socket_privileges() -> bool {
    #[cfg(unix)]
    {
        return nix::unistd::Uid::effective().is_root();
    }

    #[cfg(windows)]
    {
        return is_windows_admin();
    }

    #[cfg(not(any(unix, windows)))]
    {
        false
    }
}

#[cfg(windows)]
fn is_windows_admin() -> bool {
    use std::process::Command;

    let output = Command::new("powershell")
        .args([
            "-NoProfile",
            "-NonInteractive",
            "-Command",
            "[bool]([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)",
        ])
        .output();

    match output {
        Ok(result) if result.status.success() => {
            let text = String::from_utf8_lossy(&result.stdout);
            text.trim().eq_ignore_ascii_case("true")
        }
        _ => false,
    }
}
