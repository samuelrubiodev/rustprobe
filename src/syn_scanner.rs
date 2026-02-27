pub fn is_root() -> bool {
    #[cfg(unix)]
    {
        nix::unistd::Uid::effective().is_root()
    }

    #[cfg(not(unix))]
    {
        true
    }
}

pub async fn run_syn_scan(
    _targets: &[std::net::IpAddr],
    _ports: &[u16],
    _timing: crate::models::TimingProfile,
    reporter: &crate::report::LiveReporter,
) -> anyhow::Result<Vec<crate::models::PortReport>> {
    if !is_root() {
        anyhow::bail!("El escaneo SYN (-sS) requiere privilegios de Administrador o Root para usar Raw Sockets.");
    }

    reporter.println("[*] Iniciando motor de Raw Sockets (Stealth SYN)...".to_string());

    // TODO: Implementar inyección de paquetes pnet
    Ok(vec![])
}
