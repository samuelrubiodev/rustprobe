mod cli;
mod models;
mod network;
mod report;
mod wasm;

use crate::cli::{parse_cli, parse_ports, parse_timing};
use crate::models::{PortReport, TimingProfile};
use crate::network::{clamp_concurrency, resolve_targets, scan_targets};
use crate::report::{paint, print_report, supports_color, write_report_file, LiveReporter};
use crate::wasm::WasmEngine;
use anyhow::{bail, Context, Result};

#[tokio::main]
async fn main() {
    if let Err(error) = run().await {
        eprintln!("[!] Error: {error:#}");
        std::process::exit(1);
    }
}

async fn run() -> Result<()> {
    let cli = parse_cli();

    let targets = resolve_targets(&cli.target)
        .await
        .with_context(|| format!("No se pudo resolver target '{}'", cli.target))?;

    if targets.is_empty() {
        bail!("No se encontraron IPs válidas para escanear");
    }

    let ports = parse_ports(&cli.ports)?;
    let timing = parse_timing(&cli.timing)?;
    let timing = TimingProfile {
        concurrency: clamp_concurrency(timing.concurrency),
        timeout_ms: timing.timeout_ms,
    };
    let colors_enabled = supports_color();
    let show_closed_in_live = cli.ports.trim() != "-";

    println!(
        "{}: {} objetivo(s), {} puerto(s), concurrencia={}...",
        paint("Iniciando escaneo", "1;36", colors_enabled),
        targets.len(),
        ports.len(),
        timing.concurrency
    );

    let reporter = LiveReporter::new(colors_enabled, show_closed_in_live);
    let open_ports = scan_targets(&targets, &ports, timing, &reporter).await;

    println!(
        "\n{}: {} puerto(s) abierto(s) detectado(s).",
        paint("Escaneo finalizado", "1;36", colors_enabled),
        open_ports.len()
    );

    let wasm_engine = match &cli.script {
        Some(script_path) if !open_ports.is_empty() => Some(WasmEngine::load(script_path)?),
        _ => None,
    };

    let mut reports = Vec::with_capacity(open_ports.len());
    for open in open_ports {
        let scripts = if let Some(engine) = &wasm_engine {
            engine.run_scripts(open.ip, open.port).with_context(|| {
                format!("Falló la ejecución de scripts en {}:{}", open.ip, open.port)
            })?
        } else {
            Vec::new()
        };

        reports.push(PortReport {
            ip: open.ip,
            port: open.port,
            state: "open",
            scripts,
        });
    }

    print_report(&reports);

    if let Some(path) = cli.output {
        write_report_file(&path, &reports)?;
        println!("\n[+] Resultados guardados en {}", path.display());
    }

    Ok(())
}
