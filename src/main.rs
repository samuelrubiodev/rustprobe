mod cli;
mod config;
mod models;
mod network;
mod report;
mod services;
mod wasm;

use crate::cli::{parse_cli, parse_ports, parse_timing, should_show_closed_in_live};
use crate::config::{ensure_default_scripts_dir, has_wasm_files};
use crate::models::{PortReport, TimingProfile};
use crate::network::{clamp_concurrency, resolve_targets, scan_targets};
use crate::report::{paint, print_report, supports_color, write_report_file, LiveReporter};
use crate::services::get_service_name;
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
    let default_scripts_dir = ensure_default_scripts_dir()?;
    let (wasm_engine, using_default_scripts_dir) = if cli.script.is_empty() {
        if has_wasm_files(&default_scripts_dir)? {
            (Some(WasmEngine::load(&default_scripts_dir)?), true)
        } else {
            println!(
                "[i] Directorio de scripts local vacío. Añade archivos .wasm en {} para activar el análisis.",
                default_scripts_dir.display()
            );
            (None, true)
        }
    } else {
        (
            Some(WasmEngine::load_named_from_dir(
                &default_scripts_dir,
                &cli.script,
            )?),
            false,
        )
    };

    if !cli.script.is_empty() {
        println!(
            "[+] Cargando scripts solicitados ({}) desde {}",
            cli.script.join(","),
            default_scripts_dir.display()
        );
    }

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
    let show_closed_in_live = should_show_closed_in_live(&cli.ports);

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

    if wasm_engine.is_some() && using_default_scripts_dir {
        println!("[+] Plugins Wasm locales detectados. Análisis adicional activado automáticamente.");
    }

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
            service_name: get_service_name(open.port),
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
