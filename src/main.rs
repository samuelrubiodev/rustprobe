mod cli;
mod config;
mod models;
mod network;
mod report;
mod services;
mod syn_scanner;
mod update;
mod wasm;

use crate::cli::{parse_cli, parse_ports, parse_timing, should_show_closed_in_live};
use crate::config::{ensure_default_scripts_dir, has_wasm_files};
use crate::models::{ScriptResult, TimingProfile};
use crate::network::{clamp_concurrency, resolve_targets, scan_targets};
use crate::report::{paint, print_report, supports_color, write_report_file, LiveReporter};
use crate::syn_scanner::run_syn_scan;
use crate::update::update_scripts;
use crate::wasm::WasmEngine;
use anyhow::{bail, Context, Result};
use std::sync::Arc;

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

    if cli.update {
        update_scripts(&default_scripts_dir).await?;
        println!(
            "[+] Actualización completada. Plugins guardados en {}",
            default_scripts_dir.display()
        );
        return Ok(());
    }

    let target = cli
        .target
        .as_deref()
        .ok_or_else(|| anyhow::anyhow!("Debes especificar un objetivo o usar --update"))?;

    let wasm_engine = if !cli.script.is_empty() {
        Some(Arc::new(WasmEngine::load_named_from_dir(
            &default_scripts_dir,
            &cli.script,
        )?))
    } else if cli.default_scripts {
        if has_wasm_files(&default_scripts_dir)? {
            Some(Arc::new(WasmEngine::load(&default_scripts_dir)?))
        } else {
            println!(
                "[i] Directorio de scripts local vacío. Añade archivos .wasm en {} para usar --default-scripts.",
                default_scripts_dir.display()
            );
            None
        }
    } else {
        None
    };

    if !cli.script.is_empty() {
        println!(
            "[+] Cargando scripts solicitados ({}) desde {}",
            cli.script.join(","),
            default_scripts_dir.display()
        );
    }

    let targets = resolve_targets(target)
        .await
        .with_context(|| format!("No se pudo resolver target '{}'", target))?;

    let scan_hostname = if target.parse::<std::net::IpAddr>().is_ok()
        || target.contains('/')
        || target.contains('-')
    {
        None
    } else {
        Some(target.to_string())
    };

    if targets.is_empty() {
        bail!("No se encontraron IPs válidas para escanear");
    }

    let ports = parse_ports(&cli.ports)?;
    let timing = parse_timing(&cli.timing)?;
    let timing = TimingProfile {
        concurrency: clamp_concurrency(timing.concurrency),
        timeout_ms: timing.timeout_ms,
        retries: timing.retries,
    };
    let colors_enabled = supports_color();
    let show_closed_in_live = should_show_closed_in_live(&cli.ports);

    if cli.syn {
        println!(
            "{}: {} objetivo(s), {} puerto(s), concurrencia={}, modo=SYN...",
            paint("Iniciando escaneo", "1;36", colors_enabled),
            targets.len(),
            ports.len(),
            timing.concurrency
        );
    } else {
        println!(
            "{}: {} objetivo(s), {} puerto(s), concurrencia={}...",
            paint("Iniciando escaneo", "1;36", colors_enabled),
            targets.len(),
            ports.len(),
            timing.concurrency
        );
    }

    let reporter = LiveReporter::new(colors_enabled, show_closed_in_live);
    let reports = if cli.syn {
        let mut syn_reports = run_syn_scan(&targets, &ports, timing, &reporter).await?;

        // ── Run Wasm scripts on open ports (same pipeline as TCP connect mode) ──
        if let Some(engine) = &wasm_engine {
            let script_semaphore =
                Arc::new(tokio::sync::Semaphore::new(4));
            let mut script_jobs: tokio::task::JoinSet<(usize, Vec<ScriptResult>)> =
                tokio::task::JoinSet::new();

            for (idx, report) in syn_reports.iter().enumerate() {
                let permit = script_semaphore
                    .clone()
                    .acquire_owned()
                    .await
                    .expect("script semaphore closed");
                let engine = Arc::clone(engine);
                let reporter_clone = reporter.clone();
                let ip = report.ip;
                let port = report.port;
                let pb = reporter.add_scanning_spinner(ip, port);
                let hostname = scan_hostname.clone();
                // detection_index is already past next_index in the ordered
                // printer (on_open advanced it during drain), so finish_spinner
                // clears the spinner without re-printing the port line.
                let detection_index = idx + 1;

                script_jobs.spawn(async move {
                    let results = match tokio::task::spawn_blocking(move || {
                        engine.run_scripts(ip, port, hostname.as_deref())
                    })
                    .await
                    {
                        Ok(Ok(r)) => r,
                        Ok(Err(e)) => vec![ScriptResult {
                            script: "wasm-engine".into(),
                            status: "error".into(),
                            details: format!("{e:#}"),
                        }],
                        Err(e) => vec![ScriptResult {
                            script: "wasm-worker".into(),
                            status: "error".into(),
                            details: format!("{e}"),
                        }],
                    };
                    reporter_clone.finish_spinner(pb, detection_index, ip, port, &results);
                    drop(permit);
                    (idx, results)
                });
            }

            while let Some(Ok((idx, results))) = script_jobs.join_next().await {
                syn_reports[idx].scripts = results;
            }
        }

        syn_reports
    } else {
        scan_targets(
            &targets,
            &ports,
            scan_hostname.as_deref(),
            timing,
            &reporter,
            wasm_engine.clone(),
        )
        .await
    };

    println!(
        "\n{}: {} puerto(s) abierto(s) detectado(s).",
        paint("Escaneo finalizado", "1;36", colors_enabled),
        reports.len()
    );

    if cli.default_scripts && wasm_engine.is_some() && cli.script.is_empty() {
        println!("[+] Plugins Wasm locales detectados. Análisis adicional activado por --default-scripts.");
    }

    print_report(&reports);

    if let Some(path) = cli.output {
        write_report_file(&path, &reports)?;
        println!("\n[+] Resultados guardados en {}", path.display());
    }

    Ok(())
}
