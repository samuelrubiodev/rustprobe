use crate::models::PortReport;
use crate::services::get_service_name;
use anyhow::{Context, Result};
use serde_json::Value;
use std::env;
use std::fs;
use std::io::{IsTerminal, Write};
use std::net::IpAddr;
use std::path::Path;
use std::time::{Duration, Instant};

pub struct LiveReporter {
    colors_enabled: bool,
    show_closed_in_live: bool,
    started_at: Instant,
}

impl LiveReporter {
    pub fn new(colors_enabled: bool, show_closed_in_live: bool) -> Self {
        println!(
            "\n{}",
            paint(
                "#  Tiempo    Host                 Puerto Estado Servicio",
                "1;37",
                colors_enabled
            )
        );
        println!(
            "{}",
            paint(
                "-- --------- -------------------- ------ ------ ---------------",
                "2;37",
                colors_enabled
            )
        );

        Self {
            colors_enabled,
            show_closed_in_live,
            started_at: Instant::now(),
        }
    }

    pub fn on_open(&self, index: usize, ip: IpAddr, port: u16) {
        let elapsed = self.elapsed();
        let label = paint("open", "1;32", self.colors_enabled);
        let service = get_service_name(port);
        println!(
            "{:>2} {:>9} {:<20} {:>6}/tcp {} {}",
            index,
            format_elapsed(elapsed),
            ip,
            port,
            label,
            service
        );
    }

    pub fn on_closed(&self, index: usize, ip: IpAddr, port: u16) {
        if !self.show_closed_in_live {
            return;
        }

        let elapsed = self.elapsed();
        let label = paint("closed", "1;31", self.colors_enabled);
        println!(
            "{:>2} {:>9} {:<20} {:>6} {}",
            index,
            format_elapsed(elapsed),
            ip,
            port,
            label
        );
    }

    pub fn summary(&self, open: usize, closed: usize, total_checks: usize) {
        println!(
            "{}",
            paint(
                "-- --------- -------------------- ------ ------ ---------------",
                "2;37",
                self.colors_enabled
            )
        );
        println!(
            "{}: {} abierto(s), {} cerrado(s), {} comprobaciones.",
            paint("Resumen", "1;33", self.colors_enabled),
            open,
            closed,
            total_checks
        );
    }

    pub fn println(&self, msg: String) {
        println!("{}", msg);
    }

    fn elapsed(&self) -> Duration {
        self.started_at.elapsed()
    }
}

pub fn supports_color() -> bool {
    std::io::stdout().is_terminal() && env::var_os("NO_COLOR").is_none()
}

pub fn paint(text: &str, ansi_code: &str, enabled: bool) -> String {
    if enabled {
        format!("\x1b[{ansi_code}m{text}\x1b[0m")
    } else {
        text.to_string()
    }
}

pub fn format_elapsed(duration: Duration) -> String {
    let total_millis = duration.as_millis();
    let seconds = total_millis / 1_000;
    let millis = total_millis % 1_000;
    format!("{seconds:>2}.{millis:03}s")
}

pub fn print_report(reports: &[PortReport]) {
    if reports.is_empty() {
        println!("No se encontraron puertos abiertos.");
        return;
    }

    let has_scripts = reports.iter().any(|report| !report.scripts.is_empty());
    if !has_scripts {
        return;
    }

    println!("\nResultados de scripts:\n");
    let colors_enabled = supports_color();
    let mut last_ip: Option<IpAddr> = None;

    for report in reports {
        if report.scripts.is_empty() {
            continue;
        }

        if last_ip != Some(report.ip) {
            println!("{}", report.ip);
            last_ip = Some(report.ip);
        }

        println!(
            "  {:>5}/tcp {} {}",
            report.port, report.state, report.service_name
        );

        for script in &report.scripts {
            println!(
                "  {}",
                format_script_details_line(&script.script, &script.details, colors_enabled)
            );
        }
    }
}

pub fn write_report_file(path: &Path, reports: &[PortReport]) -> Result<()> {
    let mut file = fs::File::create(path)
        .with_context(|| format!("No se pudo crear archivo {}", path.display()))?;

    writeln!(file, "# RustProbe Report")?;
    writeln!(file, "# Open ports: {}", reports.len())?;
    writeln!(file)?;

    let mut last_ip: Option<IpAddr> = None;

    for report in reports {
        if report.scripts.is_empty() {
            continue;
        }

        if last_ip != Some(report.ip) {
            if last_ip.is_some() {
                writeln!(file)?;
            }
            writeln!(file, "{}", report.ip)?;
            last_ip = Some(report.ip);
        }

        writeln!(
            file,
            "  {:>5}/tcp {} {}",
            report.port, report.state, report.service_name
        )?;

        for script in &report.scripts {
            writeln!(
                file,
                "  {}",
                format_script_details_line(&script.script, &script.details, false)
            )?;
        }
    }

    Ok(())
}

fn format_script_details_line(script_name: &str, details: &str, colors_enabled: bool) -> String {
    let clean_name = script_name.trim_end_matches(".wasm");

    if let Ok(value) = serde_json::from_str::<Value>(details) {
        if let Some(summary) = value.get("summary").and_then(Value::as_str) {
            let severity = value
                .get("severity")
                .and_then(Value::as_str)
                .unwrap_or("info");

            let prefix = paint("  |_", "2;37", colors_enabled);
            let name = paint(clean_name, "2;37", colors_enabled);
            let severity_color = severity_color_code(severity);
            let severity_text = paint(severity, severity_color, colors_enabled);

            return format!("{prefix} {name} [{severity_text}]: {summary}");
        }
    }

    let prefix = paint("  |_", "2;37", colors_enabled);
    let name = paint(clean_name, "2;37", colors_enabled);
    format!("{prefix} {name} [raw]: {details}")
}

fn severity_color_code(severity: &str) -> &'static str {
    match severity.to_ascii_lowercase().as_str() {
        "critical" | "high" | "error" => "1;31",
        _ => "1;33",
    }
}
