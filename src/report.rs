use crate::models::{PortReport, ScriptResult};
use crate::services::get_service_name;
use anyhow::{Context, Result};
use indicatif::{MultiProgress, ProgressBar, ProgressStyle};
use serde_json::Value;
use std::collections::BTreeMap;
use std::env;
use std::fs;
use std::io::{IsTerminal, Write};
use std::net::IpAddr;
use std::path::Path;
use std::sync::Arc;
use std::sync::Mutex;
use std::time::{Duration, Instant};

struct OrderedPrintState {
    next_index: usize,
    pending: BTreeMap<usize, String>,
}

struct ReporterInner {
    colors_enabled: bool,
    show_closed_in_live: bool,
    started_at: Instant,
    multi: MultiProgress,
    ordered_print: Mutex<OrderedPrintState>,
}

#[derive(Clone)]
pub struct LiveReporter {
    inner: Arc<ReporterInner>,
}

impl LiveReporter {
    pub fn new(colors_enabled: bool, show_closed_in_live: bool) -> Self {
        let inner = Arc::new(ReporterInner {
            colors_enabled,
            show_closed_in_live,
            started_at: Instant::now(),
            multi: MultiProgress::new(),
            ordered_print: Mutex::new(OrderedPrintState {
                next_index: 1,
                pending: BTreeMap::new(),
            }),
        });

        let reporter = Self { inner };
        reporter.println(format!(
            "\n{}",
            paint(
                "#  Tiempo    Host                 Puerto Estado Servicio",
                "1;37",
                colors_enabled
            )
        ));
        reporter.println(paint(
            "-- --------- -------------------- ------ ------ ---------------",
            "2;37",
            colors_enabled,
        ));

        reporter
    }

    pub fn add_scanning_spinner(&self, ip: IpAddr, port: u16) -> ProgressBar {
        let pb = self.inner.multi.add(ProgressBar::new_spinner());
        pb.set_style(
            ProgressStyle::with_template("{spinner} {msg}")
                .unwrap_or_else(|_| ProgressStyle::default_spinner())
                .tick_strings(&["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"]),
        );
        pb.enable_steady_tick(Duration::from_millis(90));
        pb.set_message(paint(
            &format!("[~] Detectando servicio en {ip}:{port}..."),
            "1;33",
            self.inner.colors_enabled,
        ));
        pb
    }

    pub fn finish_spinner(
        &self,
        pb: ProgressBar,
        detection_index: usize,
        ip: IpAddr,
        port: u16,
        script_results: &[ScriptResult],
    ) {
        pb.finish_and_clear();

        let elapsed = self.elapsed();
        let label = paint("open", "1;32", self.inner.colors_enabled);
        let service = get_service_name(port);
        let service_details = service_banner(script_results);
        let final_service = if service_details.is_empty() {
            service.to_string()
        } else {
            format!("{service}    Service: {service_details}")
        };

        let line = format!(
            "{:>2} {:>9} {:<20} {:>6}/tcp {} {}",
            detection_index,
            format_elapsed(elapsed),
            ip,
            port,
            label,
            final_service
        );

        self.emit_open_line_ordered(detection_index, line);
    }

    pub fn println<S: Into<String>>(&self, message: S) {
        let _ = self.inner.multi.println(message.into());
    }

    pub fn warn<S: Into<String>>(&self, message: S) {
        self.println(paint(&message.into(), "1;31", self.inner.colors_enabled));
    }

    pub fn on_open(&self, index: usize, ip: IpAddr, port: u16) {
        let elapsed = self.elapsed();
        let label = paint("open", "1;32", self.inner.colors_enabled);
        let service = get_service_name(port);
        let line = format!(
            "{:>2} {:>9} {:<20} {:>6}/tcp {} {}",
            index,
            format_elapsed(elapsed),
            ip,
            port,
            label,
            service
        );
        self.emit_open_line_ordered(index, line);
    }

    pub fn on_closed(&self, index: usize, ip: IpAddr, port: u16) {
        if !self.inner.show_closed_in_live {
            return;
        }

        let elapsed = self.elapsed();
        let label = paint("closed", "1;31", self.inner.colors_enabled);
        self.println(format!(
            "{:>2} {:>9} {:<20} {:>6} {}",
            index,
            format_elapsed(elapsed),
            ip,
            port,
            label
        ));
    }

    pub fn summary(&self, open: usize, closed: usize, total_checks: usize) {
        self.println(paint(
            "-- --------- -------------------- ------ ------ ---------------",
            "2;37",
            self.inner.colors_enabled,
        ));
        self.println(format!(
            "{}: {} abierto(s), {} cerrado(s), {} comprobaciones.",
            paint("Resumen", "1;33", self.inner.colors_enabled),
            open,
            closed,
            total_checks
        ));
    }

    fn elapsed(&self) -> Duration {
        self.inner.started_at.elapsed()
    }

    fn emit_open_line_ordered(&self, index: usize, line: String) {
        let mut state = self
            .inner
            .ordered_print
            .lock()
            .unwrap_or_else(|poison| poison.into_inner());

        state.pending.insert(index, line);

        loop {
            let next_index = state.next_index;
            let Some(next_line) = state.pending.remove(&next_index) else {
                break;
            };
            self.println(next_line);
            state.next_index += 1;
        }
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

fn service_banner(script_results: &[ScriptResult]) -> String {
    for script in script_results {
        if let Ok(value) = serde_json::from_str::<Value>(&script.details) {
            if let Some(service) = value.get("service").and_then(Value::as_str) {
                let version = value.get("version").and_then(Value::as_str).unwrap_or("");
                return if version.is_empty() {
                    service.to_string()
                } else {
                    format!("{service} ({version})")
                };
            }

            if let Some(summary) = value.get("summary").and_then(Value::as_str) {
                return normalized_service_summary(summary);
            }
        }
    }

    String::new()
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

fn normalized_service_summary(summary: &str) -> String {
    let mut current = summary.trim();

    loop {
        let lower = current.to_ascii_lowercase();
        if let Some(rest) = lower.strip_prefix("service:") {
            let consumed = current.len() - rest.len();
            current = current[consumed..].trim_start();
            continue;
        }
        break;
    }

    current.to_string()
}
