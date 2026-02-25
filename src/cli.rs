use anyhow::{bail, Context, Result};
use clap::Parser;
use std::collections::BTreeSet;
use std::env;
use std::ffi::OsString;
use std::path::PathBuf;

use crate::models::TimingProfile;

#[derive(Parser, Debug)]
#[command(
    name = "rustprobe",
    version,
    about = "Escáner de red de alto rendimiento con motor de plugins Wasm",
    next_line_help = true,
    after_help = "Notas:\n  - El análisis Wasm es opt-in: solo se activa con --script o -C/--default-scripts.\n  - -oN (nmap) es compatible y se normaliza a --output.\n\nEjemplos:\n  rustprobe 10.0.2.16 -p 80\n  rustprobe 10.0.2.16 -p 80,443 --script http\n  rustprobe 10.0.2.16 -p 1-1024 -C\n  rustprobe --update"
)]
pub struct Cli {
    /// Objetivo a escanear: IP, rango (A.B.C.D-E.F.G.H), CIDR o dominio
    #[arg(required_unless_present = "update")]
    pub target: Option<String>,

    /// Actualiza los plugins Wasm oficiales desde GitHub
    #[arg(long = "update")]
    pub update: bool,

    /// Puertos: "80,443", "1-1024" o "-" para todos
    #[arg(short = 'p', long = "ports", default_value = "-")]
    pub ports: String,

    /// Plantilla de timing: T1..T5
    #[arg(short = 'T', long = "timing", default_value = "T3")]
    pub timing: String,

    /// Script(s) Wasm por nombre (ej: --script smb,http), buscados en el directorio local estándar
    #[arg(long = "script", value_delimiter = ',')]
    pub script: Vec<String>,

    /// Ejecuta todos los scripts Wasm del directorio local por defecto (equivalente a Nmap -sC)
    #[arg(short = 'C', long = "default-scripts")]
    pub default_scripts: bool,

    /// Archivo de salida (compatibilidad nmap: -oN)
    #[arg(short = 'o', long = "output")]
    pub output: Option<PathBuf>,
}

pub fn parse_cli() -> Cli {
    Cli::parse_from(normalize_nmap_shortcuts(env::args_os()))
}

pub fn parse_timing(value: &str) -> Result<TimingProfile> {
    let upper = value.trim().to_uppercase();

    let profile = match upper.as_str() {
        "T1" => TimingProfile {
            concurrency: 64,
            timeout_ms: 2_500,
            retries: 3,
        },
        "T2" => TimingProfile {
            concurrency: 256,
            timeout_ms: 1_500,
            retries: 3,
        },
        "T3" => TimingProfile {
            concurrency: 1_024,
            timeout_ms: 800,
            retries: 2,
        },
        "T4" => TimingProfile {
            concurrency: 4_096,
            timeout_ms: 350,
            retries: 1,
        },
        "T5" => TimingProfile {
            concurrency: 12_288,
            timeout_ms: 120,
            retries: 1,
        },
        _ => bail!("Timing inválido '{}'. Valores permitidos: T1..T5", value),
    };

    Ok(profile)
}

pub fn parse_ports(raw: &str) -> Result<Vec<u16>> {
    if raw.trim() == "-" {
        return Ok((1u16..=u16::MAX).collect());
    }

    let mut ports = BTreeSet::new();

    for chunk in raw.split(',').map(str::trim).filter(|s| !s.is_empty()) {
        if let Some((start, end)) = chunk.split_once('-') {
            let start_port: u16 = start
                .parse()
                .with_context(|| format!("Puerto inicial inválido: '{start}'"))?;
            let end_port: u16 = end
                .parse()
                .with_context(|| format!("Puerto final inválido: '{end}'"))?;

            if start_port == 0 || end_port == 0 || start_port > end_port {
                bail!("Rango de puertos inválido: '{chunk}'");
            }

            for port in start_port..=end_port {
                ports.insert(port);
            }
        } else {
            let port: u16 = chunk
                .parse()
                .with_context(|| format!("Puerto inválido: '{chunk}'"))?;

            if port == 0 {
                bail!("El puerto 0 no es válido en un scan TCP connect");
            }

            ports.insert(port);
        }
    }

    if ports.is_empty() {
        bail!("No se especificaron puertos válidos");
    }

    Ok(ports.into_iter().collect())
}

pub fn should_show_closed_in_live(raw_ports: &str) -> bool {
    let raw = raw_ports.trim();
    if raw == "-" {
        return false;
    }

    raw.split(',')
        .map(str::trim)
        .filter(|chunk| !chunk.is_empty())
        .all(|chunk| !chunk.contains('-'))
}

fn normalize_nmap_shortcuts(args: impl IntoIterator<Item = OsString>) -> Vec<OsString> {
    // Compatibilidad con sintaxis de nmap: "-oN archivo.txt" o "-oNarchivo.txt".
    let mut normalized = Vec::new();

    for arg in args {
        if let Some(text) = arg.to_str() {
            if text == "-oN" {
                normalized.push(OsString::from("--output"));
                continue;
            }

            if let Some(rest) = text.strip_prefix("-oN") {
                if !rest.is_empty() {
                    normalized.push(OsString::from("--output"));
                    normalized.push(OsString::from(rest));
                    continue;
                }
            }
        }

        normalized.push(arg);
    }

    normalized
}
