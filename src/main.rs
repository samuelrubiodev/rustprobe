use std::collections::BTreeSet;
use std::env;
use std::ffi::OsString;
use std::fs;
use std::io::{Read, Write};
use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpStream};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{anyhow, bail, Context, Result};
use clap::Parser;
use futures::stream::{FuturesUnordered, StreamExt};
use ipnet::IpNet;
use serde::{Deserialize, Serialize};
use tokio::net::{lookup_host, TcpStream as TokioTcpStream};
use tokio::sync::Semaphore;
use tokio::time::{timeout, Duration as TokioDuration};
use wasmtime::{Caller, Engine, Linker, Module, Store};

#[derive(Parser, Debug)]
#[command(
    name = "rustprobe",
    version,
    about = "Escáner de red de alto rendimiento con motor de plugins Wasm"
)]
struct Cli {
    /// Objetivo a escanear: IP, rango (A.B.C.D-E.F.G.H), CIDR o dominio
    target: String,

    /// Puertos: "80,443", "1-1024" o "-" para todos
    #[arg(short = 'p', long = "ports", default_value = "-")]
    ports: String,

    /// Plantilla de timing: T1..T5
    #[arg(short = 'T', long = "timing", default_value = "T3")]
    timing: String,

    /// Script .wasm específico o directorio con scripts
    #[arg(long = "script")]
    script: Option<PathBuf>,

    /// Archivo de salida (compatibilidad nmap: -oN)
    #[arg(short = 'o', long = "output")]
    output: Option<PathBuf>,
}

#[derive(Debug, Clone, Copy)]
struct TimingProfile {
    concurrency: usize,
    timeout_ms: u64,
}

#[derive(Debug, Clone)]
struct OpenPort {
    ip: IpAddr,
    port: u16,
}

#[derive(Debug, Clone, Serialize)]
struct ScriptResult {
    script: String,
    status: String,
    details: String,
}

#[derive(Debug, Clone, Serialize)]
struct PortReport {
    ip: IpAddr,
    port: u16,
    state: &'static str,
    scripts: Vec<ScriptResult>,
}

#[derive(Debug, Serialize, Deserialize)]
struct WasmScanInput {
    ip: String,
    port: u16,
}

struct WasmEngine {
    engine: Engine,
    modules: Vec<(String, Module)>,
}

#[tokio::main]
async fn main() {
    if let Err(error) = run().await {
        eprintln!("[!] Error: {error:#}");
        std::process::exit(1);
    }
}

async fn run() -> Result<()> {
    let cli = Cli::parse_from(normalize_nmap_shortcuts(env::args_os()));

    let targets = resolve_targets(&cli.target)
        .await
        .with_context(|| format!("No se pudo resolver target '{}'", cli.target))?;

    if targets.is_empty() {
        bail!("No se encontraron IPs válidas para escanear");
    }

    let ports = parse_ports(&cli.ports)?;
    let timing = parse_timing(&cli.timing)?;

    let open_ports = scan_targets(&targets, &ports, timing).await;

    let wasm_engine = match &cli.script {
        Some(script_path) if !open_ports.is_empty() => Some(WasmEngine::load(script_path)?),
        _ => None,
    };

    let mut reports = Vec::with_capacity(open_ports.len());
    for open in open_ports {
        let scripts = if let Some(engine) = &wasm_engine {
            engine
                .run_scripts(open.ip, open.port)
                .with_context(|| format!("Falló la ejecución de scripts en {}:{}", open.ip, open.port))?
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

fn parse_timing(value: &str) -> Result<TimingProfile> {
    let upper = value.trim().to_uppercase();

    let profile = match upper.as_str() {
        "T1" => TimingProfile {
            concurrency: 64,
            timeout_ms: 2_500,
        },
        "T2" => TimingProfile {
            concurrency: 256,
            timeout_ms: 1_500,
        },
        "T3" => TimingProfile {
            concurrency: 1_024,
            timeout_ms: 800,
        },
        "T4" => TimingProfile {
            concurrency: 4_096,
            timeout_ms: 350,
        },
        "T5" => TimingProfile {
            concurrency: 12_288,
            timeout_ms: 120,
        },
        _ => bail!("Timing inválido '{}'. Valores permitidos: T1..T5", value),
    };

    Ok(profile)
}

fn parse_ports(raw: &str) -> Result<Vec<u16>> {
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

async fn resolve_targets(target: &str) -> Result<Vec<IpAddr>> {
    if let Ok(ip) = target.parse::<IpAddr>() {
        return Ok(vec![ip]);
    }

    if target.contains('/') {
        let net: IpNet = target
            .parse()
            .with_context(|| format!("CIDR inválido: '{target}'"))?;

        return Ok(net.hosts().collect());
    }

    if let Some((start_text, end_text)) = target.split_once('-') {
        let start: Ipv4Addr = start_text
            .trim()
            .parse()
            .with_context(|| format!("IP inicial inválida: '{start_text}'"))?;
        let end: Ipv4Addr = end_text
            .trim()
            .parse()
            .with_context(|| format!("IP final inválida: '{end_text}'"))?;

        let start_u32 = u32::from(start);
        let end_u32 = u32::from(end);
        if start_u32 > end_u32 {
            bail!("Rango de IPs inválido: '{}'", target);
        }

        let ips = (start_u32..=end_u32)
            .map(|v| IpAddr::V4(Ipv4Addr::from(v)))
            .collect();

        return Ok(ips);
    }

    let mut resolved = BTreeSet::new();
    for socket in lookup_host((target, 0)).await? {
        resolved.insert(socket.ip());
    }

    Ok(resolved.into_iter().collect())
}

async fn scan_targets(targets: &[IpAddr], ports: &[u16], timing: TimingProfile) -> Vec<OpenPort> {
    let semaphore = Arc::new(Semaphore::new(timing.concurrency));
    let mut tasks = FuturesUnordered::new();

    for &ip in targets {
        for &port in ports {
            let semaphore = Arc::clone(&semaphore);
            let timeout_ms = timing.timeout_ms;

            tasks.push(tokio::spawn(async move {
                let permit = match semaphore.acquire_owned().await {
                    Ok(permit) => permit,
                    Err(_) => return None,
                };

                let addr = SocketAddr::new(ip, port);
                let result = timeout(
                    TokioDuration::from_millis(timeout_ms),
                    TokioTcpStream::connect(addr),
                )
                .await;

                drop(permit);

                match result {
                    Ok(Ok(_stream)) => Some(OpenPort { ip, port }),
                    _ => None,
                }
            }));
        }
    }

    let mut open_ports = Vec::new();
    while let Some(joined) = tasks.next().await {
        if let Ok(Some(open)) = joined {
            open_ports.push(open);
        }
    }

    open_ports.sort_by_key(|item| (item.ip, item.port));
    open_ports
}

impl WasmEngine {
    fn load(path: &Path) -> Result<Self> {
        let engine = Engine::default();
        let modules = load_wasm_modules(&engine, path)?;

        if modules.is_empty() {
            bail!("No se encontraron módulos Wasm en {}", path.display());
        }

        Ok(Self { engine, modules })
    }

    fn run_scripts(&self, ip: IpAddr, port: u16) -> Result<Vec<ScriptResult>> {
        let mut results = Vec::with_capacity(self.modules.len());

        for (script_name, module) in &self.modules {
            match self.run_single(module, ip, port) {
                Ok(output) => results.push(ScriptResult {
                    script: script_name.clone(),
                    status: "ok".to_string(),
                    details: output,
                }),
                Err(err) => results.push(ScriptResult {
                    script: script_name.clone(),
                    status: "error".to_string(),
                    details: format!("{err:#}"),
                }),
            }
        }

        Ok(results)
    }

    fn run_single(&self, module: &Module, ip: IpAddr, port: u16) -> Result<String> {
        // ABI diseñada (host <-> wasm guest):
        // - guest exporta: memory, alloc(i32)->i32, dealloc(i32,i32) [opcional], analyze(i32,i32)->i64
        // - host serializa {ip,port} en JSON y lo escribe en memory usando alloc.
        // - analyze retorna un i64 empaquetado: [ptr: u32 | len: u32].
        // - host lee ese buffer de salida y, si existe, llama dealloc.
        let input = WasmScanInput {
            ip: ip.to_string(),
            port,
        };
        let input_bytes = serde_json::to_vec(&input)?;

        let mut store = Store::new(&self.engine, ());
        let mut linker = Linker::new(&self.engine);
        linker.func_wrap(
            "env",
            "host_send_tcp",
            |mut caller: Caller<'_, ()>,
             ip_ptr: i32,
             ip_len: i32,
             port: i32,
             payload_ptr: i32,
             payload_len: i32|
             -> i64 {
                let pack = |ptr: i32, len: i32| -> i64 {
                    (((ptr as u32 as u64) << 32) | (len as u32 as u64)) as i64
                };

                if ip_ptr <= 0 || ip_len <= 0 || payload_ptr <= 0 || payload_len <= 0 {
                    return 0;
                }

                let Some(memory) = caller.get_export("memory").and_then(|item| item.into_memory())
                else {
                    return 0;
                };

                let Ok(ip_offset) = usize::try_from(ip_ptr) else {
                    return 0;
                };
                let Ok(ip_size) = usize::try_from(ip_len) else {
                    return 0;
                };
                let Ok(payload_offset) = usize::try_from(payload_ptr) else {
                    return 0;
                };
                let Ok(payload_size) = usize::try_from(payload_len) else {
                    return 0;
                };

                let memory_size = memory.data_size(&caller);

                let ip_end = match ip_offset.checked_add(ip_size) {
                    Some(end) if end <= memory_size => end,
                    _ => return 0,
                };

                let payload_end = match payload_offset.checked_add(payload_size) {
                    Some(end) if end <= memory_size => end,
                    _ => return 0,
                };

                if ip_end == ip_offset || payload_end == payload_offset {
                    return 0;
                }

                let mut ip_bytes = vec![0u8; ip_size];
                if memory.read(&caller, ip_offset, &mut ip_bytes).is_err() {
                    return 0;
                }

                let mut payload = vec![0u8; payload_size];
                if memory.read(&caller, payload_offset, &mut payload).is_err() {
                    return 0;
                }

                let ip_text = match std::str::from_utf8(&ip_bytes) {
                    Ok(text) => text,
                    Err(_) => return 0,
                };

                let ip_addr = match ip_text.parse::<IpAddr>() {
                    Ok(addr) => addr,
                    Err(_) => return 0,
                };

                let port_u16 = match u16::try_from(port) {
                    Ok(value) if value > 0 => value,
                    _ => return 0,
                };

                let socket = SocketAddr::new(ip_addr, port_u16);
                let mut stream = match TcpStream::connect_timeout(&socket, Duration::from_secs(2)) {
                    Ok(stream) => stream,
                    Err(_) => return 0,
                };

                let _ = stream.set_read_timeout(Some(Duration::from_secs(2)));
                let _ = stream.set_write_timeout(Some(Duration::from_secs(2)));

                if stream.write_all(&payload).is_err() {
                    return 0;
                }

                let mut response = Vec::new();
                let mut temp = [0u8; 4096];

                loop {
                    match stream.read(&mut temp) {
                        Ok(0) => break,
                        Ok(n) => response.extend_from_slice(&temp[..n]),
                        Err(err)
                            if err.kind() == std::io::ErrorKind::TimedOut
                                || err.kind() == std::io::ErrorKind::WouldBlock =>
                        {
                            break;
                        }
                        Err(_) => return 0,
                    }
                }

                if response.is_empty() {
                    return 0;
                }

                let out_len = match i32::try_from(response.len()) {
                    Ok(len) => len,
                    Err(_) => return 0,
                };

                let Some(alloc_func) = caller.get_export("alloc").and_then(|item| item.into_func())
                else {
                    return 0;
                };

                let alloc = match alloc_func.typed::<i32, i32>(&caller) {
                    Ok(func) => func,
                    Err(_) => return 0,
                };

                let out_ptr = match alloc.call(&mut caller, out_len) {
                    Ok(ptr) if ptr > 0 => ptr,
                    _ => return 0,
                };

                let Ok(out_offset) = usize::try_from(out_ptr) else {
                    return 0;
                };
                let Ok(out_size) = usize::try_from(out_len) else {
                    return 0;
                };

                let write_end = match out_offset.checked_add(out_size) {
                    Some(end) if end <= memory.data_size(&caller) => end,
                    _ => return 0,
                };

                if write_end == out_offset {
                    return 0;
                }

                if memory.write(&mut caller, out_offset, &response).is_err() {
                    return 0;
                }

                pack(out_ptr, out_len)
            },
        )?;
        let instance = linker
            .instantiate(&mut store, module)
            .context("No se pudo instanciar el módulo Wasm")?;

        let memory = instance
            .get_memory(&mut store, "memory")
            .ok_or_else(|| anyhow!("El módulo no exporta 'memory'"))?;

        let alloc = instance
            .get_typed_func::<i32, i32>(&mut store, "alloc")
            .context("El módulo no exporta alloc(i32)->i32")?;

        let analyze = instance
            .get_typed_func::<(i32, i32), i64>(&mut store, "analyze")
            .context("El módulo no exporta analyze(i32,i32)->i64")?;

        let dealloc = instance.get_typed_func::<(i32, i32), ()>(&mut store, "dealloc").ok();

        let in_len = i32::try_from(input_bytes.len()).context("Input demasiado grande para ABI i32")?;
        let in_ptr = alloc.call(&mut store, in_len)?;

        memory
            .write(
                &mut store,
                usize::try_from(in_ptr).context("Puntero alloc inválido")?,
                &input_bytes,
            )
            .context("No se pudo escribir input en memoria Wasm")?;

        let packed = analyze.call(&mut store, (in_ptr, in_len))?;

        if let Some(func) = &dealloc {
            let _ = func.call(&mut store, (in_ptr, in_len));
        }

        let packed = packed as u64;
        let out_ptr = (packed >> 32) as u32;
        let out_len = (packed & 0xFFFF_FFFF) as u32;

        if out_len == 0 {
            return Ok(String::new());
        }

        let out_offset = usize::try_from(out_ptr).context("Puntero de salida inválido")?;
        let out_size = usize::try_from(out_len).context("Longitud de salida inválida")?;

        let memory_size = memory.data_size(&store);
        let end = out_offset
            .checked_add(out_size)
            .ok_or_else(|| anyhow!("Overflow al leer salida de Wasm"))?;

        if end > memory_size {
            bail!(
                "Salida Wasm fuera de límites de memoria (offset={}, len={}, memory={})",
                out_offset,
                out_size,
                memory_size
            );
        }

        let mut output = vec![0u8; out_size];
        memory
            .read(&store, out_offset, &mut output)
            .context("No se pudo leer salida de memoria Wasm")?;

        if let Some(func) = &dealloc {
            let out_ptr_i32 = i32::try_from(out_ptr).context("Puntero de salida fuera de rango i32")?;
            let out_len_i32 = i32::try_from(out_len).context("Longitud de salida fuera de rango i32")?;
            let _ = func.call(&mut store, (out_ptr_i32, out_len_i32));
        }

        let text = String::from_utf8(output).context("Salida Wasm no es UTF-8")?;
        Ok(text)
    }
}

fn load_wasm_modules(engine: &Engine, path: &Path) -> Result<Vec<(String, Module)>> {
    if path.is_file() {
        let module = Module::from_file(engine, path)
            .with_context(|| format!("No se pudo cargar módulo {}", path.display()))?;
        let name = path
            .file_name()
            .and_then(|x| x.to_str())
            .unwrap_or("script.wasm")
            .to_string();
        return Ok(vec![(name, module)]);
    }

    if path.is_dir() {
        let mut modules = Vec::new();

        for entry in fs::read_dir(path)? {
            let entry = entry?;
            let file_path = entry.path();

            let is_wasm = file_path
                .extension()
                .and_then(|ext| ext.to_str())
                .map(|ext| ext.eq_ignore_ascii_case("wasm"))
                .unwrap_or(false);

            if !is_wasm {
                continue;
            }

            let module = Module::from_file(engine, &file_path)
                .with_context(|| format!("No se pudo cargar módulo {}", file_path.display()))?;

            let name = file_path
                .file_name()
                .and_then(|x| x.to_str())
                .unwrap_or("unknown.wasm")
                .to_string();

            modules.push((name, module));
        }

        modules.sort_by(|a, b| a.0.cmp(&b.0));
        return Ok(modules);
    }

    bail!("La ruta de script no existe: {}", path.display())
}

fn print_report(reports: &[PortReport]) {
    if reports.is_empty() {
        println!("No se encontraron puertos abiertos.");
        return;
    }

    println!("Puertos abiertos detectados:\n");

    for report in reports {
        println!("{} {:>5}/tcp {}", report.ip, report.port, report.state);

        for script in &report.scripts {
            println!(
                "  ├─ script={} status={} details={}",
                script.script, script.status, script.details
            );
        }
    }
}

fn write_report_file(path: &Path, reports: &[PortReport]) -> Result<()> {
    let mut file = fs::File::create(path)
        .with_context(|| format!("No se pudo crear archivo {}", path.display()))?;

    writeln!(file, "# RustProbe Report")?;
    writeln!(file, "# Open ports: {}", reports.len())?;
    writeln!(file)?;

    for report in reports {
        writeln!(file, "{} {:>5}/tcp {}", report.ip, report.port, report.state)?;

        for script in &report.scripts {
            writeln!(
                file,
                "  script={} status={} details={}",
                script.script, script.status, script.details
            )?;
        }
    }

    Ok(())
}
