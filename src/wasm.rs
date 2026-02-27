use crate::models::{ScriptResult, WasmScanInput};
use anyhow::{anyhow, bail, Context, Result};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream as TokioTcpStream;
use tokio::time::{timeout, Duration};
use tokio_native_tls::{native_tls, TlsConnector};
use std::fs;
use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::path::Path;
use wasmtime::{Caller, Engine, Instance, Linker, Memory, Module, Store, TypedFunc};

pub struct WasmEngine {
    engine: Engine,
    modules: Vec<(String, Module)>,
}

impl WasmEngine {
    pub fn load(path: &Path) -> Result<Self> {
        let engine = Engine::default();
        let modules = load_wasm_modules(&engine, path)?;

        if modules.is_empty() {
            bail!("No se encontraron módulos Wasm en {}", path.display());
        }

        Ok(Self { engine, modules })
    }

    pub fn run_scripts(&self, ip: IpAddr, port: u16, hostname: Option<&str>) -> Result<Vec<ScriptResult>> {
        let mut results = Vec::with_capacity(self.modules.len());

        for (script_name, module) in &self.modules {
            let mut attempts = 0u8;
            let max_attempts = 4u8;

            loop {
                match self.run_single(module, ip, port, hostname) {
                    Ok(output) => {
                        results.push(ScriptResult {
                            script: script_name.clone(),
                            status: "ok".to_string(),
                            details: output,
                        });
                        break;
                    }
                    Err(err) => {
                        attempts = attempts.saturating_add(1);

                        if attempts < max_attempts && is_too_many_open_files(&err) {
                            let backoff_ms = 30u64.saturating_mul(1u64 << attempts.min(5));
                            std::thread::sleep(std::time::Duration::from_millis(backoff_ms));
                            continue;
                        }

                        results.push(ScriptResult {
                            script: script_name.clone(),
                            status: "error".to_string(),
                            details: format!("{err:#}"),
                        });
                        break;
                    }
                }
            }
        }

        Ok(results)
    }

    pub fn load_named_from_dir(dir: &Path, script_names: &[String]) -> Result<Self> {
        let engine = Engine::default();
        let modules = load_named_wasm_modules(&engine, dir, script_names)?;
        Ok(Self { engine, modules })
    }

    fn run_single(&self, module: &Module, ip: IpAddr, port: u16, hostname: Option<&str>) -> Result<String> {
        let input_bytes = serialize_scan_input(ip, port, hostname)?;
        let (mut store, mut linker) = prepare_store_and_linker(&self.engine)?;

        let instance = instantiate_module(&mut store, &mut linker, module)?;
        let exports = resolve_exports(&mut store, &instance)?;

        let (in_ptr, in_len) =
            write_input_to_guest(&mut store, &exports.memory, &exports.alloc, &input_bytes)?;

        let packed = exports.analyze.call(&mut store, (in_ptr, in_len))?;

        if let Some(func) = &exports.dealloc {
            let _ = func.call(&mut store, (in_ptr, in_len));
        }

        let (out_ptr, out_len) = unpack_output(packed);
        read_output_from_guest(
            &mut store,
            &exports.memory,
            out_ptr,
            out_len,
            exports.dealloc.as_ref(),
        )
    }
}

struct GuestExports {
    memory: Memory,
    alloc: TypedFunc<i32, i32>,
    analyze: TypedFunc<(i32, i32), i64>,
    dealloc: Option<TypedFunc<(i32, i32), ()>>,
}

fn prepare_store_and_linker(engine: &Engine) -> Result<(Store<()>, Linker<()>)> {
    let store = Store::new(engine, ());
    let mut linker = Linker::new(engine);
    configure_host_send_tcp(&mut linker)?;
    Ok((store, linker))
}

fn configure_host_send_tcp(linker: &mut Linker<()>) -> Result<()> {
    linker.func_wrap("env", "host_send_tcp", host_send_tcp)?;
    Ok(())
}

fn instantiate_module(
    store: &mut Store<()>,
    linker: &mut Linker<()>,
    module: &Module,
) -> Result<Instance> {
    linker
        .instantiate(store, module)
        .context("No se pudo instanciar el módulo Wasm")
}

fn resolve_exports(store: &mut Store<()>, instance: &Instance) -> Result<GuestExports> {
    let memory = instance
        .get_memory(&mut *store, "memory")
        .ok_or_else(|| anyhow!("El módulo no exporta 'memory'"))?;

    let alloc = instance
        .get_typed_func::<i32, i32>(&mut *store, "alloc")
        .context("El módulo no exporta alloc(i32)->i32")?;

    let analyze = instance
        .get_typed_func::<(i32, i32), i64>(&mut *store, "analyze")
        .context("El módulo no exporta analyze(i32,i32)->i64")?;

    let dealloc = instance
        .get_typed_func::<(i32, i32), ()>(&mut *store, "dealloc")
        .ok();

    Ok(GuestExports {
        memory,
        alloc,
        analyze,
        dealloc,
    })
}

fn write_input_to_guest(
    store: &mut Store<()>,
    memory: &Memory,
    alloc: &TypedFunc<i32, i32>,
    input_bytes: &[u8],
) -> Result<(i32, i32)> {
    let in_len = i32::try_from(input_bytes.len()).context("Input demasiado grande para ABI i32")?;
    let in_ptr = alloc.call(&mut *store, in_len)?;

    memory
        .write(
            &mut *store,
            usize::try_from(in_ptr).context("Puntero alloc inválido")?,
            input_bytes,
        )
        .context("No se pudo escribir input en memoria Wasm")?;

    Ok((in_ptr, in_len))
}

fn unpack_output(packed: i64) -> (u32, u32) {
    let packed = packed as u64;
    ((packed >> 32) as u32, (packed & 0xFFFF_FFFF) as u32)
}

fn read_output_from_guest(
    store: &mut Store<()>,
    memory: &Memory,
    out_ptr: u32,
    out_len: u32,
    dealloc: Option<&TypedFunc<(i32, i32), ()>>,
) -> Result<String> {
    if out_len == 0 {
        return Ok(String::new());
    }

    let out_offset = usize::try_from(out_ptr).context("Puntero de salida inválido")?;
    let out_size = usize::try_from(out_len).context("Longitud de salida inválida")?;

    let memory_size = memory.data_size(&mut *store);
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
        .read(&mut *store, out_offset, &mut output)
        .context("No se pudo leer salida de memoria Wasm")?;

    if let Some(func) = dealloc {
        let out_ptr_i32 = i32::try_from(out_ptr).context("Puntero de salida fuera de rango i32")?;
        let out_len_i32 =
            i32::try_from(out_len).context("Longitud de salida fuera de rango i32")?;
        let _ = func.call(&mut *store, (out_ptr_i32, out_len_i32));
    }

    let text = String::from_utf8(output).context("Salida Wasm no es UTF-8")?;
    Ok(text)
}

fn serialize_scan_input(ip: IpAddr, port: u16, hostname: Option<&str>) -> Result<Vec<u8>> {
    let input = WasmScanInput {
        ip: ip.to_string(),
        port,
        hostname: hostname.map(|value| value.to_string()),
    };
    Ok(serde_json::to_vec(&input)?)
}

fn host_send_tcp(
    mut caller: Caller<'_, ()>,
    ip_ptr: i32,
    ip_len: i32,
    port: i32,
    payload_ptr: i32,
    payload_len: i32,
    use_tls: i32,
    host_ptr: i32,
    host_len: i32,
) -> i64 {
    if ip_ptr <= 0 || ip_len <= 0 {
        return 0;
    }

    let Some(memory) = caller
        .get_export("memory")
        .and_then(|item| item.into_memory())
    else {
        return 0;
    };

    let Ok(ip_offset) = usize::try_from(ip_ptr) else {
        return 0;
    };
    let Ok(ip_size) = usize::try_from(ip_len) else {
        return 0;
    };
    let has_payload = payload_ptr > 0 && payload_len > 0;
    let payload_bounds = if has_payload {
        let Ok(payload_offset) = usize::try_from(payload_ptr) else {
            return 0;
        };
        let Ok(payload_size) = usize::try_from(payload_len) else {
            return 0;
        };
        Some((payload_offset, payload_size))
    } else {
        None
    };

    let memory_size = memory.data_size(&caller);

    let ip_end = match ip_offset.checked_add(ip_size) {
        Some(end) if end <= memory_size => end,
        _ => return 0,
    };

    if ip_end == ip_offset {
        return 0;
    }

    let mut ip_bytes = vec![0u8; ip_size];
    if memory.read(&caller, ip_offset, &mut ip_bytes).is_err() {
        return 0;
    }

    let payload = if let Some((payload_offset, payload_size)) = payload_bounds {
        let payload_end = match payload_offset.checked_add(payload_size) {
            Some(end) if end <= memory_size => end,
            _ => return 0,
        };

        if payload_end == payload_offset {
            None
        } else {
            let mut payload = vec![0u8; payload_size];
            if memory.read(&caller, payload_offset, &mut payload).is_err() {
                return 0;
            }
            Some(payload)
        }
    } else {
        None
    };

    let host = if host_ptr > 0 && host_len > 0 {
        let Ok(host_offset) = usize::try_from(host_ptr) else {
            return 0;
        };
        let Ok(host_size) = usize::try_from(host_len) else {
            return 0;
        };

        let host_end = match host_offset.checked_add(host_size) {
            Some(end) if end <= memory_size => end,
            _ => return 0,
        };

        if host_end == host_offset {
            String::new()
        } else {
            let mut host_bytes = vec![0u8; host_size];
            if memory.read(&caller, host_offset, &mut host_bytes).is_err() {
                return 0;
            }

            match std::str::from_utf8(&host_bytes) {
                Ok(value) => value.trim().to_string(),
                Err(_) => return 0,
            }
        }
    } else {
        String::new()
    };

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

    let tls_hostname = if host.is_empty() {
        ip_text.to_string()
    } else {
        host
    };

    let response = match run_tcp_exchange(ip_addr, port_u16, payload, use_tls == 1, tls_hostname) {
        Ok(response) => response,
        Err(_) => return 0,
    };

    if response.is_empty() {
        return 0;
    }

    let out_len = match i32::try_from(response.len()) {
        Ok(len) => len,
        Err(_) => return 0,
    };

    let Some(alloc_func) = caller.get_export("alloc").and_then(|item| item.into_func()) else {
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

    pack_ptr_len(out_ptr, out_len)
}

fn run_tcp_exchange(
    ip_addr: IpAddr,
    port: u16,
    payload: Option<Vec<u8>>,
    use_tls: bool,
    tls_hostname: String,
) -> Result<Vec<u8>> {
    tokio::task::block_in_place(|| {
        tokio::runtime::Handle::current()
            .block_on(tcp_exchange_async(ip_addr, port, payload, use_tls, tls_hostname))
    })
}

async fn tcp_exchange_async(
    ip_addr: IpAddr,
    port: u16,
    payload: Option<Vec<u8>>,
    use_tls: bool,
    tls_hostname: String,
) -> Result<Vec<u8>> {
    let socket = SocketAddr::new(ip_addr, port);
    let stream = timeout(Duration::from_secs(4), TokioTcpStream::connect(socket))
        .await
        .context("Timeout al conectar por TCP")?
        .context("No se pudo conectar por TCP")?;

    let is_null_probe = payload.as_ref().map_or(true, |data| data.is_empty());

    if use_tls {
        let mut builder = native_tls::TlsConnector::builder();
        builder.danger_accept_invalid_certs(true);
        builder.danger_accept_invalid_hostnames(true);

        let connector = builder
            .build()
            .context("No se pudo crear conector TLS")?;
        let connector = TlsConnector::from(connector);
        let domain = if tls_hostname.trim().is_empty() {
            ip_addr.to_string()
        } else {
            tls_hostname
        };

        let mut tls_stream = timeout(Duration::from_secs(3), connector.connect(&domain, stream))
            .await
            .context("Timeout durante handshake TLS")?
            .context("Handshake TLS fallido")?;

        write_payload_if_any(&mut tls_stream, payload.as_deref()).await?;
        return read_response_with_timeout(&mut tls_stream, is_null_probe).await;
    }

    let mut tcp_stream = stream;
    write_payload_if_any(&mut tcp_stream, payload.as_deref()).await?;
    read_response_with_timeout(&mut tcp_stream, is_null_probe).await
}

async fn write_payload_if_any<S>(stream: &mut S, payload: Option<&[u8]>) -> Result<()>
where
    S: AsyncWrite + Unpin,
{
    let Some(data) = payload else {
        return Ok(());
    };

    if data.is_empty() {
        return Ok(());
    }

    timeout(Duration::from_secs(2), stream.write_all(data))
        .await
        .context("Timeout al escribir payload")?
        .context("No se pudo enviar payload")?;

    Ok(())
}

async fn read_response_with_timeout<S>(stream: &mut S, wait_first_chunk: bool) -> Result<Vec<u8>>
where
    S: AsyncRead + Unpin,
{
    let mut response = Vec::new();
    let mut temp = [0u8; 4096];
    let first_chunk_timeout = if wait_first_chunk {
        Duration::from_secs(4)
    } else {
        Duration::from_millis(3_000)
    };
    let chunk_timeout = Duration::from_millis(3_000);

    if wait_first_chunk {
        match timeout(first_chunk_timeout, stream.read(&mut temp)).await {
            Ok(Ok(0)) => return Ok(response),
            Ok(Ok(n)) => response.extend_from_slice(&temp[..n]),
            Ok(Err(err))
                if err.kind() == std::io::ErrorKind::TimedOut
                    || err.kind() == std::io::ErrorKind::WouldBlock =>
            {
                return Ok(response);
            }
            Ok(Err(err)) => return Err(err.into()),
            Err(_) => return Ok(response),
        }
    }

    loop {
        match timeout(chunk_timeout, stream.read(&mut temp)).await {
            Ok(Ok(0)) => break,
            Ok(Ok(n)) => response.extend_from_slice(&temp[..n]),
            Ok(Err(err))
                if err.kind() == std::io::ErrorKind::TimedOut
                    || err.kind() == std::io::ErrorKind::WouldBlock =>
            {
                break;
            }
            Ok(Err(err)) => return Err(err.into()),
            Err(_) => break,
        }
    }

    Ok(response)
}

fn pack_ptr_len(ptr: i32, len: i32) -> i64 {
    (((ptr as u32 as u64) << 32) | (len as u32 as u64)) as i64
}

fn is_too_many_open_files(error: &anyhow::Error) -> bool {
    error.chain().any(|cause| {
        let message = cause.to_string().to_ascii_lowercase();
        message.contains("too many open files") || message.contains("os error 24")
    })
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

fn load_named_wasm_modules(
    engine: &Engine,
    dir: &Path,
    script_names: &[String],
) -> Result<Vec<(String, Module)>> {
    if !dir.is_dir() {
        bail!("El directorio de scripts no existe: {}", dir.display());
    }

    let mut available = HashMap::<String, std::path::PathBuf>::new();

    for entry in fs::read_dir(dir)? {
        let entry = entry?;
        let path = entry.path();

        let is_wasm = path
            .extension()
            .and_then(|ext| ext.to_str())
            .map(|ext| ext.eq_ignore_ascii_case("wasm"))
            .unwrap_or(false);

        if !is_wasm {
            continue;
        }

        if let Some(stem) = path.file_stem().and_then(|v| v.to_str()) {
            available.insert(stem.to_ascii_lowercase(), path.clone());
        }

        if let Some(name) = path.file_name().and_then(|v| v.to_str()) {
            available.insert(name.to_ascii_lowercase(), path.clone());
        }
    }

    let mut modules = Vec::new();

    for raw_name in script_names {
        let name = raw_name.trim();
        if name.is_empty() {
            bail!("Se recibió un nombre de script vacío en --script");
        }

        let key = name.to_ascii_lowercase();
        let path = if let Some(path) = available.get(&key) {
            path.clone()
        } else {
            let with_ext = format!("{}.wasm", key);
            available.get(&with_ext).cloned().ok_or_else(|| {
                anyhow!(
                    "No se encontró el script '{}' en {}",
                    name,
                    dir.display()
                )
            })?
        };

        let module = Module::from_file(engine, &path)
            .with_context(|| format!("No se pudo cargar módulo {}", path.display()))?;

        let module_name = path
            .file_name()
            .and_then(|x| x.to_str())
            .unwrap_or("unknown.wasm")
            .to_string();

        modules.push((module_name, module));
    }

    Ok(modules)
}
