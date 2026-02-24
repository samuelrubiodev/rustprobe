# RustProbe

RustProbe es un escáner de red de alto rendimiento escrito en Rust, diseñado como base moderna tipo Nmap para:

- Descubrimiento rápido de puertos TCP (`TCP Connect Scan`) con `tokio`.
- Ejecución de análisis profundo con plugins WebAssembly (`.wasm`).
- Arquitectura extensible y segura para evolucionar hacia detección de servicios, banners y CVEs.

> ⚠️ Uso ético: ejecuta RustProbe solo sobre activos propios o con autorización explícita.

---

## Características actuales

- CLI robusta con `clap` (derive).
- Targets soportados:
  - IP única (IPv4/IPv6).
  - Rango IPv4 (`192.168.1.10-192.168.1.50`).
  - CIDR (`10.0.0.0/24`).
  - Dominio (resolución DNS).
- Selección de puertos:
  - Lista (`80,443,8080`).
  - Rango (`1-1024`).
  - Todos (`-` => `1..65535`).
- Plantillas de timing estilo Nmap (`T1..T5`) para ajustar concurrencia y timeout.
- Motor Wasm con `wasmtime` para ejecutar scripts sobre puertos abiertos.
- Reporte estructurado por consola y salida a archivo (`--output` o `-oN`).

---

## Stack tecnológico

- Rust 2021
- `tokio` (IO asíncrona y concurrencia masiva)
- `clap` con `derive` (CLI)
- `wasmtime` (runtime WebAssembly)
- `anyhow` (manejo de errores)
- `serde` / `serde_json` (serialización host-guest)

Dependencias exactas en [Cargo.toml](Cargo.toml).

---

## Instalación

### Requisitos

- Rustup + toolchain estable de Rust
- En Windows (MSVC): Build Tools instalados (`link.exe` disponible)
- Para compilar plugins Wasm:

```powershell
rustup target add wasm32-unknown-unknown
```

### Compilar el proyecto

```powershell
cargo check
cargo build
```

---

## Uso de RustProbe

### Ayuda

```powershell
cargo run -- --help
```

### Sintaxis base

```powershell
cargo run -- <target> [opciones]
```

### Flags soportadas

- `target` (posicional, obligatorio)
  - IP, rango IPv4, CIDR o dominio.
- `-p, --ports <spec>`
  - Ejemplos: `80,443`, `1-1000`, `-`.
- `-T, --timing <T1|T2|T3|T4|T5>`
  - Controla timeout y concurrencia.
- `--script <ruta>`
  - Archivo `.wasm` o directorio con múltiples `.wasm`.
- `-o, --output <ruta>`
  - Guarda reporte en archivo de texto.
- Compatibilidad adicional:
  - `-oN <ruta>` y `-oNruta.txt` se normalizan internamente a `--output`.

### Ejemplos

Escaneo rápido de puertos comunes:

```powershell
cargo run -- 192.168.1.10 -p 22,80,443 -T T4
```

Escaneo de rango con salida a archivo:

```powershell
cargo run -- 192.168.1.10-192.168.1.20 -p 1-1024 -T T3 -oN ./scan.txt
```

Escaneo con plugin Wasm:

```powershell
cargo run -- 127.0.0.1 -p 22,80,443 -T T4 --script ./scripts/sample_plugin.wasm
```

Cargar todos los plugins de un directorio:

```powershell
cargo run -- example.com -p 80,443 -T T3 --script ./scripts
```

---

## Arquitectura

El flujo principal en [src/main.rs](src/main.rs) está dividido en etapas claras:

1. Parseo y normalización CLI
   - `Cli::parse_from(normalize_nmap_shortcuts(...))`
2. Resolución/validación de targets
   - `resolve_targets()`
3. Parseo/validación de puertos
   - `parse_ports()`
4. Selección de perfil de timing
   - `parse_timing()`
5. Descubrimiento TCP asíncrono
   - `scan_targets()`
6. Carga de módulos Wasm (si aplica)
   - `WasmEngine::load()`
7. Ejecución de scripts por puerto abierto
   - `WasmEngine::run_scripts()`
8. Reporte por consola y archivo
   - `print_report()` y `write_report_file()`

### Modelo de concurrencia

- Se crea una tarea async por combinación target:port.
- Un `Semaphore` limita concurrencia efectiva según perfil `T1..T5`.
- Cada conexión usa `tokio::time::timeout` + `TcpStream::connect`.
- Un resultado exitoso de connect se marca como puerto `open`.

### Plantillas `-T` actuales

- `T1`: `concurrency=64`, `timeout=2500ms`
- `T2`: `concurrency=256`, `timeout=1500ms`
- `T3`: `concurrency=1024`, `timeout=800ms`
- `T4`: `concurrency=4096`, `timeout=350ms`
- `T5`: `concurrency=12288`, `timeout=120ms`

> Nota: estos valores son iniciales (baseline) y pueden calibrarse por red/latencia real.

---

## Motor de Plugins Wasm

RustProbe ejecuta scripts Wasm únicamente sobre puertos abiertos (fase 2).

### Carga de módulos

- Si `--script` apunta a un archivo, carga ese módulo.
- Si apunta a un directorio, carga todos los `.wasm` (ordenados por nombre).

### ABI host ↔ guest

El guest debe exportar:

- `memory`
- `alloc(i32) -> i32`
- `analyze(i32, i32) -> i64`
- `dealloc(i32, i32)` (opcional)

#### Protocolo de intercambio

1. Host serializa entrada JSON:

```json
{ "ip": "127.0.0.1", "port": 80 }
```

2. Host llama `alloc(len)` y copia bytes en `memory` del guest.
3. Host invoca `analyze(ptr, len)`.
4. Guest retorna `i64` empaquetado:
   - 32 bits altos: `out_ptr`
   - 32 bits bajos: `out_len`
5. Host lee `memory[out_ptr..out_ptr+out_len]` como UTF-8.
6. Host libera memoria con `dealloc` (si está disponible).

#### Formato de salida recomendado

Actualmente RustProbe espera texto UTF-8, por lo que es recomendable devolver JSON serializado como string para resultados estructurados.

---

## Crear scripts Wasm

Ya tienes un ejemplo funcional en:

- [scripts/sample_plugin/src/lib.rs](scripts/sample_plugin/src/lib.rs)

### Compilar el plugin de ejemplo

```powershell
./scripts/build_sample_plugin.ps1
```

Esto genera:

- `./scripts/sample_plugin.wasm`

Luego ejecútalo con RustProbe usando `--script`.

### Plantilla mínima conceptual de plugin

```rust
#[unsafe(no_mangle)]
pub extern "C" fn alloc(len: i32) -> i32 { /* ... */ }

#[unsafe(no_mangle)]
pub extern "C" fn dealloc(ptr: i32, len: i32) { /* ... */ }

#[unsafe(no_mangle)]
pub extern "C" fn analyze(input_ptr: i32, input_len: i32) -> i64 {
    // leer input JSON, procesar, devolver ptr/len empaquetado en i64
    0
}
```

---

## Formato de reporte

### Consola

- Si no hay puertos abiertos: `No se encontraron puertos abiertos.`
- Si hay resultados:
  - `IP PUERTO/tcp open`
  - Para cada script: `script=<name> status=<ok|error> details=<texto>`

### Archivo (`--output` / `-oN`)

Incluye cabecera y los mismos campos del reporte de consola.

---

## Estructura del proyecto

- [src/main.rs](src/main.rs): motor principal (CLI, scan, Wasm, reporte)
- [scripts/sample_plugin](scripts/sample_plugin): crate Rust para plugin Wasm de ejemplo
- [scripts/build_sample_plugin.ps1](scripts/build_sample_plugin.ps1): build y copiado del plugin
- [scripts/README.md](scripts/README.md): guía rápida de scripts

---

## Manejo de errores y robustez

- `anyhow::Result` + `Context` para trazabilidad clara de fallos.
- Validación de:
  - Puertos inválidos/rangos inválidos.
  - Targets no resolubles.
  - ABI Wasm incompleta o incompatible.
  - Punteros/longitudes fuera de límites en memoria Wasm.
  - UTF-8 inválido en salida del script.
- Falla de script Wasm no aborta todo el scan: se reporta `status=error` por script.

---

## Roadmap sugerido

- SYN scan (raw sockets / pcap) para mayor velocidad y menos costo por conexión.
- Detección de servicios (banner grabbing, fingerprinting).
- Salida JSON/XML compatible con pipelines y SIEM.
- Scheduler inteligente por latencia/host.
- Sandbox Wasm más estricto (límites de CPU/memoria por script).
- Reintentos adaptativos y rate limiting por destino.

---

## Licencia

Ver [LICENSE](LICENSE).
