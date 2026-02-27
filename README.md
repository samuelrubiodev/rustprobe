# RustProbe

Escáner de red de alto rendimiento escrito en Rust, con dos motores de escaneo y soporte para análisis extensible con plugins WebAssembly.

> ⚠️ Uso ético: úsalo solo sobre activos propios o con autorización explícita.

---

## Modos de escaneo

### TCP Connect (por defecto)
Establece el handshake TCP completo por cada puerto usando tokio asíncrono.  
Compatible con todos los entornos, sin privilegios especiales.

### SYN Stealth (`-s` / `--syn` / `-sS`) ⚡
Envía paquetes SYN crudos y captura las respuestas SYN-ACK sin completar el handshake.  
**~15× más rápido** que TCP Connect y no deja rastro en logs de aplicación.  
Requiere privilegios de **root / Administrador**.

| Modo | Velocidad (8 000 puertos, WAN) | Requiere root |
|------|-------------------------------|---------------|
| TCP Connect | ~40 s | No |
| SYN Stealth | ~2.5 s | Sí |

---

## Estado actual (2026-02)

- Escaneo SYN stealth con raw sockets (`pnet`): pacing por ráfagas, back-off ENOBUFS, ventana de drenado adaptativa.
- Escaneo TCP Connect asíncrono con tokio.
- Resultados en vivo en terminal (cada puerto aparece en el momento en que se detecta).
- Motor Wasm con wasmtime: análisis por puerto abierto con plugins.
- Plugins incluidos: `sample_plugin`, `http_title`, `service_detector`.
- `service_detector`: fingerprinting por banners, firmas regex y extracción de `<title>` HTTP.
- Auto-actualización de plugins desde GitHub (`--update`).

---

## Requisitos

- Rust estable (`rustup` recomendado).
- Windows: MSVC Build Tools instalados.
- Para compilar plugins Wasm:

```powershell
rustup target add wasm32-unknown-unknown
```

---

## Compilar

```powershell
cargo build --release
```

Para compilar todos los plugins Wasm:

```powershell
# Windows
./scripts/build_all_plugins.ps1

# Linux / macOS
chmod +x ./scripts/build_all_plugins.sh
./scripts/build_all_plugins.sh
```

Los `.wasm` compilados se despliegan automáticamente al directorio runtime estándar (`data_dir()/rustprobe/scripts`):
- Linux: `~/.local/share/rustprobe/scripts`
- Windows: `%APPDATA%\rustprobe\scripts`

---

## Uso

```
rustprobe <objetivo> [opciones]
```

### Opciones principales

| Flag | Descripción |
|------|-------------|
| `-p`, `--ports` | Puertos: `80,443`, `1-1024` o `-` para todos |
| `-s`, `--syn` | Modo SYN Stealth (root requerido). También acepta `-sS` |
| `-T`, `--timing` | Perfil de timing: T1..T5 (defecto T3) |
| `--script` | Script(s) Wasm por nombre, separados por coma |
| `-C`, `--default-scripts` | Ejecuta todos los scripts del directorio local |
| `-o`, `--output` | Archivo de salida (también acepta `-oN archivo`) |
| `--update` | Descarga los plugins Wasm oficiales desde GitHub |

### Ejemplos

```bash
# Escaneo rápido SYN sobre 8 000 puertos
sudo rustprobe 10.0.2.16 -p 1-8000 -s

# Equivalente con sintaxis nmap
sudo rustprobe 10.0.2.16 -p 1-8000 -sS

# TCP Connect estándar con scripts
rustprobe example.com -p 80,443 --script http_title,service_detector

# Escaneo de subred con todos los scripts locales
rustprobe 192.168.1.0/24 -p 1-1024 -C

# Guardar resultado
sudo rustprobe 10.0.2.16 -p 1-8000 -s -o resultado.txt

# Actualizar plugins
rustprobe --update
```

---

## Perfiles de timing

| Perfil | Concurrencia | Timeout |
|--------|-------------|---------|
| T1 | 64 | 2 500 ms |
| T2 | 256 | 1 500 ms |
| T3 | 1 024 | 800 ms |
| T4 | 4 096 | 350 ms |
| T5 | 12 288 | 120 ms |

---

## Plugins Wasm

Los plugins se cargan desde el directorio estándar del usuario y se ejecutan sobre cada puerto abierto.

Plugins incluidos:

| Plugin | Descripción |
|--------|-------------|
| `sample_plugin` | Petición HTTP básica y extracción de cabecera `Server` |
| `http_title` | Extracción de etiqueta `<title>` en respuestas HTTP |
| `service_detector` | Fingerprinting por banners, firmas regex y detección de servicios ocultos |

Código fuente de los plugins en [scripts/](scripts/).

---

## Estructura del proyecto

```
src/
  main.rs          — Punto de entrada, orquestación del escaneo
  cli.rs           — Parseo de argumentos CLI
  syn_scanner.rs   — Motor SYN stealth con raw sockets
  network.rs       — Motor TCP Connect asíncrono
  wasm.rs          — Runtime de plugins WebAssembly
  report.rs        — Salida en vivo y generación de informes
  models.rs        — Tipos compartidos
  services.rs      — Resolución de nombres de servicios
  config.rs        — Directorio de datos del usuario
  update.rs        — Auto-actualización de plugins
scripts/
  sample_plugin/   — Plugin Wasm de referencia
  http_title/      — Plugin Wasm para títulos web
  service_detector/— Plugin Wasm para fingerprinting
```

---

## Licencia

Ver [LICENSE](LICENSE).
