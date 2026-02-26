# RustProbe

RustProbe es un escáner de red de alto rendimiento en Rust, orientado a arquitectura extensible con plugins WebAssembly.

- Escaneo TCP Connect asíncrono con tokio.
- Resultados en vivo en terminal (sin esperar al final).
- Motor Wasm con wasmtime para análisis por puerto abierto.
- ABI host↔guest para que los plugins ejecuten interacción de red real vía host_send_tcp.

> ⚠️ Uso ético: úsalo solo sobre activos propios o con autorización explícita.

---

## Estado actual (2026-02)

- Descubre puertos abiertos en tiempo real.
- Muestra puertos cerrados en rojo cuando el usuario define puertos explícitos (por ejemplo -p 80,443,90).
- Mantiene resumen final con abiertos/cerrados/comprobaciones.
- Soporta plugins Wasm con importación de función host_send_tcp.
- Incluye plugins Wasm de referencia listos para usar: `sample_plugin`, `http_title` y `service_detector`.
- `service_detector` aplica fingerprinting básico (Server, SSH, 220), firmas regex y extracción de `<title>` para servicios HTTP con cabeceras ocultas.

---

## Requisitos

- Rust estable (rustup recomendado).
- En Windows MSVC: Build Tools instalados.
- Para compilar plugins Wasm:

```powershell
rustup target add wasm32-unknown-unknown
```

---

## Compilar

```powershell
cargo check
cargo build
```

Para compilar el plugin de ejemplo:

```powershell
./scripts/build_all_plugins.ps1
```

Esto compila todos los plugins dentro de `scripts/*/Cargo.toml`, genera los `.wasm` en `scripts/` y los despliega al directorio runtime estándar (`data_dir()/scripts`).

En Linux/macOS:

```bash
chmod +x ./scripts/build_all_plugins.sh
./scripts/build_all_plugins.sh
```

---

## Uso CLI

Ayuda:

```powershell
cargo run -- --help
```

Sintaxis:

```powershell
cargo run -- <target> [opciones]
```

Opciones principales:

- target: IP, rango IPv4, CIDR o dominio.
- -p, --ports: lista, rango o - para todos.
- -T, --timing: T1..T5.
- --script: nombre(s) de script Wasm (ej. `--script sample_plugin,http_title`).
	- Los nombres se resuelven en el directorio local estándar del usuario en `data_dir()/scripts`.
	- Ejemplos típicos: Linux `~/.local/share/rustprobe/scripts`, Windows `%APPDATA%\rustprobe\scripts`.
- -C, --default-scripts: ejecuta todos los scripts Wasm del directorio local estándar (opt-in, equivalente a Nmap `-sC`).
- -o, --output: archivo de salida.
- Compatibilidad Nmap: -oN archivo o -oNarchivo.

Ejemplos:

```powershell
cargo run -- 127.0.0.1 -p 80,443,90 -T T3
cargo run -- 192.0.2.10-192.0.2.20 -p 1-1024 -oN ./scan.txt
cargo run -- 127.0.0.1 -p 80,443 --script service_detector
cargo run -- example.com -p 80,443 --script sample_plugin,http_title
cargo run -- 127.0.0.1 -p 80,443 -C
cargo run -- --update
cargo run -- 127.0.0.1 -p 80,443
```

---

## Salida en vivo y colores

Durante el escaneo se imprime una tabla en tiempo real:

- open en verde.
- closed en rojo (solo cuando -p no es -).
- Resumen final con conteo de abiertos, cerrados y total.

Comportamiento de color:

- Se habilita solo si stdout es terminal interactiva.
- Si NO_COLOR está definido, se desactiva color.

Por defecto (sin `--script` ni `-C`), rustprobe no inicializa el motor Wasm y realiza solo el escaneo de puertos.
Si se usa `--script`, solo se cargan y ejecutan los scripts solicitados por nombre.
Si se usa `-C`/`--default-scripts`, se cargan todos los plugins Wasm del directorio local estándar.
Si ese directorio no tiene archivos `.wasm`, se muestra un mensaje informativo y se continúa el escaneo sin análisis Wasm.

---

## Arquitectura de escaneo

Flujo principal en [src/main.rs](src/main.rs):

1. Parseo CLI y normalización de atajos.
2. Resolución de targets.
3. Parseo de puertos y timing.
4. Escaneo asíncrono TCP con Semaphore + timeout.
5. Ejecución de plugins Wasm sobre puertos abiertos.
6. Reporte por consola y salida opcional a archivo.

Perfiles de timing actuales:

- T1: concurrency=64, timeout=2500ms
- T2: concurrency=256, timeout=1500ms
- T3: concurrency=1024, timeout=800ms
- T4: concurrency=4096, timeout=350ms
- T5: concurrency=12288, timeout=120ms

---

## Motor de plugins Wasm

RustProbe carga módulos Wasm desde archivo o directorio y ejecuta analyze por cada puerto abierto.

### ABI base host↔guest

El plugin (guest) exporta:

- memory
- alloc(i32) -> i32
- analyze(i32, i32) -> i64
- dealloc(i32, i32) (recomendado)

Entrada que recibe analyze (JSON UTF-8):

```json
{ "ip": "127.0.0.1", "port": 80 }
```

Salida de analyze:

- i64 empaquetado: 32 bits altos ptr, 32 bits bajos len.
- El buffer de salida es UTF-8 (normalmente JSON serializado).

### Host function de red: host_send_tcp

El host exporta al plugin:

- env.host_send_tcp(ip_ptr, ip_len, port, payload_ptr, payload_len, use_tls) -> i64

Contrato:

1. Guest pasa IP y payload como puntero+longitud en memoria Wasm.
2. Host valida rangos de memoria.
3. Host abre TCP con timeout (2s); si use_tls=1, envuelve el stream en TLS y acepta certificados/hostnames inválidos.
4. Si payload_ptr<=0 o payload_len==0, host entra en modo "solo escucha" (no escribe, solo lee banner/respuesta).
5. Host reserva buffer en guest llamando alloc(len), escribe respuesta y retorna ptr/len empaquetado.
6. Guest copia respuesta y llama dealloc(ptr,len) para liberar.

Si falla conexión/lectura o hay error de ABI, retorna 0.

---

## Plugins Wasm incluidos

Código:

- [scripts/sample_plugin/src/lib.rs](scripts/sample_plugin/src/lib.rs)
- [scripts/http_title/src/lib.rs](scripts/http_title/src/lib.rs)
- [scripts/service_detector/src/lib.rs](scripts/service_detector/src/lib.rs)

Qué hace cada plugin:

- `sample_plugin`: petición HTTP básica y extracción de cabecera `Server`.
- `http_title`: detección de respuesta HTTP y extracción de etiqueta `<title>`.
- `service_detector`: identificación de servicio por headers/banners, firmas regex (incluyendo Golang y Tomcat) y fallback `HTTP Service (Unknown/Hidden)` con snippet limpio.

---

## Estructura del proyecto

- [src/main.rs](src/main.rs): CLI, escaneo, Wasm runtime, salida.
- [scripts/sample_plugin](scripts/sample_plugin): plugin Wasm de referencia.
- [scripts/http_title](scripts/http_title): plugin Wasm para extraer títulos web.
- [scripts/service_detector](scripts/service_detector): plugin Wasm para fingerprinting de servicios.
- [scripts/build_all_plugins.ps1](scripts/build_all_plugins.ps1): build paralelo de todos los plugins Wasm (Windows).
- [scripts/build_all_plugins.sh](scripts/build_all_plugins.sh): build paralelo de todos los plugins Wasm (Linux/macOS).
- [scripts/README.md](scripts/README.md): notas adicionales de scripts.

---

## Robustez y seguridad

- Validación de punteros/longitudes al cruzar la frontera host↔Wasm.
- Manejo de errores con anyhow + context.
- Timeout de red tanto en escaneo como en host_send_tcp.
- Falla de un plugin no aborta todo el escaneo; se reporta por script.

---

## Licencia

Ver [LICENSE](LICENSE).
