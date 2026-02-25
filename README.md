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
- Plugin de ejemplo hace petición HTTP y extrae el header Server.

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
./scripts/build_sample_plugin.ps1
```

Esto genera scripts/sample_plugin.wasm.

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
- --script: nombre(s) de script Wasm (ej. `--script smb,http`).
	- Los nombres se resuelven en el directorio local estándar del usuario en `data_dir()/scripts`.
	- Ejemplos típicos: Linux `~/.local/share/rustprobe/scripts`, Windows `%APPDATA%\rustprobe\scripts`.
- -o, --output: archivo de salida.
- Compatibilidad Nmap: -oN archivo o -oNarchivo.

Ejemplos:

```powershell
cargo run -- 127.0.0.1 -p 80,443,90 -T T3
cargo run -- 192.0.2.10-192.0.2.20 -p 1-1024 -oN ./scan.txt
cargo run -- 127.0.0.1 -p 80,443 --script smb
cargo run -- example.com -p 80,443 --script smb,http
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

Cuando no se usa --script, rustprobe busca y ejecuta todos los plugins Wasm del directorio local estándar.
Si ese directorio no tiene archivos `.wasm`, se muestra un mensaje informativo y se continúa el escaneo sin análisis Wasm.
Si se usa --script, solo se cargan y ejecutan los scripts solicitados por nombre.

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

- env.host_send_tcp(ip_ptr, ip_len, port, payload_ptr, payload_len) -> i64

Contrato:

1. Guest pasa IP y payload como puntero+longitud en memoria Wasm.
2. Host valida rangos de memoria.
3. Host abre TCP sincrónico con timeout (2s), envía payload y lee respuesta.
4. Host reserva buffer en guest llamando alloc(len), escribe respuesta y retorna ptr/len empaquetado.
5. Guest copia respuesta y llama dealloc(ptr,len) para liberar.

Si falla conexión/lectura o hay error de ABI, retorna 0.

---

## Plugin de ejemplo

Código: [scripts/sample_plugin/src/lib.rs](scripts/sample_plugin/src/lib.rs)

Qué hace actualmente:

- Importa host_send_tcp.
- Construye GET / HTTP/1.1.
- Envía petición al target:puerto descubierto.
- Parsea cabeceras HTTP y extrae Server.
- Devuelve JSON con plugin, summary, server y severity.

---

## Estructura del proyecto

- [src/main.rs](src/main.rs): CLI, escaneo, Wasm runtime, salida.
- [scripts/sample_plugin](scripts/sample_plugin): plugin Wasm de referencia.
- [scripts/build_sample_plugin.ps1](scripts/build_sample_plugin.ps1): build del plugin.
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
