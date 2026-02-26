# Scripts Wasm para RustProbe

## 1) Ejecutar RustProbe con plugin

Los scripts Wasm en RustProbe son **opt-in**:

- Sin `--script` ni `-C`, no se ejecuta ningún script Wasm.
- Con `--script`, se ejecutan scripts específicos por nombre.
- Con `-C` / `--default-scripts`, se ejecutan todos los scripts del directorio estándar local.

Ejemplos (localhost, puertos comunes):

```powershell
cargo run -- 127.0.0.1 -p 22,80,443 -T T4 --script sample_plugin -oN ./scan.txt
cargo run -- 127.0.0.1 -p 22,80,443 -T T4 -C -oN ./scan.txt
```

## 2) Compilar todos los plugins automáticamente

Detecta cualquier subdirectorio dentro de `scripts/` que contenga `Cargo.toml` y compila todos los plugins Wasm sin listar nombres manualmente.

Compila plugins en paralelo automáticamente.

Además del `.wasm` local en `scripts/`, los scripts despliegan automáticamente los plugins al directorio runtime estándar de RustProbe (`data_dir()/scripts`) para que `--script` use la versión recién compilada.

### Windows (PowerShell)

Desde la raíz del proyecto:

```powershell
./scripts/build_all_plugins.ps1
```

### Linux/macOS (Bash)

Desde la raíz del proyecto:

```bash
chmod +x ./scripts/build_all_plugins.sh
./scripts/build_all_plugins.sh
```

Notas:

- `--script` recibe nombres separados por coma (ej. `--script sample_plugin,http_title`).
- Los nombres se buscan en el directorio local estándar (`data_dir()/scripts`).
- Puedes sobreescribir el destino runtime con la variable `RUSTPROBE_SCRIPTS_DIR`.
- El target de compilación por defecto es `wasm32-unknown-unknown` (compatible con el runtime actual de RustProbe, sin WASI). Puedes sobreescribirlo con `RUSTPROBE_WASM_TARGET`.

## ABI esperada por el host

El módulo Wasm debe exportar:

- `memory`
- `alloc(i32) -> i32`
- `analyze(i32, i32) -> i64`
- `dealloc(i32, i32)` (opcional)

`analyze` retorna un `i64` empaquetado:

- 32 bits altos: `ptr`
- 32 bits bajos: `len`

Entrada que recibe el plugin (JSON):

```json
{ "ip": "127.0.0.1", "port": 80 }
```
