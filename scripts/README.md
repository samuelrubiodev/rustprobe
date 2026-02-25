# Scripts Wasm para RustProbe

## 1) Compilar plugin de ejemplo

Desde la raíz del proyecto:

```powershell
./scripts/build_sample_plugin.ps1
```

Esto genera:

- `./scripts/sample_plugin.wasm`

## 2) Ejecutar RustProbe con plugin

Los scripts Wasm en RustProbe son **opt-in**:

- Sin `--script` ni `-C`, no se ejecuta ningún script Wasm.
- Con `--script`, se ejecutan scripts específicos por nombre.
- Con `-C` / `--default-scripts`, se ejecutan todos los scripts del directorio estándar local.

Ejemplos (localhost, puertos comunes):

```powershell
cargo run -- 127.0.0.1 -p 22,80,443 -T T4 --script sample_plugin -oN ./scan.txt
cargo run -- 127.0.0.1 -p 22,80,443 -T T4 -C -oN ./scan.txt
```

## 3) Compilar plugin `http_title`

### Windows (PowerShell)

Desde la raíz del proyecto:

```powershell
./scripts/build_http_title_plugin.ps1
```

### Linux/macOS (Bash)

Desde la raíz del proyecto:

```bash
chmod +x ./scripts/build_http_title_plugin.sh
./scripts/build_http_title_plugin.sh
```

Ejecutar el plugin:

```powershell
cargo run -- 127.0.0.1 -p 80,8080,443 --script http_title -oN ./scan.txt
```

Notas:

- `--script` recibe nombres separados por coma (ej. `--script smb,http`).
- Los nombres se buscan en el directorio local estándar (`data_dir()/scripts`).

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
