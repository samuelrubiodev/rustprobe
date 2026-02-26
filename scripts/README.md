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
