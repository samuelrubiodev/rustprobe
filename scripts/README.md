# Scripts Wasm para RustProbe

## 1) Compilar plugin de ejemplo

Desde la raíz del proyecto:

```powershell
./scripts/build_sample_plugin.ps1
```

Esto genera:

- `./scripts/sample_plugin.wasm`

## 2) Ejecutar RustProbe con plugin

Ejemplo (localhost, puertos comunes):

```powershell
cargo run -- 127.0.0.1 -p 22,80,443 -T T4 --script ./scripts/sample_plugin.wasm -oN ./scan.txt
```

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
