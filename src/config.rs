use anyhow::{anyhow, Context, Result};
use directories::ProjectDirs;
use std::fs;
use std::path::PathBuf;

pub fn ensure_default_scripts_dir() -> Result<PathBuf> {
    let project_dirs = ProjectDirs::from("", "", "rustprobe")
        .ok_or_else(|| anyhow!("No se pudo determinar el directorio de datos del usuario"))?;

    let scripts_dir = project_dirs.data_dir().join("scripts");

    fs::create_dir_all(&scripts_dir).with_context(|| {
        format!(
            "No se pudo crear el directorio de scripts local {}",
            scripts_dir.display()
        )
    })?;

    Ok(scripts_dir)
}

pub fn has_wasm_files(path: &std::path::Path) -> Result<bool> {
    let mut entries = fs::read_dir(path)
        .with_context(|| format!("No se pudo leer el directorio {}", path.display()))?;

    Ok(entries.any(|entry| {
        entry
            .ok()
            .map(|item| {
                item.path()
                    .extension()
                    .and_then(|ext| ext.to_str())
                    .map(|ext| ext.eq_ignore_ascii_case("wasm"))
                    .unwrap_or(false)
            })
            .unwrap_or(false)
    }))
}
