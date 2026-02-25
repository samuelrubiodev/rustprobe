use anyhow::{bail, Context, Result};
use reqwest::Client;
use serde_json::Value;
use std::path::Path;

const GITHUB_SCRIPTS_API: &str =
    "https://api.github.com/repos/samuelrubiodev/rustprobe/contents/scripts";

pub async fn update_scripts(scripts_dir: &Path) -> Result<()> {
    let client = Client::builder().user_agent("rustprobe-cli").build()?;

    let response = client
        .get(GITHUB_SCRIPTS_API)
        .send()
        .await
        .context("No se pudo consultar la API de GitHub")?;

    let status = response.status();
    if !status.is_success() {
        bail!("La API de GitHub devolvió un estado no exitoso: {status}");
    }

    let payload: Value = response
        .json()
        .await
        .context("No se pudo parsear la respuesta de GitHub")?;

    let entries = payload
        .as_array()
        .ok_or_else(|| anyhow::anyhow!("Respuesta inesperada de GitHub: se esperaba un array"))?;

    let mut downloaded = 0usize;

    for entry in entries {
        let name = entry.get("name").and_then(Value::as_str).unwrap_or_default();
        let item_type = entry.get("type").and_then(Value::as_str).unwrap_or_default();

        if item_type != "file" || !name.ends_with(".wasm") {
            continue;
        }

        let download_url = entry
            .get("download_url")
            .and_then(Value::as_str)
            .ok_or_else(|| anyhow::anyhow!("No se encontró download_url para '{name}'"))?;

        println!("[i] Descargando plugin: {name}...");

        let bytes = client
            .get(download_url)
            .send()
            .await
            .with_context(|| format!("No se pudo descargar '{name}'"))?
            .error_for_status()
            .with_context(|| format!("Error HTTP al descargar '{name}'"))?
            .bytes()
            .await
            .with_context(|| format!("No se pudieron leer los bytes de '{name}'"))?;

        let destination = scripts_dir.join(name);
        tokio::fs::write(&destination, &bytes)
            .await
            .with_context(|| format!("No se pudo escribir '{}':", destination.display()))?;

        downloaded += 1;
    }

    if downloaded == 0 {
        println!("[i] No se encontraron archivos .wasm para actualizar.");
    } else {
        println!("[+] Plugins actualizados: {downloaded}");
    }

    Ok(())
}
