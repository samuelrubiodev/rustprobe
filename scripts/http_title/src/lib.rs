use serde::{Deserialize, Serialize};

#[derive(Debug, Deserialize)]
struct WasmScanInput {
    ip: String,
    port: u16,
    hostname: Option<String>,
}

#[derive(Debug, Serialize)]
struct WasmScanOutput {
    plugin: &'static str,
    summary: String,
    severity: &'static str,
}

unsafe extern "C" {
    fn host_send_tcp(
        ip_ptr: i32,
        ip_len: i32,
        port: i32,
        payload_ptr: i32,
        payload_len: i32,
        use_tls: i32,
        host_ptr: i32,
        host_len: i32,
    ) -> i64;
}

#[unsafe(no_mangle)]
pub extern "C" fn alloc(len: i32) -> i32 {
    if len <= 0 {
        return 0;
    }

    let mut buf = vec![0u8; len as usize].into_boxed_slice();
    let ptr = buf.as_mut_ptr();
    std::mem::forget(buf);
    ptr as i32
}

#[unsafe(no_mangle)]
pub extern "C" fn dealloc(ptr: i32, len: i32) {
    if ptr == 0 || len <= 0 {
        return;
    }

    unsafe {
        let _ = Vec::from_raw_parts(ptr as *mut u8, len as usize, len as usize);
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn analyze(input_ptr: i32, input_len: i32) -> i64 {
    if input_ptr == 0 || input_len <= 0 {
        return 0;
    }

    let input_slice = unsafe { std::slice::from_raw_parts(input_ptr as *const u8, input_len as usize) };
    let parsed = serde_json::from_slice::<WasmScanInput>(input_slice);

    let output_text = match parsed {
        Ok(input) => {
            let hostname = input
                .hostname
                .as_deref()
                .map(str::trim)
                .filter(|value| !value.is_empty())
                .unwrap_or(input.ip.as_str())
                .to_string();

            let request = format!(
                "GET / HTTP/1.1\r\nHost: {}\r\nUser-Agent: rustprobe-plugin/1.0\r\nConnection: close\r\n\r\n",
                hostname
            );

            let request_bytes = request.as_bytes();
            let packed_response = unsafe {
                let use_tls = if input.port == 443 || input.port == 8443 { 1 } else { 0 };
                host_send_tcp(
                    input.ip.as_ptr() as i32,
                    input.ip.len() as i32,
                    input.port as i32,
                    request_bytes.as_ptr() as i32,
                    request_bytes.len() as i32,
                    use_tls,
                    hostname.as_ptr() as i32,
                    hostname.len() as i32,
                )
            } as u64;

            if packed_response == 0 {
                serialize_output("No hay respuesta del objetivo")
            } else {
                let response_ptr = (packed_response >> 32) as u32 as i32;
                let response_len = (packed_response & 0xFFFF_FFFF) as u32 as i32;

                if response_ptr <= 0 || response_len <= 0 {
                    serialize_output("Respuesta inválida del host")
                } else {
                    let response_slice =
                        unsafe { std::slice::from_raw_parts(response_ptr as *const u8, response_len as usize) };
                    let response_bytes = response_slice.to_vec();

                    dealloc(response_ptr, response_len);

                    let response_text = String::from_utf8_lossy(&response_bytes).to_string();
                    let summary = summarize_http_title(&response_text);
                    serialize_output(&summary)
                }
            }
        }
        Err(_) => serialize_output("Entrada JSON inválida"),
    };

    pack_output(output_text)
}

fn summarize_http_title(response_text: &str) -> String {
    if !is_http_response(response_text) {
        return "No es un servidor web HTTP válido".to_string();
    }

    let body = extract_http_body(response_text);
    match extract_title(body) {
        Some(title) => format!("Title: {}", title),
        None => "Servidor web detectado, pero sin etiqueta <title>".to_string(),
    }
}

fn is_http_response(response_text: &str) -> bool {
    response_text
        .lines()
        .next()
        .map(|line| line.trim_end_matches('\r').starts_with("HTTP/"))
        .unwrap_or(false)
}

fn extract_http_body(response_text: &str) -> &str {
    if let Some((_, body)) = response_text.split_once("\r\n\r\n") {
        return body;
    }
    if let Some((_, body)) = response_text.split_once("\n\n") {
        return body;
    }
    response_text
}

fn extract_title(html: &str) -> Option<String> {
    let lower = html.to_ascii_lowercase();
    let start_tag = "<title>";
    let end_tag = "</title>";

    let start_idx = lower.find(start_tag)? + start_tag.len();
    let end_rel = lower[start_idx..].find(end_tag)?;
    let end_idx = start_idx + end_rel;

    let title = html[start_idx..end_idx].trim();
    if title.is_empty() {
        None
    } else {
        Some(title.to_string())
    }
}

fn serialize_output(summary: &str) -> String {
    let output = WasmScanOutput {
        plugin: "http_title",
        summary: summary.to_string(),
        severity: "info",
    };

    serde_json::to_string(&output).unwrap_or_else(|_| {
        "{\"plugin\":\"http_title\",\"summary\":\"serialization_error\",\"severity\":\"info\"}".to_string()
    })
}

fn pack_output(output_text: String) -> i64 {
    let mut out = output_text.into_bytes().into_boxed_slice();
    let out_ptr = out.as_mut_ptr() as u32;
    let out_len = out.len() as u32;
    std::mem::forget(out);

    ((out_ptr as u64) << 32 | out_len as u64) as i64
}
