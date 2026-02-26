use serde::{Deserialize, Serialize};

mod probes;
mod signatures;

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

            let probe_queue = probes::build_probe_queue(input.port, &hostname);
            let mut selected_banner: Option<String> = None;

            for probe in probe_queue {
                let _probe_name = probe.name;
                if let Some(response_bytes) = send_probe(
                    &input.ip,
                    input.port,
                    &probe.payload,
                    probe.use_tls,
                    &hostname,
                ) {
                    if !response_bytes.is_empty() {
                        selected_banner = Some(String::from_utf8_lossy(&response_bytes).replace('\0', ""));
                        break;
                    }
                }
            }

            let summary = match selected_banner {
                Some(text) => detect_service(&text),
                None => "No response".to_string(),
            };

            serialize_output(&summary)
        }
        Err(_) => serialize_output("No response"),
    };

    pack_output(output_text)
}

fn send_probe(ip: &str, port: u16, payload: &[u8], use_tls: i32, hostname: &str) -> Option<Vec<u8>> {
    let packed_response = unsafe {
        host_send_tcp(
            ip.as_ptr() as i32,
            ip.len() as i32,
            port as i32,
            payload.as_ptr() as i32,
            payload.len() as i32,
            use_tls,
            hostname.as_ptr() as i32,
            hostname.len() as i32,
        )
    } as u64;

    if packed_response == 0 {
        return None;
    }

    let response_ptr = (packed_response >> 32) as u32 as i32;
    let response_len = (packed_response & 0xFFFF_FFFF) as u32 as i32;

    if response_ptr <= 0 || response_len <= 0 {
        return None;
    }

    let response_slice = unsafe { std::slice::from_raw_parts(response_ptr as *const u8, response_len as usize) };
    let response_bytes = response_slice.to_vec();

    dealloc(response_ptr, response_len);

    Some(response_bytes)
}

fn detect_service(banner_text: &str) -> String {
    let normalized = banner_text.trim();
    if normalized.is_empty() {
        return "No response".to_string();
    }

    for signature in signatures::SIGNATURES.iter() {
        if let Some(captures) = signature.regex.captures(normalized) {
            let details = capture_details(&captures);
            if details.is_empty() {
                return format!("Service: {}", signature.service);
            }
            return format!("Service: {} ({})", signature.service, details);
        }
    }

    let _fallback_line = first_printable_line(normalized);
    "Unknown Service".to_string()
}

fn capture_details(captures: &regex::Captures<'_>) -> String {
    if let Some(version) = captures.name("version") {
        let cleaned = version.as_str().trim();
        if !cleaned.is_empty() {
            if let Some(product) = captures.name("product") {
                let product_clean = product.as_str().trim();
                if !product_clean.is_empty() {
                    return format!("{}; {}", cleaned, product_clean);
                }
            }
            return cleaned.to_string();
        }
    }

    for index in 1..captures.len() {
        if let Some(group) = captures.get(index) {
            let cleaned = group.as_str().trim();
            if !cleaned.is_empty() {
                return cleaned.to_string();
            }
        }
    }

    String::new()
}

fn first_printable_line(text: &str) -> String {
    let first_line = text.split(['\r', '\n']).next().unwrap_or("").trim();
    let filtered: String = first_line
        .chars()
        .filter(|ch| !ch.is_control() || *ch == ' ' || *ch == '\t')
        .collect();

    if filtered.is_empty() {
        "<empty>".to_string()
    } else {
        filtered
    }
}

fn serialize_output(summary: &str) -> String {
    let output = WasmScanOutput {
        plugin: "service_detector",
        summary: summary.to_string(),
        severity: "info",
    };

    serde_json::to_string(&output).unwrap_or_else(|_| {
        "{\"plugin\":\"service_detector\",\"summary\":\"No response\",\"severity\":\"info\"}"
            .to_string()
    })
}

fn pack_output(output_text: String) -> i64 {
    let mut out = output_text.into_bytes().into_boxed_slice();
    let out_ptr = out.as_mut_ptr() as u32;
    let out_len = out.len() as u32;
    std::mem::forget(out);

    ((out_ptr as u64) << 32 | out_len as u64) as i64
}
