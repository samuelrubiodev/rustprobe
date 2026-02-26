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
    server: Option<String>,
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

    let input_slice = unsafe {
        std::slice::from_raw_parts(input_ptr as *const u8, input_len as usize)
    };

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
                "GET / HTTP/1.1\r\nHost: {}\r\nUser-Agent: rustprobe-sample-plugin/1.0\r\nConnection: close\r\n\r\n",
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
                let output = WasmScanOutput {
                    plugin: "sample_plugin",
                    summary: format!("no_response for {}:{}", input.ip, input.port),
                    server: None,
                    severity: "warning",
                };

                serde_json::to_string(&output).unwrap_or_else(|_| {
                    "{\"plugin\":\"sample_plugin\",\"summary\":\"serialization_error\",\"server\":null,\"severity\":\"error\"}".to_string()
                })
            } else {
                let response_ptr = (packed_response >> 32) as u32 as i32;
                let response_len = (packed_response & 0xFFFF_FFFF) as u32 as i32;

                if response_ptr <= 0 || response_len <= 0 {
                    let output = WasmScanOutput {
                        plugin: "sample_plugin",
                        summary: format!("invalid_response_buffer for {}:{}", input.ip, input.port),
                        server: None,
                        severity: "error",
                    };

                    serde_json::to_string(&output).unwrap_or_else(|_| {
                        "{\"plugin\":\"sample_plugin\",\"summary\":\"serialization_error\",\"server\":null,\"severity\":\"error\"}".to_string()
                    })
                } else {
                    let response_slice = unsafe {
                        std::slice::from_raw_parts(response_ptr as *const u8, response_len as usize)
                    };
                    let response_bytes = response_slice.to_vec();

                    dealloc(response_ptr, response_len);

                    let server = extract_server_header(&response_bytes);
                    let summary = match &server {
                        Some(value) => format!("server header detected: {}", value),
                        None => "server header not found".to_string(),
                    };

                    let output = WasmScanOutput {
                        plugin: "sample_plugin",
                        summary,
                        server,
                        severity: "info",
                    };

                    serde_json::to_string(&output).unwrap_or_else(|_| {
                        "{\"plugin\":\"sample_plugin\",\"summary\":\"serialization_error\",\"server\":null,\"severity\":\"error\"}".to_string()
                    })
                }
            }
        }
        Err(_) => {
            "{\"plugin\":\"sample_plugin\",\"summary\":\"invalid_input_json\",\"server\":null,\"severity\":\"error\"}".to_string()
        }
    };

    let mut out = output_text.into_bytes().into_boxed_slice();
    let out_ptr = out.as_mut_ptr() as u32;
    let out_len = out.len() as u32;
    std::mem::forget(out);

    ((out_ptr as u64) << 32 | out_len as u64) as i64
}

fn extract_server_header(response: &[u8]) -> Option<String> {
    let text = String::from_utf8_lossy(response);
    for line in text.lines() {
        let cleaned = line.trim_end_matches('\r');
        if cleaned.is_empty() {
            break;
        }

        if let Some((name, value)) = cleaned.split_once(':') {
            if name.trim().eq_ignore_ascii_case("server") {
                let server = value.trim();
                if !server.is_empty() {
                    return Some(server.to_string());
                }
            }
        }
    }

    None
}
