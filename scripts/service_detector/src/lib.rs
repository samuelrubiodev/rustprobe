use serde::{Deserialize, Serialize};
use regex::Regex;

#[derive(Debug, Deserialize)]
struct WasmScanInput {
    ip: String,
    port: u16,
}

#[derive(Debug, Serialize)]
struct WasmScanOutput {
    plugin: &'static str,
    summary: String,
    severity: &'static str,
}

unsafe extern "C" {
    fn host_send_tcp(
        ip_ptr: *const u8,
        ip_len: usize,
        port: u16,
        payload_ptr: *const u8,
        payload_len: usize,
        use_tls: i32,
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
            let payload = if input.port == 21 || input.port == 22 {
                Vec::new()
            } else {
                format!(
                    "GET / HTTP/1.1\r\nHost: {}\r\nUser-Agent: Mozilla/5.0\r\nAccept: */*\r\nConnection: close\r\n\r\n",
                    input.ip
                )
                .into_bytes()
            };

            let use_tls = if input.port == 443 || input.port == 8443 { 1 } else { 0 };
            let packed_response = unsafe {
                host_send_tcp(
                    input.ip.as_ptr(),
                    input.ip.len(),
                    input.port,
                    payload.as_ptr(),
                    payload.len(),
                    use_tls,
                )
            } as u64;

            let summary = if packed_response == 0 {
                "No response".to_string()
            } else {
                let response_ptr = (packed_response >> 32) as u32 as i32;
                let response_len = (packed_response & 0xFFFF_FFFF) as u32 as i32;

                if response_ptr <= 0 || response_len <= 0 {
                    "No response".to_string()
                } else {
                    let response_slice =
                        unsafe { std::slice::from_raw_parts(response_ptr as *const u8, response_len as usize) };
                    let response_bytes = response_slice.to_vec();

                    dealloc(response_ptr, response_len);

                    extract_signature(&response_bytes)
                }
            };

            serialize_output(&summary)
        }
        Err(_) => serialize_output("No response"),
    };

    pack_output(output_text)
}

fn extract_signature(response_bytes: &[u8]) -> String {
    let response_text = String::from_utf8_lossy(response_bytes);
    let trimmed = response_text.trim();

    if trimmed.is_empty() {
        return "No response".to_string();
    }

    let first_line = trimmed
        .split(['\r', '\n'])
        .next()
        .unwrap_or("")
        .trim();

    let is_http_response = trimmed.contains("HTTP/1.");

    if is_http_response {
        let server_line = trimmed
            .split(['\r', '\n'])
            .map(str::trim)
            .find(|line| line.to_ascii_lowercase().starts_with("server: "));

        if let Some(line) = server_line {
            let value = line
                .split_once(':')
                .map(|(_, right)| right.trim())
                .unwrap_or("");
            if !value.is_empty() {
                return format!("Service: {}", value);
            }
        }
    }

    if first_line.starts_with("SSH-") {
        return format!("Service: {}", first_line);
    }

    if trimmed.contains("220 ") {
        return first_line.to_string();
    }

    let signatures = [
        (
            r"(?i)no available server",
            "Golang net/http server (404/503)",
        ),
        (r"(?i)<title>Apache Tomcat.*</title>", "Apache Tomcat"),
    ];

    for (pattern, service) in signatures {
        if let Ok(regex) = Regex::new(pattern) {
            if regex.is_match(trimmed) {
                return format!("Service: {}", service);
            }
        }
    }

    if is_http_response {
        if let Ok(title_regex) = Regex::new(r"(?i)<title>(.*?)</title>") {
            if let Some(captures) = title_regex.captures(trimmed) {
                if let Some(title_match) = captures.get(1) {
                    let title = title_match.as_str().trim();
                    if !title.is_empty() {
                        return format!("HTTP Service (Title: {})", title);
                    }
                }
            }
        }
    }

    let cleaned: String = trimmed
        .chars()
        .filter_map(|character| {
            if character == '\0' {
                None
            } else if character.is_control() {
                Some(' ')
            } else {
                Some(character)
            }
        })
        .collect();

    let compact = cleaned.split_whitespace().collect::<Vec<_>>().join(" ");
    let snippet: String = compact.chars().take(40).collect();

    if is_http_response {
        if snippet.is_empty() {
            return "HTTP Service (Unknown/Hidden)".to_string();
        }
        return format!("HTTP Service (Unknown/Hidden): {}", snippet);
    }

    format!("Unknown: {}", snippet)
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
