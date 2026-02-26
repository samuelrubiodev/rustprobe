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
            let payload = match input.port {
                21 | 22 | 23 | 25 | 110 | 143 | 2121 | 3306 | 5432 | 5900 | 6667 | 6697 | 1524 => Vec::new(),
                80 | 443 | 8000 | 8080 | 8443 | _ => format!(
                    "GET / HTTP/1.1\r\nHost: {}\r\nUser-Agent: Mozilla/5.0\r\nConnection: close\r\n\r\n",
                    input.ip
                )
                .into_bytes(),
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
    let cleaned = clean_ascii(response_bytes);
    let trimmed = cleaned.trim();

    if trimmed.is_empty() {
        return "No response".to_string();
    }

    let first_line = trimmed
        .split(['\r', '\n'])
        .next()
        .unwrap_or("")
        .trim();

    if first_line.starts_with("RFB") {
        return format!("Service: VNC (Banner: {})", trimmed);
    }

    if first_line.starts_with("SSH-") {
        return format!("Service: SSH (Banner: {})", trimmed);
    }

    if trimmed.len() >= 3 {
        let prefix_window: String = trimmed.chars().take(40).collect();
        if prefix_window.contains("220 ") {
            return format!("Service: FTP/SMTP (Banner: {})", trimmed);
        }
    }

    if let Ok(mysql_regex) = Regex::new(r"(?i)mysql_native_password|5\.0\.|5\.5\.|8\.0\.") {
        if mysql_regex.is_match(trimmed) {
            return format!("Service: MySQL (Banner: {})", trimmed);
        }
    }

    if let Ok(irc_regex) = Regex::new(r"(?i)NOTICE AUTH|irc") {
        if irc_regex.is_match(trimmed) {
            return format!("Service: IRC (Banner: {})", trimmed);
        }
    }

    if let Ok(shell_regex) = Regex::new(r"(?i)root@|# ") {
        if shell_regex.is_match(trimmed) {
            return format!("Service: Bindshell/Telnet (Banner: {})", trimmed);
        }
    }

    let snippet: String = trimmed.chars().take(50).collect();
    format!("Unknown: {}", snippet)
}

fn clean_ascii(raw: &[u8]) -> String {
    let printable: Vec<u8> = raw
        .iter()
        .copied()
        .filter(|b| (32..=126).contains(b))
        .collect();

    let as_text = String::from_utf8_lossy(&printable).to_string();
    as_text.split_whitespace().collect::<Vec<_>>().join(" ")
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
