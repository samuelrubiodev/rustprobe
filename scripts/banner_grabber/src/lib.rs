use serde::{Deserialize, Serialize};

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
    fn host_send_tcp(ip_ptr: i32, ip_len: i32, port: i32, payload_ptr: i32, payload_len: i32) -> i64;
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
            let payload = b"\r\n\r\n";
            let packed_response = unsafe {
                host_send_tcp(
                    input.ip.as_ptr() as i32,
                    input.ip.len() as i32,
                    input.port as i32,
                    payload.as_ptr() as i32,
                    payload.len() as i32,
                )
            } as u64;

            let summary = if packed_response == 0 {
                "No banner".to_string()
            } else {
                let response_ptr = (packed_response >> 32) as u32 as i32;
                let response_len = (packed_response & 0xFFFF_FFFF) as u32 as i32;

                if response_ptr <= 0 || response_len <= 0 {
                    "No banner".to_string()
                } else {
                    let response_slice =
                        unsafe { std::slice::from_raw_parts(response_ptr as *const u8, response_len as usize) };
                    let response_bytes = response_slice.to_vec();

                    dealloc(response_ptr, response_len);

                    match extract_banner(&response_bytes) {
                        Some(text) => format!("Banner: {}", text),
                        None => "No banner".to_string(),
                    }
                }
            };

            serialize_output(&summary)
        }
        Err(_) => serialize_output("No banner"),
    };

    pack_output(output_text)
}

fn extract_banner(response_bytes: &[u8]) -> Option<String> {
    let response_text = String::from_utf8_lossy(response_bytes);
    let trimmed_tail = response_text
        .trim_end_matches(|character: char| character == '\0' || character.is_control());

    let first_line = trimmed_tail
        .split(['\r', '\n'])
        .next()
        .unwrap_or("")
        .trim();

    if first_line.is_empty() {
        return None;
    }

    let shortened: String = first_line.chars().take(80).collect();
    let cleaned = shortened.trim();

    if cleaned.is_empty() {
        None
    } else {
        Some(cleaned.to_string())
    }
}

fn serialize_output(summary: &str) -> String {
    let output = WasmScanOutput {
        plugin: "banner_grabber",
        summary: summary.to_string(),
        severity: "info",
    };

    serde_json::to_string(&output).unwrap_or_else(|_| {
        "{\"plugin\":\"banner_grabber\",\"summary\":\"No banner\",\"severity\":\"info\"}"
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
