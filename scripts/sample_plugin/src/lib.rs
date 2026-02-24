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
            let output = WasmScanOutput {
                plugin: "sample_plugin",
                summary: format!(
                    "stub analysis complete for {}:{} (banner/CVE logic pendiente)",
                    input.ip, input.port
                ),
                severity: "info",
            };

            serde_json::to_string(&output).unwrap_or_else(|_| {
                "{\"plugin\":\"sample_plugin\",\"summary\":\"serialization_error\",\"severity\":\"error\"}".to_string()
            })
        }
        Err(_) => {
            "{\"plugin\":\"sample_plugin\",\"summary\":\"invalid_input_json\",\"severity\":\"error\"}".to_string()
        }
    };

    let mut out = output_text.into_bytes().into_boxed_slice();
    let out_ptr = out.as_mut_ptr() as u32;
    let out_len = out.len() as u32;
    std::mem::forget(out);

    ((out_ptr as u64) << 32 | out_len as u64) as i64
}
