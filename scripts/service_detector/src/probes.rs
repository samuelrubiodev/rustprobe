pub struct Probe {
    pub name: &'static str,
    pub payload: Vec<u8>,
    pub use_tls: i32,
    pub preferred_ports: &'static [u16],
    pub preferred_rank: u8,
    pub fallback_rank: u8,
}

pub fn build_probe_queue(port: u16, hostname: &str) -> Vec<Probe> {
    let http_payload = format!("GET / HTTP/1.1\r\nHost: {}\r\n\r\n", hostname).into_bytes();

    let mut probes = vec![
        Probe {
            name: "DNS Version Probe",
            payload: b"\x13\x37\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x07version\x04bind\x00\x00\x10\x00\x03".to_vec(),
            use_tls: 0,
            preferred_ports: &[53],
            preferred_rank: 0,
            fallback_rank: 6,
        },
        Probe {
            name: "SMB2 Negotiate Probe",
            payload: b"\x00\x00\x00\x54\xfe\x53\x4d\x42\x40\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x24\x00\x02\x00\x01\x00\x00\x00\x7f\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x02\x02\x10\x02\x22\x02\x24\x02\x00\x03\x02\x03\x10\x03\x11\x03\x00\x00\x00\x00\x01\x00\x26\x00\x00\x00".to_vec(),
            use_tls: 0,
            preferred_ports: &[139, 445],
            preferred_rank: 0,
            fallback_rank: 6,
        },
        Probe {
            name: "SMB Negotiate Probe",
            payload: b"\x00\x00\x00\x2f\xff\x53\x4d\x42\x72\x00\x00\x00\x00\x08\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x02\x4e\x54\x20\x4c\x4d\x20\x30\x2e\x31\x32\x00".to_vec(),
            use_tls: 0,
            preferred_ports: &[139, 445],
            preferred_rank: 1,
            fallback_rank: 6,
        },
        Probe {
            name: "NULL Probe",
            payload: Vec::new(),
            use_tls: 0,
            preferred_ports: &[21, 22, 23, 25, 110, 143, 3306, 5432, 5900, 6667, 1524],
            preferred_rank: 0,
            fallback_rank: 0,
        },
        Probe {
            name: "HTTP Probe",
            payload: http_payload.clone(),
            use_tls: 0,
            preferred_ports: &[80, 8080, 8000],
            preferred_rank: 0,
            fallback_rank: 2,
        },
        Probe {
            name: "TLS HTTP Probe",
            payload: http_payload,
            use_tls: 1,
            preferred_ports: &[443, 8443],
            preferred_rank: 0,
            fallback_rank: 4,
        },
        Probe {
            name: "Generic Help Probe",
            payload: b"HELP\r\n\r\n".to_vec(),
            use_tls: 0,
            preferred_ports: &[],
            preferred_rank: 1,
            fallback_rank: 1,
        },
    ];

    probes.sort_unstable_by_key(|probe| prioritize_probe(probe, port));
    probes
}

fn prioritize_probe(probe: &Probe, port: u16) -> (u8, u8) {
    if probe.preferred_ports.contains(&port) {
        (0, probe.preferred_rank)
    } else {
        (1, probe.fallback_rank)
    }
}