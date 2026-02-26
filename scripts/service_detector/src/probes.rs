pub struct Probe {
    pub name: &'static str,
    pub payload: Vec<u8>,
    pub use_tls: i32,
    pub preferred_ports: &'static [u16],
}

pub fn build_probe_queue(port: u16, hostname: &str) -> Vec<Probe> {
    let http_payload = format!("GET / HTTP/1.1\r\nHost: {}\r\n\r\n", hostname).into_bytes();

    let mut probes = vec![
        Probe {
            name: "NULL Probe",
            payload: Vec::new(),
            use_tls: 0,
            preferred_ports: &[21, 22, 23, 25, 110, 143, 3306, 5432, 5900, 6667, 1524],
        },
        Probe {
            name: "HTTP Probe",
            payload: http_payload.clone(),
            use_tls: 0,
            preferred_ports: &[80, 8080, 8000],
        },
        Probe {
            name: "TLS HTTP Probe",
            payload: http_payload,
            use_tls: 1,
            preferred_ports: &[443, 8443],
        },
        Probe {
            name: "Generic Help Probe",
            payload: b"HELP\r\n\r\n".to_vec(),
            use_tls: 0,
            preferred_ports: &[],
        },
    ];

    probes.sort_by_key(|probe| !probe.preferred_ports.contains(&port));
    probes
}