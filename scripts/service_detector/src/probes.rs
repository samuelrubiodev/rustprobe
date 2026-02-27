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
            preferred_ports: &[21, 22, 23, 25, 110, 143, 3306, 5432, 5900, 6667, 1524] 
        },
        Probe { 
            name: "SMB Negotiate Probe", 
            // Paquete mágico de protocolo SMBv1
            payload: b"\x00\x00\x00\x2f\xff\x53\x4d\x42\x72\x00\x00\x00\x00\x08\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x02\x4e\x54\x20\x4c\x4d\x20\x30\x2e\x31\x32\x00".to_vec(), 
            use_tls: 0, 
            preferred_ports: &[139, 445] 
        },
        Probe { 
            name: "HTTP Probe", 
            payload: http_payload.clone(), 
            use_tls: 0, 
            preferred_ports: &[80, 8080, 8000] 
        },
        Probe { 
            name: "TLS HTTP Probe", 
            payload: http_payload, 
            use_tls: 1, 
            preferred_ports: &[443, 8443] 
        },
        Probe { 
            name: "Generic Help Probe", 
            payload: b"HELP\r\n\r\n".to_vec(), 
            use_tls: 0, 
            preferred_ports: &[] 
        },
    ];

    // Priorizamos la sonda si el puerto está en su lista de preferidos
    if let Some(pos) = probes.iter().position(|p| p.preferred_ports.contains(&port)) {
        let prioritized = probes.remove(pos);
        probes.insert(0, prioritized);
    } else if port == 80 || port == 8080 {
        if let Some(pos) = probes.iter().position(|p| p.name == "HTTP Probe") {
            let p = probes.remove(pos);
            probes.insert(0, p);
        }
    } else if port == 443 {
        if let Some(pos) = probes.iter().position(|p| p.name == "TLS HTTP Probe") {
            let p = probes.remove(pos);
            probes.insert(0, p);
        }
    }

    probes
}