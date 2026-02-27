pub fn is_root() -> bool {
    #[cfg(unix)]
    {
        nix::unistd::Uid::effective().is_root()
    }

    #[cfg(not(unix))]
    {
        true
    }
}

use pnet::packet::tcp::{ipv4_checksum, MutableTcpPacket, TcpFlags};
use pnet::transport::{transport_channel, TransportChannelType, TransportProtocol};
use std::net::{IpAddr, Ipv4Addr, UdpSocket};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

fn get_local_ip(target: Ipv4Addr) -> Option<Ipv4Addr> {
    let socket = UdpSocket::bind("0.0.0.0:0").ok()?;
    socket.connect((target, 80)).ok()?;
    if let IpAddr::V4(ip) = socket.local_addr().ok()?.ip() {
        Some(ip)
    } else {
        None
    }
}

pub async fn run_syn_scan(
    targets: &[std::net::IpAddr],
    ports: &[u16],
    timing: crate::models::TimingProfile,
    reporter: &crate::report::LiveReporter,
) -> anyhow::Result<Vec<crate::models::PortReport>> {
    if !is_root() {
        anyhow::bail!("El escaneo SYN (-sS) requiere privilegios de Administrador o Root para usar Raw Sockets.");
    }

    reporter.println("[*] Iniciando motor de Raw Sockets (Stealth SYN)...".to_string());

    // 1. Filtrar la lista de targets para quedarnos solo con IPv4
    let ipv4_targets: Vec<Ipv4Addr> = targets
        .iter()
        .filter_map(|ip| {
            if let IpAddr::V4(ipv4) = ip {
                Some(*ipv4)
            } else {
                None
            }
        })
        .collect();

    if ipv4_targets.is_empty() {
        reporter.println("[-] No hay objetivos IPv4 válidos para el escaneo SYN.".to_string());
        return Ok(vec![]);
    }

    // 2. Abrir el canal de bajo nivel
    let protocol = TransportChannelType::Layer4(TransportProtocol::Ipv4(
        pnet::packet::ip::IpNextHeaderProtocols::Tcp,
    ));
    let (mut tx, mut rx) = transport_channel(65536, protocol)
        .map_err(|e| anyhow::anyhow!("Error al abrir Raw Socket: {}", e))?;

    // 3. Crear estructuras de concurrencia
    let open_ports = Arc::new(Mutex::new(Vec::new()));
    let stop_signal = Arc::new(AtomicBool::new(false));

    let open_ports_clone = Arc::clone(&open_ports);
    let stop_signal_clone = Arc::clone(&stop_signal);

    // 4. El Hilo del RADAR (Receptor)
    let radar_handle = tokio::task::spawn_blocking(move || {
        let mut iter = pnet::transport::tcp_packet_iter(&mut rx);
        loop {
            if stop_signal_clone.load(Ordering::Relaxed) {
                break;
            }

            // iter.next() es bloqueante. Si no hay tráfico, se quedará esperando.
            // Para salir limpiamente, el hilo principal enviará un paquete dummy al final.
            if let Ok((packet, addr)) = iter.next() {
                if stop_signal_clone.load(Ordering::Relaxed) {
                    break;
                }

                // Verificar si el paquete TCP tiene las flags SYN | ACK (0x012)
                if packet.get_flags() == (TcpFlags::SYN | TcpFlags::ACK) {
                    let source_port = packet.get_source();
                    // Solo registrar si el puerto de destino coincide con nuestro puerto de origen (54321)
                    if packet.get_destination() == 54321 {
                        open_ports_clone.lock().unwrap().push((addr, source_port));
                    }
                }
            }
        }
    });

    // 5. El Hilo del FRANCOTIRADOR (Emisor)
    // Usamos un delay basado en el timeout del TimingProfile para no saturar la red
    // Para T5 (Insane), el delay debería ser 0 o muy cercano a 0.
    let delay = if timing.timeout_ms <= 100 {
        Duration::from_micros(0) // Sin delay para perfiles agresivos
    } else {
        Duration::from_millis(timing.timeout_ms.max(10) / 10)
    };

    for &target_ipv4 in &ipv4_targets {
        let local_ipv4 = match get_local_ip(target_ipv4) {
            Some(ip) => ip,
            None => {
                reporter.println(format!("[-] No se pudo resolver IP local para {}", target_ipv4));
                continue;
            }
        };

        for &port in ports {
            // Forjado del Paquete (REGLA ESTRICTA DE BÚFER)
            let mut tcp_buffer = [0u8; 20];
            let mut tcp_packet = MutableTcpPacket::new(&mut tcp_buffer).unwrap();

            tcp_packet.set_source(54321); // Puerto origen (podría ser aleatorio)
            tcp_packet.set_destination(port);
            tcp_packet.set_sequence(12345); // Número de secuencia aleatorio
            tcp_packet.set_data_offset(5); // Cabecera sin opciones (5 * 4 = 20 bytes)
            tcp_packet.set_flags(TcpFlags::SYN);
            tcp_packet.set_window(64240);

            // Calcular el checksum
            let checksum = ipv4_checksum(&tcp_packet.to_immutable(), &local_ipv4, &target_ipv4);
            tcp_packet.set_checksum(checksum);

            // Enviar el paquete
            if let Err(e) = tx.send_to(tcp_packet, IpAddr::V4(target_ipv4)) {
                reporter.println(format!("[-] Error enviando paquete a {}:{}: {}", target_ipv4, port, e));
            }

            // Limitador de velocidad según el TimingProfile
            if delay.as_micros() > 0 {
                std::thread::sleep(delay);
            }
        }
    }

    // 6. Sincronización y Cierre
    // Dar tiempo a que los últimos SYN-ACK lleguen de vuelta al Radar
    std::thread::sleep(Duration::from_secs(2));
    
    // Señalizar parada
    stop_signal.store(true, Ordering::Relaxed);

    // Enviar un paquete dummy a localhost para despertar al iterador bloqueado del Radar
    let dummy_ip = Ipv4Addr::new(127, 0, 0, 1);
    let mut dummy_buf = [0u8; 20];
    if let Some(mut dummy_pkt) = MutableTcpPacket::new(&mut dummy_buf) {
        dummy_pkt.set_source(80);
        dummy_pkt.set_destination(54321);
        dummy_pkt.set_data_offset(5);
        dummy_pkt.set_flags(TcpFlags::SYN | TcpFlags::ACK);
        let _ = tx.send_to(dummy_pkt, IpAddr::V4(dummy_ip));
    }

    // Esperar a que el hilo del Radar termine
    let _ = radar_handle.await;

    // 7. Mapear los puertos abiertos encontrados a la estructura PortReport
    let found_ports = open_ports.lock().unwrap().clone();
    let mut reports = Vec::new();

    for (ip, port) in found_ports {
        reports.push(crate::models::PortReport {
            ip,
            port,
            state: "open",
            service_name: "unknown", // Se detectará más adelante si es necesario
            scripts: Vec::new(),
        });
        reporter.println(format!("[+] {}:{} está ABIERTO (SYN-ACK recibido)", ip, port));
    }

    Ok(reports)
}
