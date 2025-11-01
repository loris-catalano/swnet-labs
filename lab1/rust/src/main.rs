use chrono::Local;

fn main() {
    use pcap::Device;

    let interface = Device::list()
        .unwrap()
        .into_iter()
        .find(|d| d.name == "en0")
        .unwrap();

    let mut cap = pcap::Capture::from_device(interface)
        .unwrap()
        .promisc(true)
        .snaplen(65535)
        .timeout(1000)
        .open()
        .unwrap();

    loop {
        match cap.next_packet() {
            Ok(packet) => {
                //println!("\n------ NEW PACKET ------\n{:?}\n------------------------", packet);
                handle_packet(&packet);
            }
            Err(e) => {
                println!("Error receiving packet: {:?}", e);
            }
        }
    } 
}

fn handle_packet(packet: &pcap::Packet) {
    let ether_dhost = &packet.data[0..6];
    let ether_shost = &packet.data[6..12];
    let ip_src = &packet.data[26..30];
    let ip_dst = &packet.data[30..34];
    let protocol_type = u16::from_be_bytes([packet.data[12], packet.data[13]]);
    let ip_proto = packet.data[23];
    let tcp_src_port = u16::from_be_bytes([packet.data[34], packet.data[35]]);
    let tcp_dst_port: u16 = u16::from_be_bytes([packet.data[36], packet.data[37]]);

    let dst_mac = ether_dhost
        .iter()
        .map(|b| format!("{:02x}", b))
        .collect::<Vec<String>>()
        .join(":");

    let src_mac = ether_shost
        .iter()
        .map(|b| format!("{:02x}", b))
        .collect::<Vec<String>>()
        .join(":");

    let ip_src_str = ip_src
        .iter()
        .map(|b| b.to_string())
        .collect::<Vec<String>>()
        .join(".");

    let ip_dst_str = ip_dst
        .iter()
        .map(|b| b.to_string())
        .collect::<Vec<String>>()
        .join(".");

    let protocol_str;
    if protocol_type == 0x0800 {
        match ip_proto {
            6 => protocol_str = "TCP",
            17 => protocol_str = "UDP",
            _ => protocol_str = "Unknown",
        }
    }else{
        protocol_str = "Unknown";
    }

    let timestamp = Local::now().format("%Y-%m-%d %H:%M:%S.%f").to_string();

    println!("{} {}->{} {}->{} {} {}->{}", timestamp, src_mac, dst_mac, ip_src_str, ip_dst_str, protocol_str, tcp_src_port, tcp_dst_port);
}